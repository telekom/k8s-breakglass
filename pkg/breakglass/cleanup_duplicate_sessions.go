// SPDX-FileCopyrightText: 2025 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package breakglass

import (
	"context"
	"sort"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// sessionStatePriority returns a numeric priority for a given session state.
// Higher values indicate higher priority when choosing which duplicate to keep.
func sessionStatePriority(state breakglassv1alpha1.BreakglassSessionState) int {
	switch state {
	case breakglassv1alpha1.SessionStateApproved:
		return 3
	case breakglassv1alpha1.SessionStateWaitingForScheduledTime:
		return 2
	case breakglassv1alpha1.SessionStatePending:
		return 1
	default:
		return 0
	}
}

// CleanupDuplicateSessions detects active sessions that share the same
// (cluster, user, grantedGroup) triple — which should be unique — and
// terminates the duplicates, keeping the best candidate alive.
//
// The survivor is chosen by state priority (Approved > WaitingForScheduledTime
// > Pending), then by CreationTimestamp (oldest first), with resource name as
// a deterministic tie-breaker.
//
// Duplicates can occur in multi-replica deployments due to TOCTOU race
// conditions in session creation (the in-flight guard is per-process).
// Running this during the periodic cleanup makes the system eventually
// consistent without hammering the API server.
func CleanupDuplicateSessions(ctx context.Context, log *zap.SugaredLogger, mgr *SessionManager) {
	if mgr == nil {
		return
	}
	if log == nil {
		log = zap.S()
	}

	// Collect active sessions from all "in-flight" states.
	activeStates := []breakglassv1alpha1.BreakglassSessionState{
		breakglassv1alpha1.SessionStatePending,
		breakglassv1alpha1.SessionStateApproved,
		breakglassv1alpha1.SessionStateWaitingForScheduledTime,
	}

	var allActive []breakglassv1alpha1.BreakglassSession
	for _, state := range activeStates {
		sessions, err := mgr.GetSessionsByState(ctx, state)
		if err != nil {
			log.Warnw("Failed to list sessions for duplicate cleanup", "state", state, "error", err)
			continue
		}
		allActive = append(allActive, sessions...)
	}

	if len(allActive) < 2 {
		return // need at least 2 for a duplicate
	}

	// Group by the unique triple: cluster/user/grantedGroup
	type tripleKey struct {
		Cluster, User, Group string
	}
	groups := make(map[tripleKey][]breakglassv1alpha1.BreakglassSession)
	for _, s := range allActive {
		key := tripleKey{
			Cluster: s.Spec.Cluster,
			User:    s.Spec.User,
			Group:   s.Spec.GrantedGroup,
		}
		groups[key] = append(groups[key], s)
	}

	for key, sessions := range groups {
		if len(sessions) < 2 {
			continue
		}

		// Sort by state priority (Approved > WaitingForScheduledTime > Pending),
		// then by CreationTimestamp ascending (oldest first), and finally by name
		// as a deterministic tie-breaker.
		sort.Slice(sessions, func(i, j int) bool {
			si := sessions[i]
			sj := sessions[j]

			pi := sessionStatePriority(si.Status.State)
			pj := sessionStatePriority(sj.Status.State)
			if pi != pj {
				return pi > pj
			}

			if !si.CreationTimestamp.Equal(&sj.CreationTimestamp) {
				return si.CreationTimestamp.Before(&sj.CreationTimestamp)
			}

			return si.Name < sj.Name
		})

		// Keep the best candidate (sessions[0]), terminate the rest.
		log.Warnw("Duplicate active sessions detected — terminating duplicates",
			"cluster", key.Cluster,
			"user", key.User,
			"grantedGroup", key.Group,
			"keepSession", sessions[0].Name,
			"duplicateCount", len(sessions)-1,
		)

		for _, dup := range sessions[1:] {
			// Check if the context has been cancelled (e.g., leader election loss, shutdown).
			select {
			case <-ctx.Done():
				log.Infow("Duplicate cleanup interrupted by context cancellation",
					"cluster", key.Cluster,
					"user", key.User,
					"grantedGroup", key.Group,
				)
				return
			default:
			}

			log.Infow("Handling duplicate session",
				"session", dup.Name,
				"namespace", dup.Namespace,
				"state", dup.Status.State,
				"created", dup.CreationTimestamp.Time,
			)

			var (
				targetState      breakglassv1alpha1.BreakglassSessionState
				conditionType    breakglassv1alpha1.BreakglassSessionConditionType
				conditionReason  string
				conditionMessage string
				reasonEnded      string
			)

			switch dup.Status.State {
			case breakglassv1alpha1.SessionStatePending, breakglassv1alpha1.SessionStateWaitingForScheduledTime:
				// Pending/Waiting sessions must be withdrawn, not expired,
				// to satisfy the webhook state machine.
				targetState = breakglassv1alpha1.SessionStateWithdrawn
				conditionType = breakglassv1alpha1.SessionConditionTypeCanceled
				conditionReason = "DuplicateSessionWithdrawn"
				conditionMessage = "Withdrawn by cleanup routine: duplicate session for the same cluster/user/group triple."
				reasonEnded = "withdrawn"
			case breakglassv1alpha1.SessionStateApproved:
				// Approved sessions can be directly expired.
				targetState = breakglassv1alpha1.SessionStateExpired
				conditionType = breakglassv1alpha1.SessionConditionTypeExpired
				conditionReason = "DuplicateSessionTerminated"
				conditionMessage = "Terminated by cleanup routine: duplicate session for the same cluster/user/group triple."
				reasonEnded = "duplicateCleanup"
			default:
				// For any other state, skip to avoid invalid state transitions.
				log.Infow("Skipping duplicate session with non-terminatable state",
					"session", dup.Name,
					"namespace", dup.Namespace,
					"state", dup.Status.State,
				)
				continue
			}

			// Capture a single "now" for consistent terminal metadata and condition timestamps.
			now := metav1.Now()

			// Populate terminal-state timestamps that the rest of the system expects.
			if targetState == breakglassv1alpha1.SessionStateWithdrawn {
				if dup.Status.WithdrawnAt.IsZero() {
					dup.Status.WithdrawnAt = now
				}
			}
			if targetState == breakglassv1alpha1.SessionStateExpired {
				dup.Status.ExpiresAt = now
			}
			// Set RetainedUntil so the cleanup routine can later garbage-collect the session.
			if dup.Status.RetainedUntil.IsZero() {
				retainFor := ParseRetainFor(dup.Spec, log)
				dup.Status.RetainedUntil = metav1.NewTime(now.Time.Add(retainFor))
			}

			dup.Status.State = targetState
			dup.Status.ReasonEnded = reasonEnded
			dup.SetCondition(metav1.Condition{
				Type:               string(conditionType),
				Status:             metav1.ConditionTrue,
				LastTransitionTime: now,
				Reason:             conditionReason,
				Message:            conditionMessage,
			})

			if err := mgr.UpdateBreakglassSessionStatus(ctx, dup); err != nil {
				log.Warnw("Failed to update duplicate session status", "session", dup.Name, "error", err)
			}
		}
	}
}
