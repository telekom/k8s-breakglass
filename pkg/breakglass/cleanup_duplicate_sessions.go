// SPDX-FileCopyrightText: 2025 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package breakglass

import (
	"context"
	"fmt"
	"sort"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/system"
	"go.uber.org/zap"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type duplicateSessionKey struct {
	Cluster, User, Group string
}

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

func isActiveDuplicateSessionState(state breakglassv1alpha1.BreakglassSessionState) bool {
	return sessionStatePriority(state) > 0
}

func duplicateKeyForSession(session breakglassv1alpha1.BreakglassSession) duplicateSessionKey {
	return duplicateSessionKey{
		Cluster: session.Spec.Cluster,
		User:    session.Spec.User,
		Group:   session.Spec.GrantedGroup,
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

	// Group by the unique triple: cluster/user/grantedGroup.
	groups := make(map[duplicateSessionKey][]breakglassv1alpha1.BreakglassSession)
	for _, s := range allActive {
		key := duplicateKeyForSession(s)
		groups[key] = append(groups[key], s)
	}

	for key, sessions := range groups {
		if len(sessions) < 2 {
			continue
		}

		sessions = refetchActiveDuplicateSessions(ctx, log, mgr, key, sessions)
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
			"group", system.RedactGroupName(key.Group),
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
					"group", system.RedactGroupName(key.Group),
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

			if _, err := terminateDuplicateSession(ctx, log, mgr, key, dup); err != nil {
				log.Warnw("Failed to update duplicate session status", "session", dup.Name, "error", err)
			}
		}
	}
}

func refetchActiveDuplicateSessions(
	ctx context.Context,
	log *zap.SugaredLogger,
	mgr *SessionManager,
	key duplicateSessionKey,
	sessions []breakglassv1alpha1.BreakglassSession,
) []breakglassv1alpha1.BreakglassSession {
	refreshed := make([]breakglassv1alpha1.BreakglassSession, 0, len(sessions))
	seen := make(map[types.NamespacedName]struct{}, len(sessions))
	for _, session := range sessions {
		namespacedName := types.NamespacedName{Namespace: session.Namespace, Name: session.Name}
		if _, ok := seen[namespacedName]; ok {
			continue
		}
		seen[namespacedName] = struct{}{}

		live, err := getLiveDuplicateSession(ctx, mgr, session)
		if err != nil {
			if !apierrors.IsNotFound(err) {
				log.Warnw("Failed to refetch duplicate session candidate",
					"session", session.Name,
					"namespace", session.Namespace,
					"error", err)
			}
			continue
		}
		if duplicateKeyForSession(live) != key {
			log.Infow("Skipping duplicate session candidate whose key changed after refetch",
				"session", live.Name,
				"namespace", live.Namespace)
			continue
		}
		if !isActiveDuplicateSessionState(live.Status.State) {
			log.Infow("Skipping duplicate session candidate that is no longer active",
				"session", live.Name,
				"namespace", live.Namespace,
				"state", live.Status.State)
			continue
		}
		refreshed = append(refreshed, live)
	}
	return refreshed
}

func getLiveDuplicateSession(
	ctx context.Context,
	mgr *SessionManager,
	session breakglassv1alpha1.BreakglassSession,
) (breakglassv1alpha1.BreakglassSession, error) {
	if session.Namespace == "" {
		return breakglassv1alpha1.BreakglassSession{}, fmt.Errorf("get live duplicate session %q: namespace is required for live reader lookup", session.Name)
	}

	live := breakglassv1alpha1.BreakglassSession{}
	if err := mgr.Reader().Get(ctx, types.NamespacedName{Namespace: session.Namespace, Name: session.Name}, &live); err != nil {
		return breakglassv1alpha1.BreakglassSession{}, fmt.Errorf("get live duplicate session %s/%s: %w", session.Namespace, session.Name, err)
	}
	return live, nil
}

func terminateDuplicateSession(
	ctx context.Context,
	log *zap.SugaredLogger,
	mgr *SessionManager,
	key duplicateSessionKey,
	session breakglassv1alpha1.BreakglassSession,
) (bool, error) {
	updated := false
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		live, err := getLiveDuplicateSession(ctx, mgr, session)
		if err != nil {
			if apierrors.IsNotFound(err) {
				return nil
			}
			return err
		}
		if duplicateKeyForSession(live) != key || !isActiveDuplicateSessionState(live.Status.State) {
			log.Infow("Skipping duplicate session that changed before status patch",
				"session", live.Name,
				"namespace", live.Namespace,
				"state", live.Status.State)
			return nil
		}

		base := live.DeepCopy()
		prepareDuplicateSessionTermination(&live, log)
		live.Status.ObservedGeneration = live.Generation
		if err := mgr.Client.Status().Patch(ctx, &live, client.MergeFromWithOptions(base, client.MergeFromWithOptimisticLock{})); err != nil {
			if apierrors.IsNotFound(err) {
				return nil
			}
			return err
		}
		updated = true
		return nil
	})
	if err != nil {
		return false, fmt.Errorf("patch duplicate session status %s/%s: %w", session.Namespace, session.Name, err)
	}
	return updated, nil
}

func prepareDuplicateSessionTermination(session *breakglassv1alpha1.BreakglassSession, log *zap.SugaredLogger) {
	var (
		targetState      breakglassv1alpha1.BreakglassSessionState
		conditionType    breakglassv1alpha1.BreakglassSessionConditionType
		conditionReason  string
		conditionMessage string
		reasonEnded      string
	)

	switch session.Status.State {
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
		return
	}

	// Capture a single "now" for consistent terminal metadata and condition timestamps.
	now := metav1.Now()

	// Populate terminal-state timestamps that the rest of the system expects.
	if targetState == breakglassv1alpha1.SessionStateWithdrawn && session.Status.WithdrawnAt.IsZero() {
		session.Status.WithdrawnAt = now
	}
	if targetState == breakglassv1alpha1.SessionStateExpired {
		session.Status.ExpiresAt = now
	}
	// Set RetainedUntil so the cleanup routine can later garbage-collect the session.
	if session.Status.RetainedUntil.IsZero() {
		retainFor := ParseRetainFor(session.Spec, log)
		session.Status.RetainedUntil = metav1.NewTime(now.Time.Add(retainFor))
	}

	session.Status.State = targetState
	session.Status.ReasonEnded = reasonEnded
	session.SetCondition(metav1.Condition{
		Type:               string(conditionType),
		Status:             metav1.ConditionTrue,
		LastTransitionTime: now,
		Reason:             conditionReason,
		Message:            conditionMessage,
	})
}
