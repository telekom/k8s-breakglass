// SPDX-FileCopyrightText: 2025 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package breakglass

import (
	"context"
	"sort"

	v1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// CleanupDuplicateSessions detects active sessions that share the same
// (cluster, user, grantedGroup) triple — which should be unique — and
// terminates the youngest duplicates, keeping the oldest session alive.
//
// Duplicates can occur in multi-replica deployments due to TOCTOU race
// conditions in session creation (the in-flight guard is per-process).
// Running this during the periodic cleanup makes the system eventually
// consistent without hammering the API server.
func CleanupDuplicateSessions(ctx context.Context, log *zap.SugaredLogger, mgr *SessionManager) {
	if mgr == nil {
		return
	}

	// Collect active sessions from all "in-flight" states.
	activeStates := []v1alpha1.BreakglassSessionState{
		v1alpha1.SessionStatePending,
		v1alpha1.SessionStateApproved,
		v1alpha1.SessionStateWaitingForScheduledTime,
	}

	var allActive []v1alpha1.BreakglassSession
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
	groups := make(map[tripleKey][]v1alpha1.BreakglassSession)
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

		// Sort by CreationTimestamp ascending — oldest first.
		sort.Slice(sessions, func(i, j int) bool {
			return sessions[i].CreationTimestamp.Before(&sessions[j].CreationTimestamp)
		})

		// Keep the oldest (sessions[0]), expire the rest.
		log.Warnw("Duplicate active sessions detected — terminating youngest",
			"cluster", key.Cluster,
			"user", key.User,
			"grantedGroup", key.Group,
			"keepSession", sessions[0].Name,
			"duplicateCount", len(sessions)-1,
		)

		for _, dup := range sessions[1:] {
			log.Infow("Expiring duplicate session",
				"session", dup.Name,
				"namespace", dup.Namespace,
				"state", dup.Status.State,
				"created", dup.CreationTimestamp.Time,
			)

			dup.Status.State = v1alpha1.SessionStateExpired
			dup.Status.ReasonEnded = "duplicateCleanup"
			dup.Status.Conditions = append(dup.Status.Conditions, metav1.Condition{
				Type:               string(v1alpha1.SessionConditionTypeExpired),
				Status:             metav1.ConditionTrue,
				LastTransitionTime: metav1.Now(),
				Reason:             "DuplicateSessionTerminated",
				Message:            "Terminated by cleanup routine: duplicate session for the same cluster/user/group triple.",
			})

			if err := mgr.UpdateBreakglassSessionStatus(ctx, dup); err != nil {
				log.Warnw("Failed to expire duplicate session", "session", dup.Name, "error", err)
			}
		}
	}
}
