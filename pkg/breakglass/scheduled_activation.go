/*
Copyright 2024.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package breakglass

import (
	"context"
	"time"

	v1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/metrics"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ScheduledSessionActivator handles activation of scheduled sessions.
// When a session's ScheduledStartTime is reached, it transitions from WaitingForScheduledTime to Approved
// and becomes available for use (RBAC group is applied).
type ScheduledSessionActivator struct {
	log            *zap.SugaredLogger
	sessionManager *SessionManager
}

// NewScheduledSessionActivator creates a new activator instance
func NewScheduledSessionActivator(log *zap.SugaredLogger, sessionManager *SessionManager) *ScheduledSessionActivator {
	return &ScheduledSessionActivator{
		log:            log,
		sessionManager: sessionManager,
	}
}

// ActivateScheduledSessions checks for sessions in WaitingForScheduledTime state
// whose ScheduledStartTime has arrived, and transitions them to Approved state.
// This allows the RBAC group to be applied and the session to become usable.
func (ssa *ScheduledSessionActivator) ActivateScheduledSessions() {
	sessions, err := ssa.sessionManager.GetAllBreakglassSessions(context.Background())
	if err != nil {
		ssa.log.Error("error listing sessions for scheduled activation", zap.Error(err))
		return
	}

	now := time.Now()
	for _, ses := range sessions {
		// Only process sessions in WaitingForScheduledTime state
		if ses.Status.State != v1.SessionStateWaitingForScheduledTime {
			continue
		}

		// Sanity check: session should have a scheduledStartTime
		if ses.Spec.ScheduledStartTime == nil || ses.Spec.ScheduledStartTime.IsZero() {
			ssa.log.Warnw("session in WaitingForScheduledTime state has no ScheduledStartTime",
				"session", ses.Name,
				"namespace", ses.Namespace)
			continue
		}

		scheduledTime := ses.Spec.ScheduledStartTime.Time
		if now.Before(scheduledTime) {
			// Not yet time for this session
			continue
		}

		// Time to activate!
		ssa.log.Infow("Activating scheduled session",
			"session", ses.Name,
			"namespace", ses.Namespace,
			"scheduledStartTime", scheduledTime,
			"now", now)

		// Transition to Approved state
		ses.Status.State = v1.SessionStateApproved
		ses.Status.ActualStartTime = metav1.Now()

		// Add condition for audit trail
		ses.Status.Conditions = append(ses.Status.Conditions, metav1.Condition{
			Type:               "ScheduledStartTimeReached",
			Status:             metav1.ConditionTrue,
			LastTransitionTime: metav1.Now(),
			Reason:             "ActivationTriggered",
			Message:            "Session activated at scheduled start time",
		})

		// Update session status in cluster
		if err := ssa.sessionManager.UpdateBreakglassSessionStatus(context.Background(), ses); err != nil {
			ssa.log.Errorw("failed to activate scheduled session",
				"session", ses.Name,
				"namespace", ses.Namespace,
				"error", err)
			continue
		}

		ssa.log.Infow("Successfully activated scheduled session",
			"session", ses.Name,
			"namespace", ses.Namespace,
			"actualStartTime", ses.Status.ActualStartTime.Time)

		// Record metric for successful activation
		metrics.SessionActivated.WithLabelValues(ses.Spec.Cluster).Inc()

		// RBAC group will now be applied by the authorization controller
		// (same mechanism as immediate sessions)
	}
}
