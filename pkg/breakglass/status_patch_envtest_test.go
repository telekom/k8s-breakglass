// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package breakglass

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/internal/ssatest"
	"github.com/telekom/k8s-breakglass/pkg/quotas"
	"go.uber.org/zap"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestSSAEnvtestSessionExpiryRetriesAndFences(t *testing.T) {
	apiClient := ssatest.Start(t)
	session := ssatest.Session(t, apiClient, "expiry-retry")
	session.Status.State = breakglassv1alpha1.SessionStateApproved
	require.NoError(t, apiClient.Status().Update(t.Context(), session))
	c := &ssatest.CountingClient{Client: apiClient}
	var once sync.Once
	c.BeforeStatusPatch = func(ctx context.Context, _ client.Object) {
		once.Do(func() {
			live := &breakglassv1alpha1.BreakglassSession{}
			require.NoError(t, apiClient.Get(ctx, client.ObjectKeyFromObject(session), live))
			live.Status.ActivityCount = 7
			require.NoError(t, apiClient.Status().Update(ctx, live))
		})
	}
	controller := &BreakglassSessionController{sessionManager: NewSessionManagerWithClientAndReader(c, apiClient)}
	update := func() (breakglassv1alpha1.BreakglassSession, bool, error) {
		return controller.updateSessionStatusIfCurrent(t.Context(), *session, breakglassv1alpha1.SessionStateApproved,
			func(s breakglassv1alpha1.BreakglassSession) bool { return s.Status.ReasonEnded == "" },
			func(s *breakglassv1alpha1.BreakglassSession) {
				s.Status.State = breakglassv1alpha1.SessionStateExpired
				s.Status.ReasonEnded = "expired"
			})
	}
	updated, applied, err := update()
	require.NoError(t, err)
	require.True(t, applied)
	require.EqualValues(t, 2, c.StatusPatches.Load())
	require.EqualValues(t, 7, updated.Status.ActivityCount)
	require.Equal(t, updated.Generation, updated.Status.ObservedGeneration)
	_, applied, err = update()
	require.NoError(t, err)
	require.False(t, applied)
	require.EqualValues(t, 2, c.StatusPatches.Load())
	require.NoError(t, apiClient.Delete(t.Context(), session))
	_, _, err = update()
	require.True(t, apierrors.IsNotFound(err), "%v", err)
}

func TestSSAEnvtestExpiryAcknowledgementRetriesAndSkips(t *testing.T) {
	apiClient := ssatest.Start(t)
	session := ssatest.Session(t, apiClient, "expiry-ack")
	condition := metav1.Condition{
		Type:   string(breakglassv1alpha1.SessionConditionTypeExpiryNotificationIntent),
		Status: metav1.ConditionFalse, Reason: "Pending", LastTransitionTime: metav1.NewTime(time.Now().UTC().Truncate(time.Second)),
	}
	session.SetCondition(condition)
	require.NoError(t, apiClient.Status().Update(t.Context(), session))
	c := &ssatest.CountingClient{Client: apiClient}
	var once sync.Once
	c.BeforeStatusPatch = func(ctx context.Context, _ client.Object) {
		once.Do(func() {
			live := &breakglassv1alpha1.BreakglassSession{}
			require.NoError(t, apiClient.Get(ctx, client.ObjectKeyFromObject(session), live))
			live.Status.ActivityCount = 8
			require.NoError(t, apiClient.Status().Update(ctx, live))
		})
	}
	controller := &BreakglassSessionController{sessionManager: NewSessionManagerWithClientAndReader(c, apiClient)}
	ack := func() error {
		return controller.acknowledgeExpiryNotification(t.Context(), *session, &condition, "QueueAccepted", "accepted")
	}
	require.NoError(t, ack())
	require.EqualValues(t, 2, c.StatusPatches.Load())
	require.NoError(t, apiClient.Get(t.Context(), client.ObjectKeyFromObject(session), session))
	require.EqualValues(t, 8, session.Status.ActivityCount)
	require.Equal(t, metav1.ConditionTrue, session.GetCondition(condition.Type).Status)
	require.NoError(t, ack())
	require.EqualValues(t, 2, c.StatusPatches.Load())
	require.NoError(t, apiClient.Delete(t.Context(), session))
	require.NoError(t, ack())
}

func TestSSAEnvtestScheduledActivationRetriesAndRejectsTerminal(t *testing.T) {
	apiClient := ssatest.Start(t)
	session := ssatest.Session(t, apiClient, "scheduled-retry")
	session.Status.State = breakglassv1alpha1.SessionStateWaitingForScheduledTime
	session.Status.ExpiresAt = metav1.NewTime(time.Now().Add(time.Hour))
	require.NoError(t, apiClient.Status().Update(t.Context(), session))
	desired := session.DeepCopy()
	desired.Status.State = breakglassv1alpha1.SessionStateApproved
	c := &ssatest.CountingClient{Client: apiClient}
	var once sync.Once
	c.BeforeStatusPatch = func(ctx context.Context, _ client.Object) {
		once.Do(func() {
			live := &breakglassv1alpha1.BreakglassSession{}
			require.NoError(t, apiClient.Get(ctx, client.ObjectKeyFromObject(session), live))
			live.Status.ActivityCount = 9
			require.NoError(t, apiClient.Status().Update(ctx, live))
		})
	}
	activator := NewScheduledSessionActivator(zap.NewNop().Sugar(), NewSessionManagerWithClientAndReader(c, apiClient))
	require.NoError(t, activator.updateWaitingScheduledSessionStatus(t.Context(), *desired))
	require.EqualValues(t, 2, c.StatusPatches.Load())
	require.NoError(t, apiClient.Get(t.Context(), client.ObjectKeyFromObject(session), session))
	require.EqualValues(t, 9, session.Status.ActivityCount)
	require.Equal(t, breakglassv1alpha1.SessionStateApproved, session.Status.State)
	require.True(t, apierrors.IsConflict(activator.updateWaitingScheduledSessionStatus(t.Context(), *desired)))
	require.EqualValues(t, 2, c.StatusPatches.Load())
	require.NoError(t, apiClient.Delete(t.Context(), session))
	require.True(t, apierrors.IsNotFound(activator.updateWaitingScheduledSessionStatus(t.Context(), *desired)))
}

func TestSSAEnvtestDebugStatusValidationAndStaleSnapshots(t *testing.T) {
	apiClient := ssatest.Start(t)
	for _, mode := range []string{"apply", "patch"} {
		t.Run(mode, func(t *testing.T) {
			session := ssatest.DebugSession(t, apiClient, "debug-"+mode)
			c := &ssatest.CountingClient{Client: apiClient}
			write := func(mutate func(*breakglassv1alpha1.DebugSessionStatus)) error {
				if mode == "patch" {
					return PatchDebugSessionStatusWithReader(t.Context(), c, apiClient, session, mutate)
				}
				mutate(&session.Status)
				return ApplyDebugSessionStatus(t.Context(), c, session)
			}
			require.NoError(t, write(func(s *breakglassv1alpha1.DebugSessionStatus) { s.Message = "first" }))
			require.EqualValues(t, 1, c.StatusPatches.Load())
			live := session.DeepCopy()
			live.Status.ActivityCount = 10
			require.NoError(t, apiClient.Status().Update(t.Context(), live))
			err := write(func(s *breakglassv1alpha1.DebugSessionStatus) { s.Message = "stale" })
			require.True(t, apierrors.IsConflict(err), "%v", err)
			require.EqualValues(t, 1, c.StatusPatches.Load())
			require.NoError(t, apiClient.Get(t.Context(), client.ObjectKeyFromObject(session), session))
			if mode == "patch" {
				require.ErrorContains(t, write(func(s *breakglassv1alpha1.DebugSessionStatus) { s.ActivityCount-- }), "activityCount must not decrease")
				require.EqualValues(t, 1, c.StatusPatches.Load())
			}
			require.NoError(t, apiClient.Get(t.Context(), client.ObjectKeyFromObject(session), session))
			require.ErrorContains(t, write(func(s *breakglassv1alpha1.DebugSessionStatus) { s.ExpiresAt = nil }), "active session must have an expiry")
			require.EqualValues(t, 1, c.StatusPatches.Load())
			require.NoError(t, apiClient.Get(t.Context(), client.ObjectKeyFromObject(session), session))
			require.NoError(t, write(func(s *breakglassv1alpha1.DebugSessionStatus) {
				s.State = breakglassv1alpha1.DebugSessionStateTerminated
			}))
			require.NoError(t, apiClient.Get(t.Context(), client.ObjectKeyFromObject(session), session))
			require.ErrorContains(t, write(func(s *breakglassv1alpha1.DebugSessionStatus) { s.State = breakglassv1alpha1.DebugSessionStateActive }), "terminal state")
			require.EqualValues(t, 2, c.StatusPatches.Load())
			require.NoError(t, apiClient.Delete(t.Context(), session))
			require.True(t, apierrors.IsNotFound(write(func(*breakglassv1alpha1.DebugSessionStatus) {})))
		})
	}
}

func TestSSAEnvtestAdmissionCompletionRetriesAndSkips(t *testing.T) {
	apiClient := ssatest.Start(t)
	session := ssatest.Session(t, apiClient, "admission")
	c := &ssatest.CountingClient{Client: apiClient}
	var once sync.Once
	c.BeforePatch = func(ctx context.Context, _ client.Object) {
		once.Do(func() {
			live := &breakglassv1alpha1.BreakglassSession{}
			require.NoError(t, apiClient.Get(ctx, client.ObjectKeyFromObject(session), live))
			live.Annotations = map[string]string{"foreign": "preserve"}
			require.NoError(t, apiClient.Update(ctx, live))
		})
	}
	manager := NewSessionManagerWithClientAndReader(c, apiClient)
	require.NoError(t, manager.completeSessionAdmission(t.Context(), session))
	require.EqualValues(t, 2, c.Patches.Load())
	require.Equal(t, "preserve", session.Annotations["foreign"])
	require.Equal(t, quotas.Ready, session.Annotations[quotas.AdmissionAnnotation])
	require.NoError(t, manager.completeSessionAdmission(t.Context(), session))
	require.EqualValues(t, 2, c.Patches.Load())
	require.NoError(t, apiClient.Delete(t.Context(), session))
	require.True(t, apierrors.IsNotFound(manager.completeSessionAdmission(t.Context(), session)))
}

func TestSSAEnvtestDuplicateCleanupStatusSites(t *testing.T) {
	apiClient := ssatest.Start(t)
	log := zap.NewNop().Sugar()
	t.Run("terminalize-rechecks-survivor-after-conflict", func(t *testing.T) {
		survivor := ssatest.Session(t, apiClient, "duplicate-survivor")
		survivor.Status.State = breakglassv1alpha1.SessionStateApproved
		require.NoError(t, apiClient.Status().Update(t.Context(), survivor))
		session := ssatest.Session(t, apiClient, "duplicate-candidate")
		session.Status.State = breakglassv1alpha1.SessionStatePending
		require.NoError(t, apiClient.Status().Update(t.Context(), session))
		c := &ssatest.CountingClient{Client: apiClient}
		var once sync.Once
		c.BeforeStatusPatch = func(ctx context.Context, _ client.Object) {
			once.Do(func() {
				live := session.DeepCopy()
				require.NoError(t, apiClient.Get(ctx, client.ObjectKeyFromObject(session), live))
				live.Status.ActivityCount = 7
				require.NoError(t, apiClient.Status().Update(ctx, live))
			})
		}
		manager := NewSessionManagerWithClientAndReader(c, apiClient)
		key := duplicateSessionKey{Cluster: session.Spec.Cluster, User: session.Spec.User, Group: session.Spec.GrantedGroup}
		terminalized, err := terminateDuplicateSession(t.Context(), log, manager, key, *session)
		require.NoError(t, err)
		require.False(t, terminalized)
		require.EqualValues(t, 1, c.StatusPatches.Load())
		require.NoError(t, apiClient.Get(t.Context(), client.ObjectKeyFromObject(session), session))
		require.EqualValues(t, 7, session.Status.ActivityCount)
		require.Equal(t, breakglassv1alpha1.SessionStatePending, session.Status.State)
		terminalized, err = terminateDuplicateSession(t.Context(), log, manager, key, *session)
		require.NoError(t, err)
		require.True(t, terminalized)
		require.EqualValues(t, 2, c.StatusPatches.Load())
		require.NoError(t, apiClient.Get(t.Context(), client.ObjectKeyFromObject(session), session))
		require.Equal(t, breakglassv1alpha1.SessionStateWithdrawn, session.Status.State)
		require.EqualValues(t, 7, session.Status.ActivityCount)
		terminalized, err = terminateDuplicateSession(t.Context(), log, manager, key, *session)
		require.NoError(t, err)
		require.False(t, terminalized)
		require.EqualValues(t, 2, c.StatusPatches.Load())
		require.NoError(t, apiClient.Delete(t.Context(), session))
		terminalized, err = terminateDuplicateSession(t.Context(), log, manager, key, *session)
		require.NoError(t, err)
		require.False(t, terminalized)
		require.NoError(t, apiClient.Delete(t.Context(), survivor))
	})
	for _, enabled := range []bool{true, false} {
		name := "disabled"
		if enabled {
			name = "enabled"
		}
		t.Run("audit-ack-"+name, func(t *testing.T) {
			session := ssatest.Session(t, apiClient, "duplicate-audit-"+name)
			session.Status.State = breakglassv1alpha1.SessionStateExpired
			session.SetCondition(metav1.Condition{
				Type:   string(breakglassv1alpha1.SessionConditionTypeDuplicateCleanupAuditComplete),
				Status: metav1.ConditionFalse, Reason: duplicateCleanupIntentExpire,
				LastTransitionTime: metav1.NewTime(time.Now().UTC().Truncate(time.Second)),
			})
			require.NoError(t, apiClient.Status().Update(t.Context(), session))
			c := &ssatest.CountingClient{Client: apiClient}
			var once sync.Once
			c.BeforeStatusPatch = func(ctx context.Context, _ client.Object) {
				once.Do(func() {
					live := session.DeepCopy()
					require.NoError(t, apiClient.Get(ctx, client.ObjectKeyFromObject(session), live))
					live.Status.ActivityCount = 11
					require.NoError(t, apiClient.Status().Update(ctx, live))
				})
			}
			manager := NewSessionManagerWithClientAndReader(c, apiClient)
			emitter := &duplicateCleanupAuditRecorder{intentionallyDisabled: !enabled}
			require.NoError(t, drainDuplicateCleanupAudit(t.Context(), log, manager, session.Namespace, session.Name, emitter))
			require.EqualValues(t, 2, c.StatusPatches.Load())
			require.NoError(t, apiClient.Get(t.Context(), client.ObjectKeyFromObject(session), session))
			require.EqualValues(t, 11, session.Status.ActivityCount)
			require.Equal(t, metav1.ConditionTrue, duplicateCleanupAuditCondition(session).Status)
			require.NoError(t, drainDuplicateCleanupAudit(t.Context(), log, manager, session.Namespace, session.Name, emitter))
			require.EqualValues(t, 2, c.StatusPatches.Load())
			expectedEvents := 0
			if enabled {
				expectedEvents = 1
			}
			require.Len(t, emitter.events, expectedEvents)
			require.NoError(t, apiClient.Delete(t.Context(), session))
			require.NoError(t, drainDuplicateCleanupAudit(t.Context(), log, manager, session.Namespace, session.Name, emitter))
		})
	}
}

func TestSSAEnvtestSessionManagerSpecApplyCounts(t *testing.T) {
	apiClient := ssatest.Start(t)
	session := ssatest.Session(t, apiClient, "session-spec")
	session.Status.ActivityCount = 12
	require.NoError(t, apiClient.Status().Update(t.Context(), session))
	c := &ssatest.CountingClient{Client: apiClient}
	manager := NewSessionManagerWithClient(c, WithSessionLogger(zap.NewNop().Sugar()))
	require.NoError(t, manager.UpdateBreakglassSession(t.Context(), *session))
	require.EqualValues(t, 0, c.Applies.Load()) // Same fetched object including server metadata.
	desired := session.DeepCopy()
	desired.Spec.RequestReason = "new request reason"
	desired.ManagedFields = nil
	require.NoError(t, manager.UpdateBreakglassSession(t.Context(), *desired))
	require.EqualValues(t, 1, c.Applies.Load())
	require.NoError(t, apiClient.Get(t.Context(), client.ObjectKeyFromObject(session), session))
	require.Equal(t, desired.Spec.RequestReason, session.Spec.RequestReason)
	require.EqualValues(t, 12, session.Status.ActivityCount)
}

func TestSSAEnvtestSessionProvisionalAdmissionConflict(t *testing.T) {
	apiClient := ssatest.Start(t)
	escalation := ssatest.Escalation(t, apiClient, "quota-owner")
	session := ssatest.Session(t, apiClient, "provisional")
	controlling := true
	session.OwnerReferences = []metav1.OwnerReference{{
		APIVersion: breakglassv1alpha1.GroupVersion.String(), Kind: "BreakglassEscalation",
		Name: escalation.Name, UID: escalation.UID, Controller: &controlling,
	}}
	require.NoError(t, apiClient.Update(t.Context(), session))
	c := &ssatest.CountingClient{Client: apiClient}
	var once sync.Once
	c.BeforePatch = func(ctx context.Context, _ client.Object) {
		once.Do(func() {
			live := session.DeepCopy()
			require.NoError(t, apiClient.Get(ctx, client.ObjectKeyFromObject(session), live))
			live.Annotations = map[string]string{"foreign": "preserve"}
			require.NoError(t, apiClient.Update(ctx, live))
		})
	}
	manager := NewSessionManagerWithClientAndReader(c, apiClient, WithQuotaNamespace("default"))
	require.True(t, apierrors.IsConflict(manager.admitSession(t.Context(), session)))
	require.EqualValues(t, 1, c.Patches.Load())
	require.NoError(t, apiClient.Get(t.Context(), client.ObjectKeyFromObject(session), session))
	require.NoError(t, manager.admitSession(t.Context(), session))
	require.EqualValues(t, 3, c.Patches.Load())
	require.Equal(t, "preserve", session.Annotations["foreign"])
	require.Equal(t, quotas.Ready, session.Annotations[quotas.AdmissionAnnotation])
	require.NoError(t, manager.admitSession(t.Context(), session))
	require.EqualValues(t, 3, c.Patches.Load())
}

func TestSSAEnvtestDebugStatusRejectsImmutableSnapshots(t *testing.T) {
	apiClient := ssatest.Start(t)
	for _, tc := range []struct {
		name   string
		seed   func(*breakglassv1alpha1.DebugSessionStatus)
		mutate func(*breakglassv1alpha1.DebugSessionStatus)
		error  string
	}{
		{"template", func(s *breakglassv1alpha1.DebugSessionStatus) {
			s.ResolvedTemplate = &breakglassv1alpha1.DebugSessionTemplateSpec{DisplayName: "approved"}
		}, func(s *breakglassv1alpha1.DebugSessionStatus) { s.ResolvedTemplate.DisplayName = "changed" }, "template snapshot is immutable"},
		{"groups", func(s *breakglassv1alpha1.DebugSessionStatus) {
			s.AuthenticatedUserGroups = []string{"approved"}
			s.AuthenticatedUserGroupsCaptured = true
		}, func(s *breakglassv1alpha1.DebugSessionStatus) { s.AuthenticatedUserGroups = []string{"changed"} }, "group provenance is immutable"},
		{"renewal", func(*breakglassv1alpha1.DebugSessionStatus) {}, func(s *breakglassv1alpha1.DebugSessionStatus) {
			later := metav1.NewTime(s.ExpiresAt.Add(time.Hour))
			s.ExpiresAt = &later
		}, "expiry may only be extended by one renewal"},
		{"activity-time", func(s *breakglassv1alpha1.DebugSessionStatus) {
			now := metav1.NewTime(time.Now().UTC().Truncate(time.Second))
			s.LastActivity = &now
		}, func(s *breakglassv1alpha1.DebugSessionStatus) { s.LastActivity = nil }, "timestamps must not regress"},
		{"retention-active", func(*breakglassv1alpha1.DebugSessionStatus) {}, func(s *breakglassv1alpha1.DebugSessionStatus) {
			now := metav1.Now()
			s.RetainedUntil = &now
		}, "retainedUntil is only valid for terminal"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			session := ssatest.DebugSession(t, apiClient, "immutable-"+tc.name)
			tc.seed(&session.Status)
			require.NoError(t, apiClient.Status().Update(t.Context(), session))
			c := &ssatest.CountingClient{Client: apiClient}
			require.ErrorContains(t, PatchDebugSessionStatusWithReader(t.Context(), c, apiClient, session, tc.mutate), tc.error)
			require.EqualValues(t, 0, c.StatusPatches.Load())
		})
	}
}
