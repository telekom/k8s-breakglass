// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package breakglass

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"go.uber.org/zap/zaptest"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

// stateIndexerActivation indexes BreakglassSessions by status.state for field selector support.
var stateIndexerActivation = func(o client.Object) []string {
	bs, ok := o.(*breakglassv1alpha1.BreakglassSession)
	if !ok || bs.Status.State == "" {
		return nil
	}
	return []string{string(bs.Status.State)}
}

// metadataNameIndexerActivation indexes objects by metadata.name.
var metadataNameIndexerActivation = func(o client.Object) []string {
	return []string{o.GetName()}
}

// newFakeActivationClient creates a fake client with required indexers for scheduled activation tests.
func newFakeActivationClient(objects ...client.Object) client.Client {
	return fake.NewClientBuilder().
		WithScheme(Scheme).
		WithObjects(objects...).
		WithStatusSubresource(&breakglassv1alpha1.BreakglassSession{}).
		WithIndex(&breakglassv1alpha1.BreakglassSession{}, "status.state", stateIndexerActivation).
		WithIndex(&breakglassv1alpha1.BreakglassSession{}, "metadata.name", metadataNameIndexerActivation).
		Build()
}

type staleScheduledActivationClient struct {
	client.Client
	mutateOnce              sync.Once
	mutate                  func(context.Context, client.Client)
	statusMutateOnce        sync.Once
	mutateBeforeStatusWrite func(context.Context, client.Client)
	statusUpdateErr         error
}

func (c *staleScheduledActivationClient) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	err := c.Client.List(ctx, list, opts...)
	if err == nil {
		if _, ok := list.(*breakglassv1alpha1.BreakglassSessionList); ok && c.mutate != nil {
			c.mutateOnce.Do(func() {
				c.mutate(ctx, c.Client)
			})
		}
	}
	return err
}

func (c *staleScheduledActivationClient) Status() client.SubResourceWriter {
	base := c.Client.Status()
	if c.mutateBeforeStatusWrite == nil && c.statusUpdateErr == nil {
		return base
	}
	return &conflictingStatusWriter{
		SubResourceWriter: base,
		err:               c.statusUpdateErr,
		mutate: func(ctx context.Context) {
			if c.mutateBeforeStatusWrite != nil {
				c.statusMutateOnce.Do(func() {
					c.mutateBeforeStatusWrite(ctx, c.Client)
				})
			}
		},
	}
}

type conflictingStatusWriter struct {
	client.SubResourceWriter
	mutate func(context.Context)
	err    error
}

func (w *conflictingStatusWriter) Update(ctx context.Context, obj client.Object, opts ...client.SubResourceUpdateOption) error {
	return w.failStatusWrite(ctx, obj)
}

func (w *conflictingStatusWriter) Patch(ctx context.Context, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
	return w.failStatusWrite(ctx, obj)
}

func (w *conflictingStatusWriter) failStatusWrite(ctx context.Context, obj client.Object) error {
	if w.mutate != nil {
		w.mutate(ctx)
	}
	if w.err != nil {
		return w.err
	}
	return apierrors.NewConflict(
		schema.GroupResource{Group: breakglassv1alpha1.GroupVersion.Group, Resource: "breakglasssessions"},
		obj.GetName(),
		fmt.Errorf("status changed before scheduled activation update"),
	)
}

func (w *conflictingStatusWriter) Apply(ctx context.Context, obj runtime.ApplyConfiguration, opts ...client.SubResourceApplyOption) error {
	return w.SubResourceWriter.Apply(ctx, obj, opts...)
}

type getErrorActivationClient struct {
	client.Client
	err error
}

func (c *getErrorActivationClient) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	return c.err
}

type countingGetActivationClient struct {
	client.Client
	count int
}

func (c *countingGetActivationClient) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	c.count++
	return c.Client.Get(ctx, key, obj, opts...)
}

func TestActivateScheduledSessions(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()

	t.Run("returns when listing waiting sessions fails", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(Scheme).
			WithStatusSubresource(&breakglassv1alpha1.BreakglassSession{}).
			WithIndex(&breakglassv1alpha1.BreakglassSession{}, "status.state", stateIndexerActivation).
			WithIndex(&breakglassv1alpha1.BreakglassSession{}, "metadata.name", metadataNameIndexerActivation).
			WithInterceptorFuncs(interceptor.Funcs{
				List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
					if _, ok := list.(*breakglassv1alpha1.BreakglassSessionList); ok {
						return assert.AnError
					}
					return c.List(ctx, list, opts...)
				},
			}).
			Build()
		mgr := NewSessionManagerWithClient(fakeClient)

		activator := NewScheduledSessionActivator(logger, mgr).
			WithMailService(nil, "TestBranding", true)

		assert.NotPanics(t, func() {
			activator.ActivateScheduledSessions()
		})
	})

	t.Run("activates session when scheduledStartTime has passed", func(t *testing.T) {
		scheduledTime := time.Now().Add(-5 * time.Minute)
		session := &breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "scheduled-ready",
				Namespace: "breakglass",
			},
			Spec: breakglassv1alpha1.BreakglassSessionSpec{
				User:               "test@example.com",
				Cluster:            "test-cluster",
				GrantedGroup:       "admin",
				ScheduledStartTime: &metav1.Time{Time: scheduledTime},
			},
			Status: breakglassv1alpha1.BreakglassSessionStatus{
				State:      breakglassv1alpha1.SessionStateWaitingForScheduledTime,
				ApprovedAt: metav1.NewTime(scheduledTime.Add(-30 * time.Minute)),
				ExpiresAt:  metav1.NewTime(time.Now().UTC().Add(1 * time.Hour)),
			},
		}

		fakeClient := newFakeActivationClient(session)
		mgr := NewSessionManagerWithClient(fakeClient)

		activator := NewScheduledSessionActivator(logger, mgr).
			WithMailService(nil, "TestBranding", true) // email disabled

		activator.ActivateScheduledSessions()

		var updated breakglassv1alpha1.BreakglassSession
		err := fakeClient.Get(context.Background(),
			client.ObjectKey{Namespace: "breakglass", Name: "scheduled-ready"},
			&updated)
		require.NoError(t, err)
		assert.Equal(t, breakglassv1alpha1.SessionStateApproved, updated.Status.State)
		assert.False(t, updated.Status.ActualStartTime.IsZero(), "ActualStartTime should be set")

		// Verify the ScheduledStartTimeReached condition was added
		var hasCondition bool
		for _, c := range updated.Status.Conditions {
			if c.Type == "ScheduledStartTimeReached" {
				hasCondition = true
				assert.Equal(t, metav1.ConditionTrue, c.Status)
				assert.Equal(t, "ActivationTriggered", c.Reason)
			}
		}
		assert.True(t, hasCondition, "expected ScheduledStartTimeReached condition")
	})

	t.Run("leaves scheduled session waiting when activation status update fails", func(t *testing.T) {
		scheduledTime := time.Now().Add(-5 * time.Minute)
		session := &breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "scheduled-update-fails",
				Namespace: "breakglass",
			},
			Spec: breakglassv1alpha1.BreakglassSessionSpec{
				User:               "test@example.com",
				Cluster:            "test-cluster",
				GrantedGroup:       "admin",
				ScheduledStartTime: &metav1.Time{Time: scheduledTime},
			},
			Status: breakglassv1alpha1.BreakglassSessionStatus{
				State:      breakglassv1alpha1.SessionStateWaitingForScheduledTime,
				ApprovedAt: metav1.NewTime(scheduledTime.Add(-30 * time.Minute)),
				ExpiresAt:  metav1.NewTime(time.Now().Add(1 * time.Hour)),
			},
		}

		baseClient := newFakeActivationClient(session)
		staleClient := &staleScheduledActivationClient{
			Client:          baseClient,
			statusUpdateErr: assert.AnError,
		}
		mgr := NewSessionManagerWithClient(staleClient)

		activator := NewScheduledSessionActivator(logger, mgr).
			WithMailService(nil, "TestBranding", true)

		activator.ActivateScheduledSessions()

		var updated breakglassv1alpha1.BreakglassSession
		err := baseClient.Get(context.Background(),
			client.ObjectKey{Namespace: "breakglass", Name: "scheduled-update-fails"},
			&updated)
		require.NoError(t, err)
		assert.Equal(t, breakglassv1alpha1.SessionStateWaitingForScheduledTime, updated.Status.State)
		assert.True(t, updated.Status.ActualStartTime.IsZero(), "failed activation update must not persist ActualStartTime")
	})

	t.Run("expires session whose validity ended before activation", func(t *testing.T) {
		now := time.Now()
		expiredAt := metav1.NewTime(now.Add(-1 * time.Minute))
		session := &breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "scheduled-already-expired",
				Namespace: "breakglass",
			},
			Spec: breakglassv1alpha1.BreakglassSessionSpec{
				User:               "test@example.com",
				Cluster:            "test-cluster",
				GrantedGroup:       "admin",
				ScheduledStartTime: &metav1.Time{Time: now.Add(-10 * time.Minute)},
			},
			Status: breakglassv1alpha1.BreakglassSessionStatus{
				State:      breakglassv1alpha1.SessionStateWaitingForScheduledTime,
				ApprovedAt: metav1.NewTime(now.Add(-30 * time.Minute)),
				ExpiresAt:  expiredAt,
			},
		}

		fakeClient := newFakeActivationClient(session)
		mgr := NewSessionManagerWithClient(fakeClient)

		activator := NewScheduledSessionActivator(logger, mgr).
			WithMailService(nil, "TestBranding", true)

		activator.ActivateScheduledSessions()

		var updated breakglassv1alpha1.BreakglassSession
		err := fakeClient.Get(context.Background(),
			client.ObjectKey{Namespace: "breakglass", Name: "scheduled-already-expired"},
			&updated)
		require.NoError(t, err)
		assert.Equal(t, breakglassv1alpha1.SessionStateExpired, updated.Status.State)
		assert.True(t, updated.Status.ActualStartTime.IsZero(), "expired scheduled session must not be activated")
		assert.Equal(t, "scheduledSessionExpiredBeforeActivation", updated.Status.ReasonEnded)
		assert.WithinDuration(t, expiredAt.Time, updated.Status.ExpiresAt.Time, time.Second)
		assert.False(t, updated.Status.RetainedUntil.IsZero(), "RetainedUntil should be set for cleanup")

		var hasCondition bool
		for _, cond := range updated.Status.Conditions {
			if cond.Type == string(breakglassv1alpha1.SessionConditionTypeExpired) {
				hasCondition = true
				assert.Equal(t, "ScheduledSessionExpiredBeforeActivation", cond.Reason)
			}
		}
		assert.True(t, hasCondition, "expected Expired condition")
	})

	t.Run("leaves expired scheduled session waiting when expiry status update fails", func(t *testing.T) {
		now := time.Now()
		expiredAt := metav1.NewTime(now.Add(-1 * time.Minute))
		session := &breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "scheduled-expire-update-fails",
				Namespace: "breakglass",
			},
			Spec: breakglassv1alpha1.BreakglassSessionSpec{
				User:               "test@example.com",
				Cluster:            "test-cluster",
				GrantedGroup:       "admin",
				ScheduledStartTime: &metav1.Time{Time: now.Add(-10 * time.Minute)},
			},
			Status: breakglassv1alpha1.BreakglassSessionStatus{
				State:      breakglassv1alpha1.SessionStateWaitingForScheduledTime,
				ApprovedAt: metav1.NewTime(now.Add(-30 * time.Minute)),
				ExpiresAt:  expiredAt,
			},
		}

		baseClient := newFakeActivationClient(session)
		staleClient := &staleScheduledActivationClient{
			Client:          baseClient,
			statusUpdateErr: assert.AnError,
		}
		mgr := NewSessionManagerWithClient(staleClient)

		activator := NewScheduledSessionActivator(logger, mgr).
			WithMailService(nil, "TestBranding", true)

		activator.ActivateScheduledSessions()

		var updated breakglassv1alpha1.BreakglassSession
		err := baseClient.Get(context.Background(),
			client.ObjectKey{Namespace: "breakglass", Name: "scheduled-expire-update-fails"},
			&updated)
		require.NoError(t, err)
		assert.Equal(t, breakglassv1alpha1.SessionStateWaitingForScheduledTime, updated.Status.State)
		assert.Empty(t, updated.Status.ReasonEnded)
		assert.True(t, updated.Status.RetainedUntil.IsZero(), "failed expiry update must not persist retention")
	})

	t.Run("skips session whose live state changed after list", func(t *testing.T) {
		scheduledTime := time.Now().Add(-5 * time.Minute)
		session := &breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "scheduled-withdrawn-after-list",
				Namespace: "breakglass",
			},
			Spec: breakglassv1alpha1.BreakglassSessionSpec{
				User:               "test@example.com",
				Cluster:            "test-cluster",
				GrantedGroup:       "admin",
				ScheduledStartTime: &metav1.Time{Time: scheduledTime},
			},
			Status: breakglassv1alpha1.BreakglassSessionStatus{
				State:      breakglassv1alpha1.SessionStateWaitingForScheduledTime,
				ApprovedAt: metav1.NewTime(scheduledTime.Add(-30 * time.Minute)),
				ExpiresAt:  metav1.NewTime(time.Now().Add(1 * time.Hour)),
			},
		}

		baseClient := newFakeActivationClient(session)
		staleClient := &staleScheduledActivationClient{
			Client: baseClient,
			mutate: func(ctx context.Context, c client.Client) {
				current := &breakglassv1alpha1.BreakglassSession{}
				err := c.Get(ctx, client.ObjectKey{Namespace: "breakglass", Name: "scheduled-withdrawn-after-list"}, current)
				require.NoError(t, err)
				current.Status.State = breakglassv1alpha1.SessionStateWithdrawn
				current.Status.WithdrawnAt = metav1.NewTime(time.Now())
				err = c.Status().Update(ctx, current)
				require.NoError(t, err)
			},
		}
		mgr := NewSessionManagerWithClient(staleClient)

		activator := NewScheduledSessionActivator(logger, mgr).
			WithMailService(nil, "TestBranding", true)

		activator.ActivateScheduledSessions()

		var updated breakglassv1alpha1.BreakglassSession
		err := baseClient.Get(context.Background(),
			client.ObjectKey{Namespace: "breakglass", Name: "scheduled-withdrawn-after-list"},
			&updated)
		require.NoError(t, err)
		assert.Equal(t, breakglassv1alpha1.SessionStateWithdrawn, updated.Status.State)
		assert.True(t, updated.Status.ActualStartTime.IsZero(), "stale scheduled activation must not reactivate withdrawn sessions")

		for _, condition := range updated.Status.Conditions {
			assert.NotEqual(t, "ScheduledStartTimeReached", condition.Type)
		}
	})

	t.Run("skips future scheduled session before live read", func(t *testing.T) {
		scheduledTime := time.Now().Add(30 * time.Minute)
		session := &breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "scheduled-future",
				Namespace: "breakglass",
			},
			Spec: breakglassv1alpha1.BreakglassSessionSpec{
				User:               "test@example.com",
				Cluster:            "test-cluster",
				GrantedGroup:       "admin",
				ScheduledStartTime: &metav1.Time{Time: scheduledTime},
			},
			Status: breakglassv1alpha1.BreakglassSessionStatus{
				State:      breakglassv1alpha1.SessionStateWaitingForScheduledTime,
				ApprovedAt: metav1.NewTime(time.Now()),
				ExpiresAt:  metav1.NewTime(scheduledTime.Add(1 * time.Hour)),
			},
		}

		baseClient := newFakeActivationClient(session)
		countingClient := &countingGetActivationClient{Client: baseClient}
		mgr := NewSessionManagerWithClient(countingClient)
		activator := NewScheduledSessionActivator(logger, mgr).
			WithMailService(nil, "TestBranding", true)

		activator.ActivateScheduledSessions()

		assert.Zero(t, countingClient.count, "future scheduled sessions should not require a live APIReader Get")
		var updated breakglassv1alpha1.BreakglassSession
		err := baseClient.Get(context.Background(),
			client.ObjectKey{Namespace: "breakglass", Name: "scheduled-future"},
			&updated)
		require.NoError(t, err)
		assert.Equal(t, breakglassv1alpha1.SessionStateWaitingForScheduledTime, updated.Status.State)
		assert.True(t, updated.Status.ActualStartTime.IsZero())
	})

	t.Run("skips session whose live state changes before status update", func(t *testing.T) {
		scheduledTime := time.Now().Add(-5 * time.Minute)
		session := &breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "scheduled-withdrawn-before-update",
				Namespace: "breakglass",
			},
			Spec: breakglassv1alpha1.BreakglassSessionSpec{
				User:               "test@example.com",
				Cluster:            "test-cluster",
				GrantedGroup:       "admin",
				ScheduledStartTime: &metav1.Time{Time: scheduledTime},
			},
			Status: breakglassv1alpha1.BreakglassSessionStatus{
				State:      breakglassv1alpha1.SessionStateWaitingForScheduledTime,
				ApprovedAt: metav1.NewTime(scheduledTime.Add(-30 * time.Minute)),
				ExpiresAt:  metav1.NewTime(time.Now().Add(1 * time.Hour)),
			},
		}

		baseClient := newFakeActivationClient(session)
		staleClient := &staleScheduledActivationClient{
			Client: baseClient,
			mutateBeforeStatusWrite: func(ctx context.Context, c client.Client) {
				current := &breakglassv1alpha1.BreakglassSession{}
				err := c.Get(ctx, client.ObjectKey{Namespace: "breakglass", Name: "scheduled-withdrawn-before-update"}, current)
				require.NoError(t, err)
				current.Status.State = breakglassv1alpha1.SessionStateWithdrawn
				current.Status.WithdrawnAt = metav1.NewTime(time.Now())
				err = c.Status().Update(ctx, current)
				require.NoError(t, err)
			},
		}
		mgr := NewSessionManagerWithClient(staleClient)

		activator := NewScheduledSessionActivator(logger, mgr).
			WithMailService(nil, "TestBranding", true)

		activator.ActivateScheduledSessions()

		var updated breakglassv1alpha1.BreakglassSession
		err := baseClient.Get(context.Background(),
			client.ObjectKey{Namespace: "breakglass", Name: "scheduled-withdrawn-before-update"},
			&updated)
		require.NoError(t, err)
		assert.Equal(t, breakglassv1alpha1.SessionStateWithdrawn, updated.Status.State)
		assert.True(t, updated.Status.ActualStartTime.IsZero(), "conflicted scheduled activation must not reactivate withdrawn sessions")

		for _, condition := range updated.Status.Conditions {
			assert.NotEqual(t, "ScheduledStartTimeReached", condition.Type)
		}
	})

	t.Run("skips activation when status update returns non-conflict error", func(t *testing.T) {
		scheduledTime := time.Now().Add(-5 * time.Minute)
		session := &breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "scheduled-update-error",
				Namespace: "breakglass",
			},
			Spec: breakglassv1alpha1.BreakglassSessionSpec{
				User:               "test@example.com",
				Cluster:            "test-cluster",
				GrantedGroup:       "admin",
				ScheduledStartTime: &metav1.Time{Time: scheduledTime},
			},
			Status: breakglassv1alpha1.BreakglassSessionStatus{
				State:      breakglassv1alpha1.SessionStateWaitingForScheduledTime,
				ApprovedAt: metav1.NewTime(scheduledTime.Add(-30 * time.Minute)),
				ExpiresAt:  metav1.NewTime(time.Now().Add(1 * time.Hour)),
			},
		}

		baseClient := newFakeActivationClient(session)
		staleClient := &staleScheduledActivationClient{
			Client:          baseClient,
			statusUpdateErr: fmt.Errorf("status writer unavailable"),
		}
		mgr := NewSessionManagerWithClient(staleClient)

		activator := NewScheduledSessionActivator(logger, mgr).
			WithMailService(nil, "TestBranding", true)

		activator.ActivateScheduledSessions()

		var updated breakglassv1alpha1.BreakglassSession
		err := baseClient.Get(context.Background(),
			client.ObjectKey{Namespace: "breakglass", Name: "scheduled-update-error"},
			&updated)
		require.NoError(t, err)
		assert.Equal(t, breakglassv1alpha1.SessionStateWaitingForScheduledTime, updated.Status.State)
		assert.True(t, updated.Status.ActualStartTime.IsZero(), "failed status writes must not activate the persisted session")
	})

	t.Run("does not activate session before scheduledStartTime", func(t *testing.T) {
		futureTime := time.Now().Add(1 * time.Hour)
		session := &breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "scheduled-future",
				Namespace: "breakglass",
			},
			Spec: breakglassv1alpha1.BreakglassSessionSpec{
				User:               "test@example.com",
				Cluster:            "test-cluster",
				GrantedGroup:       "admin",
				ScheduledStartTime: &metav1.Time{Time: futureTime},
			},
			Status: breakglassv1alpha1.BreakglassSessionStatus{
				State:      breakglassv1alpha1.SessionStateWaitingForScheduledTime,
				ApprovedAt: metav1.NewTime(time.Now().UTC().Add(-10 * time.Minute)),
				ExpiresAt:  metav1.NewTime(futureTime.Add(1 * time.Hour)),
			},
		}

		fakeClient := newFakeActivationClient(session)
		mgr := NewSessionManagerWithClient(fakeClient)

		activator := NewScheduledSessionActivator(logger, mgr).
			WithMailService(nil, "TestBranding", true)

		activator.ActivateScheduledSessions()

		var updated breakglassv1alpha1.BreakglassSession
		err := fakeClient.Get(context.Background(),
			client.ObjectKey{Namespace: "breakglass", Name: "scheduled-future"},
			&updated)
		require.NoError(t, err)
		assert.Equal(t, breakglassv1alpha1.SessionStateWaitingForScheduledTime, updated.Status.State)
		assert.True(t, updated.Status.ActualStartTime.IsZero(), "ActualStartTime should not be set yet")
	})

	t.Run("expires session with nil scheduledStartTime", func(t *testing.T) {
		session := &breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "no-schedule",
				Namespace: "breakglass",
			},
			Spec: breakglassv1alpha1.BreakglassSessionSpec{
				User:               "test@example.com",
				Cluster:            "test-cluster",
				GrantedGroup:       "admin",
				ScheduledStartTime: nil,
			},
			Status: breakglassv1alpha1.BreakglassSessionStatus{
				State:      breakglassv1alpha1.SessionStateWaitingForScheduledTime,
				ApprovedAt: metav1.NewTime(time.Now().UTC().Add(-10 * time.Minute)),
			},
		}

		fakeClient := newFakeActivationClient(session)
		mgr := NewSessionManagerWithClient(fakeClient)

		activator := NewScheduledSessionActivator(logger, mgr).
			WithMailService(nil, "TestBranding", true)

		// Should not panic
		activator.ActivateScheduledSessions()

		var updated breakglassv1alpha1.BreakglassSession
		err := fakeClient.Get(context.Background(),
			client.ObjectKey{Namespace: "breakglass", Name: "no-schedule"},
			&updated)
		require.NoError(t, err)
		// Session should be expired — nil ScheduledStartTime is invalid
		assert.Equal(t, breakglassv1alpha1.SessionStateExpired, updated.Status.State)
		assert.False(t, updated.Status.ExpiresAt.IsZero(), "ExpiresAt should be set when expiring stuck session")

		// Verify the Expired condition was added
		var hasCondition bool
		for _, cond := range updated.Status.Conditions {
			if cond.Type == string(breakglassv1alpha1.SessionConditionTypeExpired) {
				hasCondition = true
				assert.Equal(t, "MissingScheduledStartTime", cond.Reason)
			}
		}
		assert.True(t, hasCondition, "expected Expired condition")
	})

	t.Run("skips expiry when status update conflicts", func(t *testing.T) {
		session := &breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "no-schedule-conflict",
				Namespace: "breakglass",
			},
			Spec: breakglassv1alpha1.BreakglassSessionSpec{
				User:         "test@example.com",
				Cluster:      "test-cluster",
				GrantedGroup: "admin",
			},
			Status: breakglassv1alpha1.BreakglassSessionStatus{
				State:      breakglassv1alpha1.SessionStateWaitingForScheduledTime,
				ApprovedAt: metav1.NewTime(time.Now().Add(-10 * time.Minute)),
			},
		}

		baseClient := newFakeActivationClient(session)
		staleClient := &staleScheduledActivationClient{
			Client: baseClient,
			mutateBeforeStatusWrite: func(ctx context.Context, c client.Client) {
				current := &breakglassv1alpha1.BreakglassSession{}
				err := c.Get(ctx, client.ObjectKey{Namespace: "breakglass", Name: "no-schedule-conflict"}, current)
				require.NoError(t, err)
				current.Status.State = breakglassv1alpha1.SessionStateWithdrawn
				current.Status.WithdrawnAt = metav1.NewTime(time.Now())
				err = c.Status().Update(ctx, current)
				require.NoError(t, err)
			},
		}
		mgr := NewSessionManagerWithClient(staleClient)

		activator := NewScheduledSessionActivator(logger, mgr).
			WithMailService(nil, "TestBranding", true)

		activator.ActivateScheduledSessions()

		var updated breakglassv1alpha1.BreakglassSession
		err := baseClient.Get(context.Background(),
			client.ObjectKey{Namespace: "breakglass", Name: "no-schedule-conflict"},
			&updated)
		require.NoError(t, err)
		assert.Equal(t, breakglassv1alpha1.SessionStateWithdrawn, updated.Status.State)
		assert.True(t, updated.Status.RetainedUntil.IsZero(), "conflicted expiry must not stamp retention")
	})

	t.Run("keeps session waiting when nil scheduledStartTime update fails", func(t *testing.T) {
		session := &breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "no-schedule-update-error",
				Namespace: "breakglass",
			},
			Spec: breakglassv1alpha1.BreakglassSessionSpec{
				User:         "test@example.com",
				Cluster:      "test-cluster",
				GrantedGroup: "admin",
			},
			Status: breakglassv1alpha1.BreakglassSessionStatus{
				State:      breakglassv1alpha1.SessionStateWaitingForScheduledTime,
				ApprovedAt: metav1.NewTime(time.Now().Add(-10 * time.Minute)),
			},
		}

		baseClient := newFakeActivationClient(session)
		staleClient := &staleScheduledActivationClient{
			Client:          baseClient,
			statusUpdateErr: fmt.Errorf("status writer unavailable"),
		}
		mgr := NewSessionManagerWithClient(staleClient)

		activator := NewScheduledSessionActivator(logger, mgr).
			WithMailService(nil, "TestBranding", true)

		activator.ActivateScheduledSessions()

		var updated breakglassv1alpha1.BreakglassSession
		err := baseClient.Get(context.Background(),
			client.ObjectKey{Namespace: "breakglass", Name: "no-schedule-update-error"},
			&updated)
		require.NoError(t, err)
		assert.Equal(t, breakglassv1alpha1.SessionStateWaitingForScheduledTime, updated.Status.State)
		assert.True(t, updated.Status.RetainedUntil.IsZero(), "failed expiry writes must not persist terminal retention")
	})

	t.Run("expires session with zero scheduledStartTime", func(t *testing.T) {
		session := &breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "zero-schedule",
				Namespace: "breakglass",
			},
			Spec: breakglassv1alpha1.BreakglassSessionSpec{
				User:               "test@example.com",
				Cluster:            "test-cluster",
				GrantedGroup:       "admin",
				ScheduledStartTime: &metav1.Time{}, // zero value
			},
			Status: breakglassv1alpha1.BreakglassSessionStatus{
				State:      breakglassv1alpha1.SessionStateWaitingForScheduledTime,
				ApprovedAt: metav1.NewTime(time.Now().UTC().Add(-10 * time.Minute)),
			},
		}

		fakeClient := newFakeActivationClient(session)
		mgr := NewSessionManagerWithClient(fakeClient)

		activator := NewScheduledSessionActivator(logger, mgr).
			WithMailService(nil, "TestBranding", true)

		activator.ActivateScheduledSessions()

		var updated breakglassv1alpha1.BreakglassSession
		err := fakeClient.Get(context.Background(),
			client.ObjectKey{Namespace: "breakglass", Name: "zero-schedule"},
			&updated)
		require.NoError(t, err)
		assert.Equal(t, breakglassv1alpha1.SessionStateExpired, updated.Status.State)
		assert.False(t, updated.Status.ExpiresAt.IsZero(), "ExpiresAt should be set when expiring stuck session")
	})

	t.Run("handles multiple sessions with different scheduled times", func(t *testing.T) {
		pastTime := time.Now().Add(-10 * time.Minute)
		futureTime := time.Now().Add(2 * time.Hour)

		readySession := &breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "multi-ready",
				Namespace: "breakglass",
			},
			Spec: breakglassv1alpha1.BreakglassSessionSpec{
				User:               "user1@example.com",
				Cluster:            "cluster-a",
				GrantedGroup:       "admin",
				ScheduledStartTime: &metav1.Time{Time: pastTime},
			},
			Status: breakglassv1alpha1.BreakglassSessionStatus{
				State:      breakglassv1alpha1.SessionStateWaitingForScheduledTime,
				ApprovedAt: metav1.NewTime(pastTime.Add(-1 * time.Hour)),
				ExpiresAt:  metav1.NewTime(time.Now().UTC().Add(2 * time.Hour)),
			},
		}

		waitingSession := &breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "multi-waiting",
				Namespace: "breakglass",
			},
			Spec: breakglassv1alpha1.BreakglassSessionSpec{
				User:               "user2@example.com",
				Cluster:            "cluster-b",
				GrantedGroup:       "viewer",
				ScheduledStartTime: &metav1.Time{Time: futureTime},
			},
			Status: breakglassv1alpha1.BreakglassSessionStatus{
				State:      breakglassv1alpha1.SessionStateWaitingForScheduledTime,
				ApprovedAt: metav1.NewTime(time.Now().UTC().Add(-30 * time.Minute)),
				ExpiresAt:  metav1.NewTime(futureTime.Add(1 * time.Hour)),
			},
		}

		fakeClient := newFakeActivationClient(readySession, waitingSession)
		mgr := NewSessionManagerWithClient(fakeClient)

		activator := NewScheduledSessionActivator(logger, mgr).
			WithMailService(nil, "TestBranding", true)

		activator.ActivateScheduledSessions()

		// Ready session should be activated
		var updatedReady breakglassv1alpha1.BreakglassSession
		err := fakeClient.Get(context.Background(),
			client.ObjectKey{Namespace: "breakglass", Name: "multi-ready"},
			&updatedReady)
		require.NoError(t, err)
		assert.Equal(t, breakglassv1alpha1.SessionStateApproved, updatedReady.Status.State)

		// Waiting session should remain unchanged
		var updatedWaiting breakglassv1alpha1.BreakglassSession
		err = fakeClient.Get(context.Background(),
			client.ObjectKey{Namespace: "breakglass", Name: "multi-waiting"},
			&updatedWaiting)
		require.NoError(t, err)
		assert.Equal(t, breakglassv1alpha1.SessionStateWaitingForScheduledTime, updatedWaiting.Status.State)
	})

	t.Run("activates session 1 second past scheduled time", func(t *testing.T) {
		justPast := time.Now().Add(-1 * time.Second)
		session := &breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "boundary-activation",
				Namespace: "breakglass",
			},
			Spec: breakglassv1alpha1.BreakglassSessionSpec{
				User:               "test@example.com",
				Cluster:            "test-cluster",
				GrantedGroup:       "admin",
				ScheduledStartTime: &metav1.Time{Time: justPast},
			},
			Status: breakglassv1alpha1.BreakglassSessionStatus{
				State:      breakglassv1alpha1.SessionStateWaitingForScheduledTime,
				ApprovedAt: metav1.NewTime(justPast.Add(-1 * time.Hour)),
				ExpiresAt:  metav1.NewTime(time.Now().UTC().Add(1 * time.Hour)),
			},
		}

		fakeClient := newFakeActivationClient(session)
		mgr := NewSessionManagerWithClient(fakeClient)

		activator := NewScheduledSessionActivator(logger, mgr).
			WithMailService(nil, "TestBranding", true)

		activator.ActivateScheduledSessions()

		var updated breakglassv1alpha1.BreakglassSession
		err := fakeClient.Get(context.Background(),
			client.ObjectKey{Namespace: "breakglass", Name: "boundary-activation"},
			&updated)
		require.NoError(t, err)
		assert.Equal(t, breakglassv1alpha1.SessionStateApproved, updated.Status.State)
	})

	t.Run("no sessions to activate is a no-op", func(t *testing.T) {
		fakeClient := newFakeActivationClient() // no sessions
		mgr := NewSessionManagerWithClient(fakeClient)

		activator := NewScheduledSessionActivator(logger, mgr).
			WithMailService(nil, "TestBranding", true)

		// Should not panic
		assert.NotPanics(t, func() {
			activator.ActivateScheduledSessions()
		})
	})

	t.Run("ignores sessions in other states", func(t *testing.T) {
		// An approved session should not be picked up by GetSessionsByState(WaitingForScheduledTime)
		approvedSession := &breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "already-approved",
				Namespace: "breakglass",
			},
			Spec: breakglassv1alpha1.BreakglassSessionSpec{
				User:               "test@example.com",
				Cluster:            "test-cluster",
				GrantedGroup:       "admin",
				ScheduledStartTime: &metav1.Time{Time: time.Now().Add(-10 * time.Minute)},
			},
			Status: breakglassv1alpha1.BreakglassSessionStatus{
				State:           breakglassv1alpha1.SessionStateApproved,
				ApprovedAt:      metav1.NewTime(time.Now().UTC().Add(-1 * time.Hour)),
				ActualStartTime: metav1.NewTime(time.Now().UTC().Add(-1 * time.Hour)),
				ExpiresAt:       metav1.NewTime(time.Now().UTC().Add(1 * time.Hour)),
			},
		}

		fakeClient := newFakeActivationClient(approvedSession)
		mgr := NewSessionManagerWithClient(fakeClient)

		activator := NewScheduledSessionActivator(logger, mgr).
			WithMailService(nil, "TestBranding", true)

		activator.ActivateScheduledSessions()

		// Should remain unchanged
		var updated breakglassv1alpha1.BreakglassSession
		err := fakeClient.Get(context.Background(),
			client.ObjectKey{Namespace: "breakglass", Name: "already-approved"},
			&updated)
		require.NoError(t, err)
		assert.Equal(t, breakglassv1alpha1.SessionStateApproved, updated.Status.State)
	})

	t.Run("activation with past scheduledStartTime (far in the past)", func(t *testing.T) {
		farPast := time.Now().Add(-24 * time.Hour) // 1 day ago
		session := &breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "far-past-scheduled",
				Namespace: "breakglass",
			},
			Spec: breakglassv1alpha1.BreakglassSessionSpec{
				User:               "test@example.com",
				Cluster:            "test-cluster",
				GrantedGroup:       "admin",
				ScheduledStartTime: &metav1.Time{Time: farPast},
			},
			Status: breakglassv1alpha1.BreakglassSessionStatus{
				State:      breakglassv1alpha1.SessionStateWaitingForScheduledTime,
				ApprovedAt: metav1.NewTime(farPast.Add(-1 * time.Hour)),
				ExpiresAt:  metav1.NewTime(time.Now().UTC().Add(1 * time.Hour)),
			},
		}

		fakeClient := newFakeActivationClient(session)
		mgr := NewSessionManagerWithClient(fakeClient)

		activator := NewScheduledSessionActivator(logger, mgr).
			WithMailService(nil, "TestBranding", true)

		activator.ActivateScheduledSessions()

		var updated breakglassv1alpha1.BreakglassSession
		err := fakeClient.Get(context.Background(),
			client.ObjectKey{Namespace: "breakglass", Name: "far-past-scheduled"},
			&updated)
		require.NoError(t, err)
		// Should still activate even if far in the past
		assert.Equal(t, breakglassv1alpha1.SessionStateApproved, updated.Status.State)
	})
}

func TestCurrentWaitingScheduledSession(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	listed := breakglassv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "listed-session",
			Namespace: "breakglass",
		},
		Status: breakglassv1alpha1.BreakglassSessionStatus{
			State: breakglassv1alpha1.SessionStateWaitingForScheduledTime,
		},
	}

	t.Run("returns false when live session was deleted", func(t *testing.T) {
		fakeClient := newFakeActivationClient()
		mgr := NewSessionManagerWithClient(fakeClient)
		activator := NewScheduledSessionActivator(logger, mgr)

		current, ok := activator.currentWaitingScheduledSession(context.Background(), listed, "activation")

		assert.False(t, ok)
		assert.Equal(t, listed.Name, current.Name)
	})

	t.Run("returns false when live session read fails", func(t *testing.T) {
		baseClient := newFakeActivationClient()
		mgr := NewSessionManagerWithClient(&getErrorActivationClient{
			Client: baseClient,
			err:    fmt.Errorf("reader unavailable"),
		})
		activator := NewScheduledSessionActivator(logger, mgr)

		current, ok := activator.currentWaitingScheduledSession(context.Background(), listed, "activation")

		assert.False(t, ok)
		assert.Equal(t, listed.Name, current.Name)
	})
}

func TestApplyScheduledSessionStatusTransitionPreservesUnrelatedLiveStatus(t *testing.T) {
	current := &breakglassv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "scheduled-session",
			Generation: 7,
		},
		Status: breakglassv1alpha1.BreakglassSessionStatus{
			State: breakglassv1alpha1.SessionStateWaitingForScheduledTime,
			Conditions: []metav1.Condition{{
				Type:               "UnrelatedMaintenance",
				Status:             metav1.ConditionTrue,
				LastTransitionTime: metav1.NewTime(time.Now().Add(-time.Hour)),
				Reason:             "StillOwnedElsewhere",
				Message:            "must survive scheduled transition patch",
			}},
		},
	}
	desired := current.DeepCopy()
	desired.Status.State = breakglassv1alpha1.SessionStateApproved
	desired.Status.ActualStartTime = metav1.Now()
	desired.SetCondition(metav1.Condition{
		Type:               "ScheduledStartTimeReached",
		Status:             metav1.ConditionTrue,
		LastTransitionTime: metav1.Now(),
		Reason:             "ActivationTriggered",
		Message:            "Session activated at scheduled start time",
	})

	applyScheduledSessionStatusTransition(current, *desired)

	assert.Equal(t, breakglassv1alpha1.SessionStateApproved, current.Status.State)
	assert.Equal(t, int64(7), current.Status.ObservedGeneration)
	assert.False(t, current.Status.ActualStartTime.IsZero())
	assert.Len(t, current.Status.Conditions, 2)
	assert.Condition(t, func() bool {
		for _, condition := range current.Status.Conditions {
			if condition.Type == "UnrelatedMaintenance" && condition.Reason == "StillOwnedElsewhere" {
				return true
			}
		}
		return false
	})
}

func TestNewScheduledSessionActivator(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	fakeClient := newFakeActivationClient()
	mgr := NewSessionManagerWithClient(fakeClient)

	t.Run("creates activator with defaults", func(t *testing.T) {
		activator := NewScheduledSessionActivator(logger, mgr)
		assert.NotNil(t, activator)
		assert.False(t, activator.disableEmail)
		// Regression guards: verify zero-value defaults are not accidentally changed by constructor
		assert.Nil(t, activator.mailService)
		assert.Empty(t, activator.brandingName)
	})

	t.Run("WithMailService sets mail properties", func(t *testing.T) {
		activator := NewScheduledSessionActivator(logger, mgr).
			WithMailService(nil, "TestBrand", true)
		assert.True(t, activator.disableEmail)
		assert.Equal(t, "TestBrand", activator.brandingName)
	})
}
