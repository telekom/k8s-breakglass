// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func defenderExpiry() *metav1.Time {
	expires := metav1.NewTime(time.Now().Add(time.Hour))
	return &expires
}

func TestDefenderNamespaceUsesTemplateTarget(t *testing.T) {
	c := &DebugSessionAPIController{log: zap.NewNop().Sugar()}
	template := &breakglassv1alpha1.DebugSessionTemplate{Spec: breakglassv1alpha1.DebugSessionTemplateSpec{TargetNamespace: "admin-debug"}}
	ns, err := c.resolveTargetNamespace(context.Background(), "", template, "", nil)
	require.NoError(t, err)
	assert.Equal(t, "admin-debug", ns)
	_, err = c.resolveTargetNamespace(context.Background(), "", template, "attacker", nil)
	assert.Error(t, err)
}

func TestDefenderEmptyNodeSelectorTermsAreUnsatisfiable(t *testing.T) {
	nonempty := &corev1.NodeSelector{NodeSelectorTerms: []corev1.NodeSelectorTerm{{MatchExpressions: []corev1.NodeSelectorRequirement{{Key: "pool", Operator: corev1.NodeSelectorOpExists}}}}}
	for _, pair := range [][2]*corev1.NodeSelector{{{}, nonempty}, {nonempty, {}}, {{}, nil}, {nil, {}}} {
		selector, err := andNodeSelectors(pair[0], pair[1])
		require.NoError(t, err)
		require.NotNil(t, selector)
		require.Empty(t, selector.NodeSelectorTerms)
	}
	selector, err := andNodeSelectors(nil, nonempty)
	require.NoError(t, err)
	require.Equal(t, nonempty, selector)
}

func TestDefenderNotificationExclusionsNormalizeUsersAndSuppressUnresolvedGroups(t *testing.T) {
	result := buildNotificationRecipients([]string{" User@Example.test ", "other@example.test"}, &breakglassv1alpha1.DebugSessionNotificationConfig{
		AdditionalRecipients: []string{"other@example.test"},
		ExcludedRecipients:   &breakglassv1alpha1.NotificationExclusions{Users: []string{"user@example.test"}, Groups: []string{"GROUP-OPS"}},
	})
	assert.Empty(t, result)
	result = buildNotificationRecipients([]string{" User@Example.test "}, &breakglassv1alpha1.DebugSessionNotificationConfig{ExcludedRecipients: &breakglassv1alpha1.NotificationExclusions{Users: []string{"user@example.test"}}})
	assert.Empty(t, result)
}

func TestDefenderRecordedBindingWithoutApproversDenies(t *testing.T) {
	template := &breakglassv1alpha1.DebugSessionTemplate{ObjectMeta: metav1.ObjectMeta{Name: "template"}, Spec: breakglassv1alpha1.DebugSessionTemplateSpec{Approvers: &breakglassv1alpha1.DebugSessionApprovers{Users: []string{"approver"}}}}
	session := &breakglassv1alpha1.DebugSession{ObjectMeta: metav1.ObjectMeta{Name: "session", Namespace: "system"}, Spec: breakglassv1alpha1.DebugSessionSpec{TemplateRef: "template", BindingRef: &breakglassv1alpha1.BindingReference{Name: "deleted", Namespace: "system"}}}
	client := fake.NewClientBuilder().WithScheme(Scheme).WithObjects(template, session).Build()
	c := NewDebugSessionAPIController(zap.NewNop().Sugar(), client, nil, nil)
	ok, err := c.canReadDebugSession(context.Background(), session, debugSessionReadIdentity{username: "approver"})
	require.Error(t, err)
	assert.False(t, ok)
}

func TestDefenderMutationRefreshRejectsRevokedSession(t *testing.T) {
	session := &breakglassv1alpha1.DebugSession{ObjectMeta: metav1.ObjectMeta{Name: "session", Namespace: "system"}, Status: breakglassv1alpha1.DebugSessionStatus{State: breakglassv1alpha1.DebugSessionStateTerminated}}
	client := fake.NewClientBuilder().WithScheme(Scheme).WithObjects(session).Build()
	h := NewKubectlDebugHandler(client, nil).withIdentity(debugSessionReadIdentity{legacyAllowed: true})
	err := h.requireActiveSession(context.Background(), session, "")
	assert.Error(t, err)
	var operationErr *kubectlDebugOperationError
	require.ErrorAs(t, err, &operationErr)
	assert.Equal(t, kubectlDebugOperationErrorPolicy, operationErr.kind)
}

type defenderGroupResolver map[string][]string

func (r defenderGroupResolver) Members(_ context.Context, group string) ([]string, error) {
	members, ok := r[group]
	if !ok {
		return nil, fmt.Errorf("group unavailable")
	}
	return members, nil
}

func TestDefenderNotificationExclusionsResolveMembership(t *testing.T) {
	cfg := &breakglassv1alpha1.DebugSessionNotificationConfig{ExcludedRecipients: &breakglassv1alpha1.NotificationExclusions{Groups: []string{"ops"}}}
	before := cfg.DeepCopy()
	c := &DebugSessionAPIController{log: zap.NewNop().Sugar(), groupMemberResolver: defenderGroupResolver{"ops": {"Alice@Example.test"}}}
	require.Equal(t, []string{"bob@example.test"}, c.notificationRecipients(context.Background(), []string{"alice@example.test", "bob@example.test"}, cfg))
	require.Equal(t, before, cfg)
	c.groupMemberResolver = defenderGroupResolver{}
	require.Empty(t, c.notificationRecipients(context.Background(), []string{"alice@example.test", "bob@example.test"}, cfg))
}

func TestDefenderMutationRechecksAfterSpokeRead(t *testing.T) {
	for _, revoke := range []string{"terminated", "participant-left", "provider-replaced"} {
		t.Run(revoke, func(t *testing.T) {
			ctx := context.Background()
			ds := &breakglassv1alpha1.DebugSession{ObjectMeta: metav1.ObjectMeta{Name: "session", Namespace: "hub", UID: types.UID("session-uid")}, Spec: breakglassv1alpha1.DebugSessionSpec{Cluster: "spoke"}, Status: breakglassv1alpha1.DebugSessionStatus{State: breakglassv1alpha1.DebugSessionStateActive, ExpiresAt: defenderExpiry(), Participants: []breakglassv1alpha1.DebugSessionParticipant{{User: "operator", IdentityProviderName: "a", IdentityProviderIssuer: "https://a.example", Role: breakglassv1alpha1.ParticipantRoleParticipant}}}}
			hub := fake.NewClientBuilder().WithScheme(Scheme).WithObjects(ds).WithStatusSubresource(ds).Build()
			mutations := 0
			spoke := fake.NewClientBuilder().WithScheme(Scheme).WithObjects(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "default"}}).WithInterceptorFuncs(interceptor.Funcs{
				Get: func(ctx context.Context, cl ctrlclient.WithWatch, key ctrlclient.ObjectKey, obj ctrlclient.Object, opts ...ctrlclient.GetOption) error {
					if err := cl.Get(ctx, key, obj, opts...); err != nil {
						return err
					}
					current := &breakglassv1alpha1.DebugSession{}
					if err := hub.Get(ctx, ctrlclient.ObjectKeyFromObject(ds), current); err != nil {
						return err
					}
					if revoke == "terminated" {
						current.Status.State = breakglassv1alpha1.DebugSessionStateTerminated
					} else if revoke == "provider-replaced" {
						current.Status.Participants[0].IdentityProviderName = "b"
						current.Status.Participants[0].IdentityProviderIssuer = "https://b.example"
					} else {
						now := metav1.Now()
						current.Status.Participants[0].LeftAt = &now
					}
					return hub.Status().Update(ctx, current)
				},
				SubResourceUpdate: func(context.Context, ctrlclient.Client, string, ctrlclient.Object, ...ctrlclient.SubResourceUpdateOption) error {
					mutations++
					return nil
				},
			}).Build()
			h := NewKubectlDebugHandler(hub, &mockClientProvider{clients: map[string]ctrlclient.Client{"spoke": spoke}}).withIdentity(debugSessionReadIdentity{username: "operator", provider: "a", issuer: "https://a.example"}).WithAPIReader(hub)
			require.Error(t, h.InjectEphemeralContainer(ctx, ds, "default", "app", "debugger", "busybox", nil, nil, "operator"))
			require.Zero(t, mutations)
		})
	}
}

func TestDefenderLateInjectionRetainsEvidenceAfterTerminationAndCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ds := &breakglassv1alpha1.DebugSession{ObjectMeta: metav1.ObjectMeta{Name: "session", Namespace: "hub", UID: types.UID("session-uid")}, Spec: breakglassv1alpha1.DebugSessionSpec{Cluster: "spoke", RequestedBy: "owner"}, Status: breakglassv1alpha1.DebugSessionStatus{State: breakglassv1alpha1.DebugSessionStateActive, ExpiresAt: defenderExpiry(), ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{KubectlDebug: &breakglassv1alpha1.KubectlDebugConfig{EphemeralContainers: &breakglassv1alpha1.EphemeralContainersConfig{Enabled: true}}}}}
	hub := fake.NewClientBuilder().WithScheme(Scheme).WithObjects(ds).WithStatusSubresource(ds).Build()
	mutations := 0
	spoke := fake.NewClientBuilder().WithScheme(Scheme).WithObjects(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "default", UID: types.UID("injected-pod-uid")}}).WithInterceptorFuncs(interceptor.Funcs{
		SubResourceUpdate: func(_ context.Context, _ ctrlclient.Client, _ string, _ ctrlclient.Object, _ ...ctrlclient.SubResourceUpdateOption) error {
			mutations++
			current := &breakglassv1alpha1.DebugSession{}
			if err := hub.Get(context.Background(), ctrlclient.ObjectKeyFromObject(ds), current); err != nil {
				return err
			}
			current.Status.State = breakglassv1alpha1.DebugSessionStateTerminated
			if err := hub.Status().Update(context.Background(), current); err != nil {
				return err
			}
			cancel()
			return nil
		},
	}).Build()
	h := NewKubectlDebugHandler(hub, &mockClientProvider{clients: map[string]ctrlclient.Client{"spoke": spoke}}).withIdentity(debugSessionReadIdentity{legacyAllowed: true}).WithAPIReader(hub)
	require.ErrorContains(t, h.InjectEphemeralContainer(ctx, ds, "default", "app", "debugger", "busybox", nil, nil, "owner"), "recorded")
	require.Equal(t, 1, mutations)
	current := &breakglassv1alpha1.DebugSession{}
	require.NoError(t, hub.Get(context.Background(), ctrlclient.ObjectKeyFromObject(ds), current))
	require.Equal(t, breakglassv1alpha1.DebugSessionStateTerminated, current.Status.State)
	require.NotNil(t, current.Status.KubectlDebugStatus)
	require.Len(t, current.Status.KubectlDebugStatus.EphemeralContainersInjected, 1)
	require.Equal(t, "injected-pod-uid", current.Status.KubectlDebugStatus.EphemeralContainersInjected[0].PodUID)
	require.Empty(t, current.Status.AllowedPods)
}

func TestDefenderNodePolicyRejectsAffinityAndAbsentEmptyLabel(t *testing.T) {
	for _, sc := range []*breakglassv1alpha1.SchedulingConstraints{
		{NodeSelector: map[string]string{"required": ""}},
		{RequiredNodeAffinity: &corev1.NodeSelector{NodeSelectorTerms: []corev1.NodeSelectorTerm{{MatchExpressions: []corev1.NodeSelectorRequirement{{Key: "pool", Operator: corev1.NodeSelectorOpIn, Values: []string{"approved"}}}}}}},
	} {
		ds := &breakglassv1alpha1.DebugSession{ObjectMeta: metav1.ObjectMeta{Name: "session", Namespace: "hub", UID: types.UID("session-uid")}, Spec: breakglassv1alpha1.DebugSessionSpec{Cluster: "spoke", RequestedBy: "owner", ResolvedSchedulingConstraints: sc}, Status: breakglassv1alpha1.DebugSessionStatus{State: breakglassv1alpha1.DebugSessionStateActive, ExpiresAt: defenderExpiry(), ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{KubectlDebug: &breakglassv1alpha1.KubectlDebugConfig{NodeDebug: &breakglassv1alpha1.NodeDebugConfig{Enabled: true}}}}}
		hub := fake.NewClientBuilder().WithScheme(Scheme).WithObjects(ds).Build()
		spoke := fake.NewClientBuilder().WithScheme(Scheme).WithObjects(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "breakglass-debug", UID: types.UID("namespace-uid")}}, &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node", UID: types.UID("node-uid"), Labels: map[string]string{"pool": "other"}}}).Build()
		h := NewKubectlDebugHandler(hub, &mockClientProvider{clients: map[string]ctrlclient.Client{"spoke": spoke}}).withIdentity(debugSessionReadIdentity{legacyAllowed: true})
		_, err := h.CreateNodeDebugPod(context.Background(), ds, "node", "owner")
		require.ErrorContains(t, err, "does not match")
		pods := &corev1.PodList{}
		require.NoError(t, spoke.List(context.Background(), pods))
		require.Empty(t, pods.Items)
	}
}

func TestDefenderOrphanCompensationUsesCreatedUID(t *testing.T) {
	for _, replacedBeforeRead := range []bool{true, false} {
		t.Run(fmt.Sprintf("replaced-before-read=%t", replacedBeforeRead), func(t *testing.T) {
			created := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "debug", Namespace: "default", UID: types.UID("created"), Annotations: map[string]string{sourceSessionUIDAnnotation: "session-uid"}}}
			replacement := created.DeepCopy()
			replacement.UID = types.UID("replacement")
			initial := created
			if replacedBeforeRead {
				initial = replacement
			}
			deleteCalls := 0
			spoke := fake.NewClientBuilder().WithScheme(Scheme).WithObjects(initial).WithInterceptorFuncs(interceptor.Funcs{
				Delete: func(ctx context.Context, cl ctrlclient.WithWatch, obj ctrlclient.Object, opts ...ctrlclient.DeleteOption) error {
					deleteCalls++
					options := &ctrlclient.DeleteOptions{}
					for _, opt := range opts {
						opt.ApplyToDelete(options)
					}
					require.NotNil(t, options.Preconditions)
					require.NotNil(t, options.Preconditions.UID)
					require.Equal(t, created.UID, *options.Preconditions.UID)
					// Replace after the helper's read; model the API rejecting the
					// original UID precondition without deleting the replacement.
					require.NoError(t, cl.Delete(ctx, created))
					require.NoError(t, cl.Create(ctx, replacement))
					return apierrors.NewConflict(schema.GroupResource{Resource: "pods"}, obj.GetName(), fmt.Errorf("UID changed"))
				},
			}).Build()
			h := NewKubectlDebugHandler(nil, nil)
			h.deleteOrphanedPod(context.Background(), spoke, created, fmt.Errorf("status rejected"))
			if replacedBeforeRead {
				require.Zero(t, deleteCalls)
			} else {
				require.Equal(t, 1, deleteCalls)
			}
			current := &corev1.Pod{}
			require.NoError(t, spoke.Get(context.Background(), ctrlclient.ObjectKeyFromObject(replacement), current))
			require.Equal(t, replacement.UID, current.UID)
		})
	}
}

func TestDefenderLeaveTargetsActiveRejoinAndPreservesHistory(t *testing.T) {
	oldLeft := metav1.NewTime(time.Now().Add(-time.Hour).Truncate(time.Second))
	ds := &breakglassv1alpha1.DebugSession{ObjectMeta: metav1.ObjectMeta{Name: "session", Namespace: "hub", UID: types.UID("session-uid")}, Spec: breakglassv1alpha1.DebugSessionSpec{RequestedBy: "owner"}, Status: breakglassv1alpha1.DebugSessionStatus{State: breakglassv1alpha1.DebugSessionStateActive, ExpiresAt: defenderExpiry(), Participants: []breakglassv1alpha1.DebugSessionParticipant{
		{User: "member", Role: breakglassv1alpha1.ParticipantRoleParticipant, LeftAt: &oldLeft},
		{User: "member", Role: breakglassv1alpha1.ParticipantRoleParticipant},
	}}}
	hub := fake.NewClientBuilder().WithScheme(Scheme).WithObjects(ds).WithStatusSubresource(ds).Build()
	c := NewDebugSessionAPIController(zap.NewNop().Sugar(), hub, nil, nil).WithAPIReader(hub)
	router := setupAuthenticatedDebugSessionRouter(t, c, "member", "", nil)
	leave := func() *httptest.ResponseRecorder {
		response := httptest.NewRecorder()
		router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/debugSessions/session/leave?namespace=hub", nil))
		return response
	}
	require.Equal(t, http.StatusOK, leave().Code)
	current := &breakglassv1alpha1.DebugSession{}
	require.NoError(t, hub.Get(context.Background(), ctrlclient.ObjectKeyFromObject(ds), current))
	require.True(t, current.Status.Participants[0].LeftAt.Equal(&oldLeft))
	require.NotNil(t, current.Status.Participants[1].LeftAt)
	activeLeft := current.Status.Participants[1].LeftAt.DeepCopy()
	require.Equal(t, http.StatusNotFound, leave().Code)
	require.NoError(t, hub.Get(context.Background(), ctrlclient.ObjectKeyFromObject(ds), current))
	require.True(t, current.Status.Participants[1].LeftAt.Equal(activeLeft))
}

func TestDefenderNodeCreationCompensatesTerminationAfterCreate(t *testing.T) {
	ctx := context.Background()
	ds := &breakglassv1alpha1.DebugSession{ObjectMeta: metav1.ObjectMeta{Name: "session-12345678", Namespace: "hub", UID: types.UID("session-uid")}, Spec: breakglassv1alpha1.DebugSessionSpec{Cluster: "spoke", RequestedBy: "owner", TargetNamespace: "debug"}, Status: breakglassv1alpha1.DebugSessionStatus{State: breakglassv1alpha1.DebugSessionStateActive, ExpiresAt: defenderExpiry(), ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{TargetNamespace: "debug", KubectlDebug: &breakglassv1alpha1.KubectlDebugConfig{NodeDebug: &breakglassv1alpha1.NodeDebugConfig{Enabled: true}}}}}
	hub := fake.NewClientBuilder().WithScheme(Scheme).WithObjects(ds).WithStatusSubresource(ds).Build()
	created := false
	spoke := fake.NewClientBuilder().WithScheme(Scheme).WithObjects(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "debug", UID: types.UID("namespace-uid")}}, &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node", UID: types.UID("node-uid")}}).WithInterceptorFuncs(interceptor.Funcs{
		Get: func(ctx context.Context, cl ctrlclient.WithWatch, key ctrlclient.ObjectKey, obj ctrlclient.Object, opts ...ctrlclient.GetOption) error {
			if err := cl.Get(ctx, key, obj, opts...); err != nil {
				return err
			}
			if ns, ok := obj.(*corev1.Namespace); ok && ns.UID == "" {
				ns.UID = types.UID("namespace-uid")
			}
			return nil
		},
		Create: func(ctx context.Context, cl ctrlclient.WithWatch, obj ctrlclient.Object, opts ...ctrlclient.CreateOption) error {
			obj.SetUID(types.UID("created"))
			if err := cl.Create(ctx, obj, opts...); err != nil {
				return err
			}
			created = true
			current := &breakglassv1alpha1.DebugSession{}
			if err := hub.Get(ctx, ctrlclient.ObjectKeyFromObject(ds), current); err != nil {
				return err
			}
			current.Status.State = breakglassv1alpha1.DebugSessionStateTerminated
			return hub.Status().Update(ctx, current)
		},
	}).Build()
	h := NewKubectlDebugHandler(hub, &mockClientProvider{clients: map[string]ctrlclient.Client{"spoke": spoke}}).withIdentity(debugSessionReadIdentity{legacyAllowed: true}).WithAPIReader(hub)
	pod, err := h.CreateNodeDebugPod(ctx, ds, "node", "owner")
	require.True(t, created, "create did not reach the target API: %v", err)
	require.Error(t, err)
	require.Nil(t, pod)
	pods := &corev1.PodList{}
	require.NoError(t, spoke.List(ctx, pods))
	require.Empty(t, pods.Items)
}

func TestMergedStatusRetryRejectsReboundParticipant(t *testing.T) {
	ctx := context.Background()
	ds := &breakglassv1alpha1.DebugSession{ObjectMeta: metav1.ObjectMeta{Name: "session", Namespace: "hub", UID: types.UID("session-uid")}, Status: breakglassv1alpha1.DebugSessionStatus{State: breakglassv1alpha1.DebugSessionStateActive, ExpiresAt: defenderExpiry(), Participants: []breakglassv1alpha1.DebugSessionParticipant{{User: "operator", IdentityProviderName: "a", IdentityProviderIssuer: "https://a.example", Role: breakglassv1alpha1.ParticipantRoleParticipant}}}}
	base := fake.NewClientBuilder().WithScheme(Scheme).WithObjects(ds).WithStatusSubresource(ds).Build()
	attempts := 0
	cli := interceptor.NewClient(base, interceptor.Funcs{SubResourcePatch: func(ctx context.Context, c ctrlclient.Client, _ string, _ ctrlclient.Object, _ ctrlclient.Patch, _ ...ctrlclient.SubResourcePatchOption) error {
		attempts++
		current := &breakglassv1alpha1.DebugSession{}
		require.NoError(t, c.Get(ctx, ctrlclient.ObjectKeyFromObject(ds), current))
		current.Status.Participants[0].IdentityProviderName = "b"
		current.Status.Participants[0].IdentityProviderIssuer = "https://b.example"
		require.NoError(t, c.Status().Update(ctx, current))
		return apierrors.NewConflict(schema.GroupResource{Group: breakglassv1alpha1.GroupVersion.Group, Resource: "debugsessions"}, ds.Name, fmt.Errorf("concurrent participant change"))
	}})
	h := NewKubectlDebugHandler(cli, nil).WithAPIReader(base).withIdentity(debugSessionReadIdentity{username: "operator", provider: "a", issuer: "https://a.example"})
	require.NoError(t, h.requireActiveSession(ctx, ds, "operator"))
	err := h.patchDebugSessionStatusWithRetryState(ctx, ds, func(status *breakglassv1alpha1.DebugSessionStatus) { status.Message = "must not persist" }, true, "operator")
	require.Error(t, err)
	require.Equal(t, 1, attempts, "retry must reject the rebound identity before another write")
	current := &breakglassv1alpha1.DebugSession{}
	require.NoError(t, base.Get(ctx, ctrlclient.ObjectKeyFromObject(ds), current))
	require.Empty(t, current.Status.Message)
}
