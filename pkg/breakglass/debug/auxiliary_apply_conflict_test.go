// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func TestAuxiliaryApplyConflictRequeuesWithFreshFences(t *testing.T) {
	for _, policy := range []breakglassv1alpha1.AuxiliaryResourceFailurePolicy{
		breakglassv1alpha1.AuxiliaryResourceFailurePolicyFail,
		breakglassv1alpha1.AuxiliaryResourceFailurePolicyWarn,
		breakglassv1alpha1.AuxiliaryResourceFailurePolicyIgnore,
	} {
		for _, change := range []string{"same", "replacement", "foreign session", "foreign operation", "terminal"} {
			t.Run(string(policy)+"/"+change, func(t *testing.T) {
				ctx := context.Background()
				session := &breakglassv1alpha1.DebugSession{ObjectMeta: metav1.ObjectMeta{Name: "aux-conflict", Namespace: "default", UID: "session-uid"}}
				session.Status.State = breakglassv1alpha1.DebugSessionStatePendingApproval
				template := &breakglassv1alpha1.DebugSessionTemplateSpec{
					RequiredAuxiliaryResourceCategories: []string{"required"},
					AuxiliaryResources: []breakglassv1alpha1.AuxiliaryResource{{
						Name: "egress", Category: "required", FailurePolicy: policy,
						TemplateString: "apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n  name: debug-egress\nspec:\n  podSelector: {}\n  policyTypes: [Egress]\n",
					}},
				}
				applies := 0
				target := fake.NewClientBuilder().WithScheme(testScheme()).WithInterceptorFuncs(interceptor.Funcs{
					Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
						if obj.GetUID() == "" {
							obj.SetUID("original-uid")
						}
						return c.Create(ctx, obj, opts...)
					},
					Apply: func(ctx context.Context, c client.WithWatch, cfg runtime.ApplyConfiguration, _ ...client.ApplyOption) error {
						applies++
						if applies == 1 {
							return apierrors.NewConflict(schema.GroupResource{Group: "networking.k8s.io", Resource: "networkpolicies"}, "debug-egress", errors.New("concurrent write"))
						}
						payload, err := json.Marshal(cfg)
						require.NoError(t, err)
						obj := &unstructured.Unstructured{}
						require.NoError(t, json.Unmarshal(payload, &obj.Object))
						live := obj.DeepCopy()
						require.NoError(t, c.Get(ctx, client.ObjectKeyFromObject(obj), live))
						require.Equal(t, live.GetUID(), obj.GetUID())
						require.Equal(t, live.GetResourceVersion(), obj.GetResourceVersion())
						return c.Update(ctx, obj)
					},
				}).Build()
				manager := newTestAuxiliaryResourceManager()
				fences := 0
				fence := func() error {
					fences++
					if session.Status.State == breakglassv1alpha1.DebugSessionStateTerminated {
						return errors.New("session is terminal")
					}
					return nil
				}
				persist := func(status breakglassv1alpha1.AuxiliaryResourceStatus) error {
					session.Status.AuxiliaryResourceStatuses = mergeAuxiliaryStatuses(session.Status.AuxiliaryResourceStatuses, []breakglassv1alpha1.AuxiliaryResourceStatus{status})
					return nil
				}
				deploy := func() error {
					_, err := manager.DeployAuxiliaryResourcesForPhaseWithFenceAndPersist(ctx, session, template, nil, target, "target", true, fence, persist)
					return err
				}
				require.NoError(t, deploy())
				original := *session.Status.AuxiliaryResourceStatuses[0].DeepCopy()
				live := &unstructured.Unstructured{}
				live.SetAPIVersion("networking.k8s.io/v1")
				live.SetKind("NetworkPolicy")
				key := client.ObjectKey{Namespace: "target", Name: "debug-egress"}
				require.NoError(t, target.Get(ctx, key, live))
				require.NoError(t, unstructured.SetNestedSlice(live.Object, []interface{}{"Ingress"}, "spec", "policyTypes"))
				require.NoError(t, target.Update(ctx, live))
				err := deploy()
				require.True(t, apierrors.IsConflict(err), "%v", err)
				require.True(t, isDebugSessionDeploymentConflict(err), "%v", err)
				require.False(t, isDebugSessionStatusConflict(err))
				require.Equal(t, original.UID, session.Status.AuxiliaryResourceStatuses[0].UID)
				require.Equal(t, original.CreateOperationID, session.Status.AuxiliaryResourceStatuses[0].CreateOperationID)
				require.Equal(t, breakglassv1alpha1.DebugSessionStatePendingApproval, session.Status.State)
				require.NoError(t, target.Get(ctx, key, live))
				switch change {
				case "replacement":
					require.NoError(t, target.Delete(ctx, live))
					live.SetUID("replacement-uid")
					live.SetResourceVersion("")
					require.NoError(t, target.Create(ctx, live))
				case "foreign session", "foreign operation":
					annotations := live.GetAnnotations()
					field := sourceSessionUIDAnnotation
					if change == "foreign operation" {
						field = createOperationIDAnnotation
					}
					annotations[field] = "foreign"
					live.SetAnnotations(annotations)
					require.NoError(t, target.Update(ctx, live))
				case "terminal":
					session.Status.State = breakglassv1alpha1.DebugSessionStateTerminated
				}
				previousFences := fences
				err = deploy()
				require.Greater(t, fences, previousFences)
				if change == "same" {
					require.NoError(t, err)
					require.Equal(t, 2, applies)
				} else {
					if policy == breakglassv1alpha1.AuxiliaryResourceFailurePolicyFail || change == "terminal" {
						require.Error(t, err)
					} else {
						require.NoError(t, err, "existing optional failure policy remains unchanged")
					}
					require.False(t, isDebugSessionDeploymentConflict(err))
					require.Equal(t, 1, applies, "changed identity or terminal session must not reach SSA")
				}
			})
		}
	}
}

func TestDeploymentConflictDoesNotRetryUnclassifiedErrors(t *testing.T) {
	conflict := apierrors.NewConflict(schema.GroupResource{Resource: "pods"}, "unclassified", nil)
	require.False(t, isDebugSessionDeploymentConflict(conflict))
	require.True(t, isDebugSessionDeploymentConflict(&debugSessionStatusConflict{err: conflict}))
	require.False(t, isDebugSessionDeploymentConflict(apierrors.NewForbidden(schema.GroupResource{Resource: "networkpolicies"}, "denied", nil)))
}
