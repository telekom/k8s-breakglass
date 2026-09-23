// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"context"
	kptr "k8s.io/utils/ptr"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func TestActivationRetriesAuxiliaryStatusConflict(t *testing.T) {
	for _, phase := range []string{"intent", "outcome", "warn-intent", "warn-outcome"} {
		t.Run(phase, func(t *testing.T) {
			ctx := context.Background()
			c, ds, template, target := newDeploymentFenceFixture(t)
			c.connectionLeases = nil
			ds.Status.State = breakglassv1alpha1.DebugSessionStatePendingApproval
			require.NoError(t, c.client.Status().Update(ctx, ds))
			template.Spec.RequiredAuxiliaryResourceCategories = []string{"security"}
			template.Spec.AuxiliaryResources = []breakglassv1alpha1.AuxiliaryResource{{
				Name: "security", Category: "security", CreateBefore: kptr.To(true), DeleteAfter: kptr.To(true),
				TemplateString: "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: security-precondition\n",
			}}
			if strings.HasPrefix(phase, "warn-") {
				template.Spec.AuxiliaryResources[0].FailurePolicy = breakglassv1alpha1.AuxiliaryResourceFailurePolicyWarn
			}
			require.NoError(t, c.client.Update(ctx, template))
			// Another replica writes unrelated activity between activation's status write
			// and persistence of the pre-apply auxiliary intent.
			injected := false
			advance := func() {
				injected = true
				current := &breakglassv1alpha1.DebugSession{}
				require.NoError(t, c.client.Get(ctx, client.ObjectKeyFromObject(ds), current))
				current.Status.ActivityCount++
				require.NoError(t, c.client.Status().Update(ctx, current))
			}
			if strings.HasSuffix(phase, "intent") {
				c.beforeDebugTargetWrite = func(string) {
					if !injected {
						advance()
					}
				}
			} else {
				c.client = interceptor.NewClient(c.client.(client.WithWatch), interceptor.Funcs{SubResourcePatch: func(ctx context.Context, cl client.Client, sub string, obj client.Object, p client.Patch, opts ...client.SubResourcePatchOption) error {
					candidate, ok := obj.(*breakglassv1alpha1.DebugSession)
					if ok && sub == "status" && !injected && len(candidate.Status.AuxiliaryResourceStatuses) > 0 && candidate.Status.AuxiliaryResourceStatuses[0].UID != "" {
						advance()
						return apierrors.NewConflict(schema.GroupResource{Group: breakglassv1alpha1.GroupVersion.Group, Resource: "debugsessions"}, ds.Name, nil)
					}
					return cl.SubResource(sub).Patch(ctx, obj, p, opts...)
				}})
			}

			_, err := c.activateSession(ctx, ds, template, nil)
			require.True(t, apierrors.IsConflict(err), "expected retriable status conflict, got %v", err)
			require.True(t, injected)
			current := &breakglassv1alpha1.DebugSession{}
			require.NoError(t, c.client.Get(ctx, client.ObjectKeyFromObject(ds), current))
			require.Equal(t, breakglassv1alpha1.DebugSessionStatePendingApproval, current.Status.State)
			require.EqualValues(t, 1, current.Status.ActivityCount)
			var workloads appsv1.DeploymentList
			require.NoError(t, target.List(ctx, &workloads))
			require.Empty(t, workloads.Items, "no workload may precede persisted auxiliary intent")
			// Controller-runtime retries from the freshly read object, preserving the
			// other writer's status and the original bounded activation expiry.
			expiry := current.Status.ExpiresAt.DeepCopy()
			c.beforeDebugTargetWrite = nil
			_, err = c.activateSession(ctx, current, template, nil)
			require.NoError(t, err)
			require.NoError(t, c.client.Get(ctx, client.ObjectKeyFromObject(ds), current))
			require.Equal(t, breakglassv1alpha1.DebugSessionStateActive, current.Status.State)
			require.EqualValues(t, 1, current.Status.ActivityCount)
			require.Equal(t, expiry, current.Status.ExpiresAt)
			require.Len(t, current.Status.AuxiliaryResourceStatuses, 1)
			require.NotEmpty(t, current.Status.AuxiliaryResourceStatuses[0].UID)
			require.Len(t, current.Status.DeployedResources, 1, "retry must reconcile the existing workload inventory entry")
			var prerequisite corev1.ConfigMap
			require.NoError(t, target.Get(ctx, client.ObjectKey{Namespace: "breakglass-debug", Name: "security-precondition"}, &prerequisite))
			require.NoError(t, target.List(ctx, &workloads))
			require.Len(t, workloads.Items, 1)
		})
	}
}

func TestActivationRetryPreservesOtherAuxiliaryCleanupEvidence(t *testing.T) {
	ctx := context.Background()
	c, ds, template, target := newDeploymentFenceFixture(t)
	c.connectionLeases = nil
	ds.Status.State = breakglassv1alpha1.DebugSessionStatePendingApproval
	template.Spec.RequiredAuxiliaryResourceCategories = []string{"security"}
	for _, name := range []string{"first", "second"} {
		template.Spec.AuxiliaryResources = append(template.Spec.AuxiliaryResources, breakglassv1alpha1.AuxiliaryResource{
			Name: name, Category: "security", CreateBefore: kptr.To(true), DeleteAfter: kptr.To(true),
			TemplateString: "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: " + name + "\n",
		})
	}
	ds.Status.ResolvedTemplate = template.Spec.DeepCopy()
	require.NoError(t, c.client.Status().Update(ctx, ds))
	injected := false
	c.client = interceptor.NewClient(c.client.(client.WithWatch), interceptor.Funcs{SubResourcePatch: func(ctx context.Context, cl client.Client, sub string, obj client.Object, p client.Patch, opts ...client.SubResourcePatchOption) error {
		candidate, ok := obj.(*breakglassv1alpha1.DebugSession)
		if ok && sub == "status" && !injected && len(candidate.Status.DeployedResources) > 0 {
			injected = true
			return apierrors.NewConflict(schema.GroupResource{Group: breakglassv1alpha1.GroupVersion.Group, Resource: "debugsessions"}, ds.Name, nil)
		}
		return cl.SubResource(sub).Patch(ctx, obj, p, opts...)
	}})
	_, err := c.activateSession(ctx, ds, template, nil)
	require.True(t, apierrors.IsConflict(err), "expected status conflict, got %v", err)
	current := &breakglassv1alpha1.DebugSession{}
	require.NoError(t, c.client.Get(ctx, client.ObjectKeyFromObject(ds), current))
	require.Len(t, current.Status.AuxiliaryResourceStatuses, 2)
	for _, status := range current.Status.AuxiliaryResourceStatuses {
		require.NotEmpty(t, status.UID)
	}
	// On retry an earlier prerequisite fails. Both previously created objects
	// must remain discoverable and safely deletable through the persisted status.
	// A direct deployment retry uses the same inventory but fails before the
	// second prerequisite is visited. The approved snapshot itself is unchanged.
	template.Spec.AuxiliaryResources[0].TemplateString = "invalid: ["
	err = c.deployDebugResources(ctx, current, template)
	require.Error(t, err)
	require.Len(t, current.Status.AuxiliaryResourceStatuses, 2)
	require.NoError(t, c.auxiliaryMgr.CleanupAuxiliaryResources(ctx, current, target))
	for _, name := range []string{"first", "second"} {
		require.True(t, apierrors.IsNotFound(target.Get(ctx, client.ObjectKey{Namespace: "breakglass-debug", Name: name}, &corev1.ConfigMap{})))
	}
}

func TestAuxiliaryRetryPreservesUnvisitedChildDocuments(t *testing.T) {
	ctx := context.Background()
	c, ds, _, _ := newDeploymentFenceFixture(t)
	ds.Status.AuxiliaryResourceStatuses = []breakglassv1alpha1.AuxiliaryResourceStatus{{
		Name: "documents", ResourceName: "primary", Kind: "ConfigMap", APIVersion: "v1", Namespace: "breakglass-debug", UID: "primary-uid", CreateOperationID: "primary-op",
		AdditionalResources: []breakglassv1alpha1.AdditionalResourceRef{{
			ResourceName: "child", Kind: "ConfigMap", APIVersion: "v1", Namespace: "breakglass-debug", UID: "child-uid", CreateOperationID: "child-op",
		}},
	}}
	require.NoError(t, c.client.Status().Update(ctx, ds))
	primary := ds.Status.AuxiliaryResourceStatuses[0]
	primary.UID = ""
	primary.AdditionalResources = nil
	require.NoError(t, c.persistAuxiliaryStatus(ctx, ds, primary))
	current := &breakglassv1alpha1.DebugSession{}
	require.NoError(t, c.client.Get(ctx, client.ObjectKeyFromObject(ds), current))
	require.Len(t, current.Status.AuxiliaryResourceStatuses, 1)
	require.Equal(t, "primary-uid", current.Status.AuxiliaryResourceStatuses[0].UID)
	require.Len(t, current.Status.AuxiliaryResourceStatuses[0].AdditionalResources, 1)
	require.Equal(t, "child-uid", current.Status.AuxiliaryResourceStatuses[0].AdditionalResources[0].UID)
	// Replaying the child intent also retains its observed UID without duplication.
	replay := current.Status.AuxiliaryResourceStatuses[0]
	replay.AdditionalResources[0].UID = ""
	require.NoError(t, c.persistAuxiliaryStatus(ctx, ds, replay))
	require.Len(t, ds.Status.AuxiliaryResourceStatuses[0].AdditionalResources, 1)
	require.Equal(t, "child-uid", ds.Status.AuxiliaryResourceStatuses[0].AdditionalResources[0].UID)
}
