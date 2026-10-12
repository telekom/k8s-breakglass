// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

// An admission-denied Create never persists the object. Cleanup must not
// report it as a residual (CleanupFailed), and the deploy error must keep the
// admission denial visible.
func TestRejectedCreateIntentIsNotReportedAsCleanupResidual(t *testing.T) {
	const denial = `admission webhook "vpol.validate.kyverno.svc-fail-finegrained-disallow-host-namespaces" denied the request: host namespaces are disallowed`
	maxPods := int32(1)
	for _, tc := range []struct {
		name      string
		configure func(*breakglassv1alpha1.DebugSessionTemplate)
		reject    func(client.Object) bool
		priorErr  error
		createErr error
		resolved  bool
	}{
		{
			name:      "workload admission denial",
			reject:    func(obj client.Object) bool { return obj.GetName() == "debug-fenced" },
			createErr: apierrors.NewForbidden(schema.GroupResource{Group: "apps", Resource: "deployments"}, "debug-fenced", errors.New(denial)),
			resolved:  true,
		},
		{
			name:      "workload invalid",
			reject:    func(obj client.Object) bool { return obj.GetName() == "debug-fenced" },
			createErr: apierrors.NewBadRequest(denial),
			resolved:  true,
		},
		{
			name: "resource quota admission denial",
			configure: func(tpl *breakglassv1alpha1.DebugSessionTemplate) {
				tpl.Spec.ResourceQuota = &breakglassv1alpha1.DebugResourceQuotaConfig{MaxPods: &maxPods}
			},
			reject:    func(obj client.Object) bool { _, ok := obj.(*corev1.ResourceQuota); return ok },
			createErr: apierrors.NewForbidden(schema.GroupResource{Resource: "resourcequotas"}, "quota", errors.New(denial)),
			resolved:  true,
		},
		{
			name: "pod disruption budget admission denial",
			configure: func(tpl *breakglassv1alpha1.DebugSessionTemplate) {
				tpl.Spec.PodDisruptionBudget = &breakglassv1alpha1.DebugPDBConfig{Enabled: true, MinAvailable: &maxPods}
			},
			reject: func(obj client.Object) bool {
				return obj.GetObjectKind().GroupVersionKind().Kind == "PodDisruptionBudget"
			},
			createErr: apierrors.NewForbidden(schema.GroupResource{Group: "policy", Resource: "poddisruptionbudgets"}, "pdb", errors.New(denial)),
			resolved:  true,
		},
		{
			name: "pod template document admission denial",
			configure: func(tpl *breakglassv1alpha1.DebugSessionTemplate) {
				tpl.Spec.PodTemplateString = "containers:\n  - name: debug\n    image: busybox\n---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: denied\n"
			},
			reject:    func(obj client.Object) bool { return obj.GetName() == "denied" },
			createErr: apierrors.NewForbidden(schema.GroupResource{Resource: "configmaps"}, "denied", errors.New(denial)),
			resolved:  true,
		},
		{
			name:      "rejection after an ambiguous attempt stays unresolved",
			reject:    func(obj client.Object) bool { return obj.GetName() == "debug-fenced" },
			priorErr:  apierrors.NewTimeoutError("lost outcome", 1),
			createErr: apierrors.NewForbidden(schema.GroupResource{Group: "apps", Resource: "deployments"}, "debug-fenced", errors.New(denial)),
		},
		{
			name:      "ambiguous timeout stays unresolved",
			reject:    func(obj client.Object) bool { return obj.GetName() == "debug-fenced" },
			createErr: apierrors.NewTimeoutError(denial, 1),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			c, ds, template, target := newDeploymentFenceFixture(t)
			if tc.configure != nil {
				tc.configure(template)
			}
			createErr := tc.createErr
			if tc.priorErr != nil {
				createErr = tc.priorErr
			}
			denying := interceptor.NewClient(target.(client.WithWatch), interceptor.Funcs{Create: func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
				if tc.reject(obj) {
					return createErr
				}
				return cl.Create(ctx, obj, opts...)
			}})
			c.targetClientFactory = func(_ *rest.Config) (client.Client, error) { return denying, nil }

			if tc.priorErr != nil {
				require.Error(t, c.deployDebugResources(ctx, ds, template))
				createErr = tc.createErr
			}
			err := c.deployDebugResources(ctx, ds, template)
			require.ErrorContains(t, err, denial)

			live := &breakglassv1alpha1.DebugSession{}
			require.NoError(t, c.client.Get(ctx, client.ObjectKeyFromObject(ds), live))
			unresolved := false
			for _, ref := range live.Status.DeployedResources {
				unresolved = unresolved || (ref.UID == "" && ref.CreateOperationID != "")
			}
			for _, status := range live.Status.PodTemplateResourceStatuses {
				unresolved = unresolved || (status.UID == "" && status.CreateOperationID != "")
			}
			require.Equal(t, !tc.resolved, unresolved, "deployed=%+v podTemplate=%+v", live.Status.DeployedResources, live.Status.PodTemplateResourceStatuses)

			live.Status.State = breakglassv1alpha1.DebugSessionStateFailed
			cleanupErr := c.cleanupResources(ctx, live)
			if !tc.resolved {
				require.Error(t, cleanupErr)
				require.True(t, cleanupConditionFailed(live))
				return
			}
			require.NoError(t, cleanupErr)
			require.False(t, cleanupConditionFailed(live), "conditions=%+v", live.Status.Conditions)
			require.Empty(t, cleanupResidualIdentities(live))
		})
	}
}
