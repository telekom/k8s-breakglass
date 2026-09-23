// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0
package debug

import (
	"context"
	"errors"
	kptr "k8s.io/utils/ptr"
	"testing"

	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"go.uber.org/zap"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func TestAuxiliaryRejectedCreateRetiresOnlyFreshIntent(t *testing.T) {
	for _, tc := range []struct {
		name                   string
		prior, child, conflict bool
		rejection              error
		retired                bool
	}{
		{name: "fresh bad request", rejection: apierrors.NewBadRequest("invalid data"), retired: true},
		{name: "fresh forbidden", rejection: apierrors.NewForbidden(schema.GroupResource{Resource: "configmaps"}, "bad", errors.New("denied")), retired: true},
		{name: "connection reset remains unresolved", rejection: errors.New("connection reset by peer")},
		{name: "timeout remains unresolved", rejection: apierrors.NewTimeoutError("lost outcome", 1)},
		{name: "prior ambiguous intent remains unresolved", prior: true, rejection: apierrors.NewBadRequest("invalid data")},
		{name: "earlier document UID survives", child: true, rejection: apierrors.NewBadRequest("invalid data"), retired: true},
		{name: "retirement conflict preserves persisted intent", conflict: true, rejection: apierrors.NewBadRequest("invalid data")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			scheme := testScheme()
			session := &breakglassv1alpha1.DebugSession{ObjectMeta: metav1.ObjectMeta{Name: "rejection", Namespace: "default", UID: "session-uid"}}
			hub := fake.NewClientBuilder().WithScheme(scheme).WithObjects(session).WithStatusSubresource(session).Build()
			controller := &DebugSessionController{client: hub, log: zap.NewNop().Sugar()}
			createErr := tc.rejection
			target := fake.NewClientBuilder().WithScheme(runtime.NewScheme()).WithInterceptorFuncs(interceptor.Funcs{Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
				if obj.GetName() == "bad" {
					return createErr
				}
				obj.SetUID("first-document-uid")
				return c.Create(ctx, obj, opts...)
			}}).Build()
			doc := "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: bad\n"
			if tc.child {
				doc = "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: good\n---\n" + doc
			}
			template := &breakglassv1alpha1.DebugSessionTemplateSpec{RequiredAuxiliaryResourceCategories: []string{"required"}, AuxiliaryResources: []breakglassv1alpha1.AuxiliaryResource{{Name: "fixture", Category: "required", CreateBefore: kptr.To(true), DeleteAfter: kptr.To(true), FailurePolicy: breakglassv1alpha1.AuxiliaryResourceFailurePolicyFail, TemplateString: doc}}}
			manager := newTestAuxiliaryResourceManager()
			persist := func(status breakglassv1alpha1.AuxiliaryResourceStatus) error {
				if tc.conflict && status.CreateOperationID == "" {
					return &debugSessionStatusConflict{err: apierrors.NewConflict(schema.GroupResource{Resource: "debugsessions"}, session.Name, nil)}
				}
				return controller.persistAuxiliaryStatus(ctx, session, status)
			}
			deploy := func() error {
				_, err := manager.DeployAuxiliaryResourcesForPhaseWithFenceAndPersist(ctx, session, template, nil, target, "target", true, nil, persist)
				return err
			}
			if tc.prior {
				createErr = errors.New("connection reset by peer")
				require.Error(t, deploy())
				createErr = tc.rejection
			}
			err := deploy()
			require.Error(t, err)
			live := &breakglassv1alpha1.DebugSession{}
			require.NoError(t, hub.Get(ctx, client.ObjectKeyFromObject(session), live))
			require.Len(t, live.Status.AuxiliaryResourceStatuses, 1)
			status := live.Status.AuxiliaryResourceStatuses[0]
			if tc.retired {
				if tc.child {
					require.Equal(t, "first-document-uid", status.UID)
					require.Empty(t, status.AdditionalResources)
				} else {
					require.False(t, status.Created)
					require.False(t, status.Deleted)
					require.Empty(t, status.CreateOperationID)
				}
				live.Status.ResolvedTemplate = template
				require.NoError(t, manager.CleanupAuxiliaryResources(ctx, live, target))
			} else {
				require.NotEmpty(t, status.CreateOperationID)
				require.Empty(t, status.UID)
				if tc.conflict {
					require.True(t, isDebugSessionStatusConflict(err))
				}
			}
		})
	}
}
