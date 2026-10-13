/*
Copyright 2026.

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

package debug

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"go.uber.org/zap/zaptest"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const (
	selfApprovalCluster  = "prd-cluster"
	selfApprovalNS       = "breakglass"
	selfApprovalTemplate = "ops-debug"
	selfApprovalBinding  = "ops-binding"
	selfApprovalUser     = "ops@example.com"
)

func selfApprovalSession(templateBlock *bool, withBinding bool) *breakglassv1alpha1.DebugSession {
	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "self-approval", Namespace: selfApprovalNS},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			TemplateRef:      selfApprovalTemplate,
			Cluster:          selfApprovalCluster,
			RequestedBy:      selfApprovalUser,
			RequestedByEmail: selfApprovalUser,
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			State: breakglassv1alpha1.DebugSessionStatePendingApproval,
			ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{
				BlockSelfApproval: templateBlock,
				Approvers:         &breakglassv1alpha1.DebugSessionApprovers{Groups: []string{"ops"}},
			},
		},
	}
	if withBinding {
		session.Spec.BindingRef = &breakglassv1alpha1.BindingReference{Name: selfApprovalBinding, Namespace: selfApprovalNS}
	}
	return session
}

func selfApprovalBindingObj(block *bool, approvers *breakglassv1alpha1.DebugSessionApprovers) *breakglassv1alpha1.DebugSessionClusterBinding {
	return &breakglassv1alpha1.DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{Name: selfApprovalBinding, Namespace: selfApprovalNS},
		Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
			TemplateRef:       &breakglassv1alpha1.TemplateReference{Name: selfApprovalTemplate},
			Clusters:          []string{selfApprovalCluster},
			Approvers:         approvers,
			BlockSelfApproval: block,
		},
	}
}

func selfApprovalController(t *testing.T, objs ...ctrlclient.Object) *DebugSessionAPIController {
	t.Helper()
	c := fake.NewClientBuilder().WithScheme(Scheme).WithObjects(objs...).Build()
	return NewDebugSessionAPIController(zaptest.NewLogger(t).Sugar(), c, nil, nil)
}

var (
	selfApprovalRequester = debugSessionReadIdentity{username: selfApprovalUser, email: selfApprovalUser, groups: []string{"ops"}, legacyAllowed: true}
	selfApprovalPeer      = debugSessionReadIdentity{username: "peer@example.com", email: "peer@example.com", groups: []string{"ops"}, legacyAllowed: true}
)

func TestDebugSessionBlockSelfApprovalResolution(t *testing.T) {
	for _, tc := range []struct {
		name          string
		templateBlock *bool
		binding       *breakglassv1alpha1.DebugSessionClusterBinding
		clusterBlock  *bool
		wantSelf      bool
	}{
		{name: "inherit defaults to blocked", wantSelf: false},
		{name: "inherit with ClusterConfig false stays blocked", clusterBlock: ptr.To(false), wantSelf: false},
		{name: "inherit with prd ClusterConfig true is blocked", clusterBlock: ptr.To(true), wantSelf: false},
		{name: "template override true", templateBlock: ptr.To(true), wantSelf: false},
		{name: "template override false", templateBlock: ptr.To(false), wantSelf: true},
		{name: "template override false wins over prd ClusterConfig true", templateBlock: ptr.To(false), clusterBlock: ptr.To(true), wantSelf: true},
		{
			name:     "binding override false without approvers uses template approvers",
			binding:  selfApprovalBindingObj(ptr.To(false), nil),
			wantSelf: true,
		},
		{
			name:          "binding override true beats template false",
			templateBlock: ptr.To(false),
			binding:       selfApprovalBindingObj(ptr.To(true), &breakglassv1alpha1.DebugSessionApprovers{Groups: []string{"ops"}}),
			wantSelf:      false,
		},
		{
			name:         "binding override false beats prd ClusterConfig true",
			clusterBlock: ptr.To(true),
			binding:      selfApprovalBindingObj(ptr.To(false), &breakglassv1alpha1.DebugSessionApprovers{Groups: []string{"ops"}}),
			wantSelf:     true,
		},
		{
			name:          "binding nil inherits template false",
			templateBlock: ptr.To(false),
			binding:       selfApprovalBindingObj(nil, &breakglassv1alpha1.DebugSessionApprovers{Groups: []string{"ops"}}),
			wantSelf:      true,
		},
		{
			name:     "binding nil and template nil stays blocked",
			binding:  selfApprovalBindingObj(nil, &breakglassv1alpha1.DebugSessionApprovers{Groups: []string{"ops"}}),
			wantSelf: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var objs []ctrlclient.Object
			if tc.clusterBlock != nil {
				objs = append(objs, &breakglassv1alpha1.ClusterConfig{
					ObjectMeta: metav1.ObjectMeta{Name: selfApprovalCluster, Namespace: selfApprovalNS},
					Spec:       breakglassv1alpha1.ClusterConfigSpec{BlockSelfApproval: *tc.clusterBlock},
				})
			}
			if tc.binding != nil {
				objs = append(objs, tc.binding)
			}
			ctrl := selfApprovalController(t, objs...)
			session := selfApprovalSession(tc.templateBlock, tc.binding != nil)

			assert.Equal(t, tc.wantSelf, ctrl.isIdentityAuthorizedToApprove(context.Background(), session, selfApprovalRequester))
			assert.Equal(t, tc.wantSelf, ctrl.canActOnDebugSessionApproval(context.Background(), session, selfApprovalRequester, nil))
			assert.True(t, ctrl.isIdentityAuthorizedToApprove(context.Background(), session, selfApprovalPeer),
				"independent approvers are unaffected by blockSelfApproval")
		})
	}
}

func TestDebugSessionSelfApprovalStillRequiresApproverMembership(t *testing.T) {
	ctrl := selfApprovalController(t)
	session := selfApprovalSession(ptr.To(false), false)
	outsider := selfApprovalRequester
	outsider.groups = []string{"tenant"}
	assert.False(t, ctrl.isIdentityAuthorizedToApprove(context.Background(), session, outsider))
}

func TestDebugSessionSelfApprovalUsesTemplateSnapshot(t *testing.T) {
	live := &breakglassv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: selfApprovalTemplate},
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			BlockSelfApproval: ptr.To(false),
			Approvers:         &breakglassv1alpha1.DebugSessionApprovers{Groups: []string{"ops"}},
		},
	}
	ctrl := selfApprovalController(t, live)
	session := selfApprovalSession(nil, false)
	assert.False(t, ctrl.isIdentityAuthorizedToApprove(context.Background(), session, selfApprovalRequester),
		"relaxing the live template must not relax sessions created from a blocking snapshot")

	session.Status.ResolvedTemplate = nil
	assert.True(t, ctrl.isIdentityAuthorizedToApprove(context.Background(), session, selfApprovalRequester),
		"sessions without a snapshot fall back to the live template")
}

func TestDebugSessionNodeMaintenanceAlwaysBlocksSelfApproval(t *testing.T) {
	ctrl := selfApprovalController(t)
	session := selfApprovalSession(ptr.To(false), false)
	session.Spec.NodeMaintenance = &breakglassv1alpha1.NodeMaintenanceTarget{TargetNode: "node-a"}
	require.False(t, ctrl.isIdentityAuthorizedToApprove(context.Background(), session, selfApprovalRequester))
}

func TestResolveDebugSessionBlockSelfApproval(t *testing.T) {
	binding := func(v *bool) *breakglassv1alpha1.DebugSessionClusterBinding {
		return &breakglassv1alpha1.DebugSessionClusterBinding{Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{BlockSelfApproval: v}}
	}
	assert.True(t, resolveDebugSessionBlockSelfApproval(nil, nil))
	assert.True(t, resolveDebugSessionBlockSelfApproval(nil, binding(nil)))
	assert.False(t, resolveDebugSessionBlockSelfApproval(ptr.To(false), nil))
	assert.False(t, resolveDebugSessionBlockSelfApproval(ptr.To(false), binding(nil)))
	assert.True(t, resolveDebugSessionBlockSelfApproval(ptr.To(false), binding(ptr.To(true))))
	assert.False(t, resolveDebugSessionBlockSelfApproval(ptr.To(true), binding(ptr.To(false))))
}
