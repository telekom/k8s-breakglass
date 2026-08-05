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
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// approverSetShape describes one way an operator can express "no approvers".
type approverSetShape struct {
	name      string
	approvers *breakglassv1alpha1.DebugSessionApprovers
}

// unconfiguredApproverShapes enumerates every representation of an empty approver
// set. All of them must authorize nobody; before the fix each of them authorized
// the entire authenticated population on the approve path.
func unconfiguredApproverShapes() []approverSetShape {
	return []approverSetShape{
		{name: "nil approvers", approvers: nil},
		{name: "empty struct", approvers: &breakglassv1alpha1.DebugSessionApprovers{}},
		{
			name: "explicitly empty slices",
			approvers: &breakglassv1alpha1.DebugSessionApprovers{
				Users:  []string{},
				Groups: []string{},
			},
		},
	}
}

// TestApproveAuthorization_EmptyApproverSetAuthorizesNobody pins BUG 2 across every
// source of the effective approver set: binding, template fetched from the API, and
// the resolved template cached in status.
func TestApproveAuthorization_EmptyApproverSetAuthorizesNobody(t *testing.T) {
	for _, shape := range unconfiguredApproverShapes() {
		t.Run(shape.name+"/from template", func(t *testing.T) {
			template := &breakglassv1alpha1.DebugSessionTemplate{
				ObjectMeta: metav1.ObjectMeta{Name: "tmpl"},
				Spec:       breakglassv1alpha1.DebugSessionTemplateSpec{Approvers: shape.approvers},
			}
			ctrl := newApproverTestController(t, template)

			session := &breakglassv1alpha1.DebugSession{
				ObjectMeta: metav1.ObjectMeta{Name: "s"},
				Spec: breakglassv1alpha1.DebugSessionSpec{
					TemplateRef: "tmpl",
					RequestedBy: "alice@example.com",
				},
			}

			got := ctrl.isUserAuthorizedToApprove(context.Background(), session, "mallory@example.com", []string{"any-group"})
			assert.False(t, got, "an unconfigured approver set must not authorize an arbitrary user")
		})

		t.Run(shape.name+"/from resolved template in status", func(t *testing.T) {
			ctrl := newApproverTestController(t)

			session := &breakglassv1alpha1.DebugSession{
				ObjectMeta: metav1.ObjectMeta{Name: "s"},
				Spec: breakglassv1alpha1.DebugSessionSpec{
					TemplateRef: "tmpl",
					RequestedBy: "alice@example.com",
				},
				Status: breakglassv1alpha1.DebugSessionStatus{
					ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{Approvers: shape.approvers},
				},
			}

			// A nil approver set in status makes the authorizer fall back to fetching
			// the template, which does not exist here, so that path fails closed and
			// is covered by the template subtest above.
			if shape.approvers == nil {
				t.Skip("nil status approvers intentionally falls through to the template lookup")
			}

			got := ctrl.isUserAuthorizedToApprove(context.Background(), session, "mallory@example.com", []string{"any-group"})
			assert.False(t, got, "an unconfigured approver set must not authorize an arbitrary user")
		})
	}
}

// TestApproveAuthorization_PopulatedApproverSetStillWorks is the counterweight: the
// fix must deny only the empty case and leave real approver configuration intact.
func TestApproveAuthorization_PopulatedApproverSetStillWorks(t *testing.T) {
	template := &breakglassv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: "tmpl"},
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			Approvers: &breakglassv1alpha1.DebugSessionApprovers{
				Users:  []string{"approver@example.com"},
				Groups: []string{"debug-approvers"},
			},
		},
	}
	ctrl := newApproverTestController(t, template)

	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "s"},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			TemplateRef: "tmpl",
			RequestedBy: "alice@example.com",
		},
	}
	ctx := context.Background()

	assert.True(t, ctrl.isUserAuthorizedToApprove(ctx, session, "approver@example.com", nil),
		"a named approver must still be authorized")
	assert.True(t, ctrl.isUserAuthorizedToApprove(ctx, session, "someone@example.com", []string{"debug-approvers"}),
		"a member of an approver group must still be authorized")
	assert.False(t, ctrl.isUserAuthorizedToApprove(ctx, session, "mallory@example.com", []string{"other"}),
		"an unrelated user must remain unauthorized")
	assert.False(t, ctrl.isUserAuthorizedToApprove(ctx, session, "alice@example.com", []string{"debug-approvers"}),
		"self-approval must remain blocked even for a configured approver")
}

// TestApproveAuthorization_BindingApproversTakePrecedence covers the binding branch,
// where an empty binding approver set must not fall back to allow-all either.
func TestApproveAuthorization_BindingApproversTakePrecedence(t *testing.T) {
	binding := &breakglassv1alpha1.DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "bind", Namespace: "breakglass-system"},
		Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
			TemplateRef: &breakglassv1alpha1.TemplateReference{Name: "tmpl"},
			Approvers:   &breakglassv1alpha1.DebugSessionApprovers{},
		},
	}
	template := &breakglassv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: "tmpl"},
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			Approvers: &breakglassv1alpha1.DebugSessionApprovers{
				Users: []string{"template-approver@example.com"},
			},
		},
	}
	ctrl := newApproverTestController(t, binding, template)

	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "s"},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			TemplateRef: "tmpl",
			RequestedBy: "alice@example.com",
			BindingRef: &breakglassv1alpha1.BindingReference{
				Name:      "bind",
				Namespace: "breakglass-system",
			},
		},
	}

	// The binding replaces the template approvers, and an empty binding approver set
	// authorizes nobody -- it must not silently widen to "any authenticated user",
	// nor fall through to the template's approver list.
	assert.False(t, ctrl.isUserAuthorizedToApprove(context.Background(), session, "mallory@example.com", nil),
		"empty binding approvers must not authorize an arbitrary user")
}

// TestApproveAndReadAuthorization_AgreeOnEmptyApprovers is the symmetry assertion.
//
// The read authorizer has always required a configured approver set
// (isExplicitDebugSessionApprover guards on debugSessionApproversConfigured), while
// the approve path treated the same set as allow-all. That asymmetry was the
// decisive evidence that the empty-set branch was a defect and not a feature: the
// two paths disagreed about the same data. They must now agree.
func TestApproveAndReadAuthorization_AgreeOnEmptyApprovers(t *testing.T) {
	template := &breakglassv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: "tmpl"},
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			Approvers: &breakglassv1alpha1.DebugSessionApprovers{},
		},
	}
	ctrl := newApproverTestController(t, template)

	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "s"},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			TemplateRef: "tmpl",
			RequestedBy: "alice@example.com",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{
				Approvers: &breakglassv1alpha1.DebugSessionApprovers{},
			},
		},
	}

	identity := debugSessionReadIdentity{username: "mallory@example.com"}
	ctx := context.Background()

	canRead, err := ctrl.canReadDebugSession(ctx, session, identity)
	require.NoError(t, err)
	canApprove := ctrl.isIdentityAuthorizedToApprove(ctx, session, identity)

	assert.False(t, canRead, "read path already denied this; asserted here to pin the pairing")
	assert.False(t, canApprove, "approve path must reach the same verdict as the read path")
	assert.Equal(t, canRead, canApprove,
		"read and approve must agree on whether an empty approver set confers approver status")
}

// TestRequiresApproval_EmptyApproversMeansNoLockout documents why tightening the
// approve path cannot lock anybody out, which is the backwards-compatibility crux
// of BUG 2.
//
// requiresApproval() already uses debugSessionApproversConfigured, so a session
// whose effective approver set is empty is auto-approved and never enters
// PendingApproval. Both the approve and reject endpoints reject any session that is
// not PendingApproval. Therefore no session that used to be approvable becomes
// unapprovable: the allow-all branch was only ever reachable for sessions that did
// not need approval in the first place.
func TestRequiresApproval_EmptyApproversMeansNoLockout(t *testing.T) {
	controller := &DebugSessionController{log: zaptest.NewLogger(t).Sugar()}

	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "s"},
		Spec:       breakglassv1alpha1.DebugSessionSpec{Cluster: "c", TemplateRef: "tmpl"},
	}

	for _, shape := range unconfiguredApproverShapes() {
		t.Run("template/"+shape.name, func(t *testing.T) {
			template := &breakglassv1alpha1.DebugSessionTemplate{
				ObjectMeta: metav1.ObjectMeta{Name: "tmpl"},
				Spec:       breakglassv1alpha1.DebugSessionTemplateSpec{Approvers: shape.approvers},
			}
			assert.False(t, controller.requiresApproval(template, nil, session),
				"an empty approver set means the session is auto-approved, so it never awaits an approver")
		})
	}
}

// newApproverTestController builds an API controller backed by a fake client
// preloaded with the given templates/bindings.
func newApproverTestController(t *testing.T, objs ...ctrlclient.Object) *DebugSessionAPIController {
	t.Helper()
	fakeClient := fake.NewClientBuilder().
		WithScheme(Scheme).
		WithObjects(objs...).
		Build()
	return NewDebugSessionAPIController(zaptest.NewLogger(t).Sugar(), fakeClient, nil, nil)
}
