// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TestDebugSessionWithoutBindingRefUsesTheBindingThatAllowsTheRequester
// covers a template with a first-line and an onboarding binding for the same
// cluster. Each binding has its own display name, because the webhook rejects
// two bindings with the same effective name. A request without bindingRef
// from an onboarding requester uses the onboarding binding, although the
// first-line binding sorts first.
func TestDebugSessionWithoutBindingRefUsesTheBindingThatAllowsTheRequester(t *testing.T) {
	s := helpers.SetupTest(t, helpers.WithLongTimeout())
	user := helpers.TestUsers.SecurityRequester
	peer := helpers.TestUsers.SecurityApprover
	api := NewDebugSessionAPIClient(s.TC.OIDCProvider().GetTokenForUser(t, s.Ctx, user))

	template := &breakglassv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: helpers.GenerateUniqueName("binding-selection")},
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			DisplayName: "binding selection", Mode: breakglassv1alpha1.DebugSessionModeWorkload,
			TargetNamespace: "breakglass-debug",
			PodTemplateString: `apiVersion: v1
kind: Pod
spec:
  containers:
  - name: debug
    image: busybox:1.37
    command: ["sleep", "600"]
    securityContext:
      runAsNonRoot: true
      runAsUser: 65532
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
      seccompProfile:
        type: RuntimeDefault
`,
		},
	}
	require.NoError(t, s.CreateResource(template))
	binding := func(prefix, group string) *breakglassv1alpha1.DebugSessionClusterBinding {
		b := &breakglassv1alpha1.DebugSessionClusterBinding{
			ObjectMeta: metav1.ObjectMeta{Name: helpers.GenerateUniqueName(prefix), Namespace: s.Namespace},
			Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
				DisplayName: prefix,
				TemplateRef: &breakglassv1alpha1.TemplateReference{Name: template.Name},
				Clusters:    []string{s.Cluster},
				Allowed:     &breakglassv1alpha1.DebugSessionAllowed{Groups: []string{group}},
				Approvers:   &breakglassv1alpha1.DebugSessionApprovers{Users: []string{peer.Email}},
			},
		}
		require.NoError(t, s.CreateResource(b))
		return b
	}
	firstLine := binding("a-first-line", helpers.GenerateUniqueName("first-line-only"))
	onboarding := binding("b-onboarding", "security-test-requester")
	require.Less(t, firstLine.Name, onboarding.Name, "the first-line binding must sort first")

	var session *breakglassv1alpha1.DebugSession
	var lastStatus int
	var lastErr error
	assert.Eventually(t, func() bool {
		created, status, err := api.CreateDebugSession(s.Ctx, t, DebugSessionCreateRequest{
			TemplateRef: template.Name, Cluster: s.Cluster, RequestedDuration: "5m", Reason: "binding selection",
		})
		lastStatus, lastErr = status, err
		if err != nil || status != http.StatusCreated {
			return false
		}
		session = created
		return true
	}, helpers.WaitForStateTimeout, 2*time.Second, "the onboarding requester must be admitted through the onboarding binding")
	require.NotNil(t, session, "last status %d, error %v", lastStatus, lastErr)
	s.Cleanup.Add(session)
	require.NotNil(t, session.Spec.BindingRef)
	require.Equal(t, onboarding.Name, session.Spec.BindingRef.Name)
	require.Equal(t, onboarding.Namespace, session.Spec.BindingRef.Namespace)
}
