// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/telekom/k8s-breakglass/pkg/quotas"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestAuthorizeArtifactReadRejectsUnrelatedAuthenticatedUser(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))
	expires := metav1.NewTime(time.Now().Add(time.Hour))
	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "session", Namespace: "breakglass", UID: "session-uid"},
		Spec:       breakglassv1alpha1.DebugSessionSpec{RequestedBy: "alice", IdentityProviderName: "idp", IdentityProviderIssuer: "https://issuer.example"},
		Status:     breakglassv1alpha1.DebugSessionStatus{State: breakglassv1alpha1.DebugSessionStateActive, ExpiresAt: &expires},
	}
	client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(session).Build()
	controller := NewDebugSessionAPIController(nil, client, nil, nil).WithAPIReader(client)

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	record := httptest.NewRecorder()
	ginContext, _ := gin.CreateTestContext(record)
	ginContext.Request = request
	ginContext.Set("username", "mallory")
	ginContext.Set("identity_provider_name", "idp")
	ginContext.Set("issuer", "https://issuer.example")
	_, err := controller.AuthorizeArtifactRead(ginContext, "breakglass", "session")
	require.Error(t, err)

	ginContext.Set("username", "alice")
	binding, err := controller.AuthorizeArtifactRead(ginContext, "breakglass", "session")
	require.NoError(t, err)
	require.Equal(t, "session-uid", string(binding.UID))
}

func TestAuthorizeArtifactReadRejectsInactiveAccessFences(t *testing.T) {
	for _, scenario := range []string{"idle", "provisional", "deleting"} {
		t.Run(scenario, func(t *testing.T) {
			scheme := runtime.NewScheme()
			require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))
			expiry, start := metav1.NewTime(time.Now().Add(time.Hour)), metav1.NewTime(time.Now().Add(-time.Hour))
			session := &breakglassv1alpha1.DebugSession{ObjectMeta: metav1.ObjectMeta{Name: "session", Namespace: "hub", UID: "uid"}, Spec: breakglassv1alpha1.DebugSessionSpec{RequestedBy: "alice", IdentityProviderName: "idp", IdentityProviderIssuer: "https://issuer.example"}, Status: breakglassv1alpha1.DebugSessionStatus{State: breakglassv1alpha1.DebugSessionStateActive, ExpiresAt: &expiry, StartsAt: &start}}
			switch scenario {
			case "idle":
				session.Status.ResolvedTemplate = &breakglassv1alpha1.DebugSessionTemplateSpec{Constraints: &breakglassv1alpha1.DebugSessionConstraints{IdleTimeout: "1m"}}
			case "provisional":
				session.Annotations = map[string]string{quotas.AdmissionAnnotation: quotas.Pending}
			case "deleting":
				session.DeletionTimestamp = &start
				session.Finalizers = []string{"test"}
			}
			live := fake.NewClientBuilder().WithScheme(scheme).WithObjects(session).Build()
			controller := NewDebugSessionAPIController(nil, live, nil, nil).WithAPIReader(live)
			ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
			ctx.Request = httptest.NewRequest(http.MethodGet, "/", nil)
			ctx.Set("username", "alice")
			ctx.Set("identity_provider_name", "idp")
			ctx.Set("issuer", "https://issuer.example")
			_, err := controller.AuthorizeArtifactRead(ctx, "hub", "session")
			require.Error(t, err)
		})
	}
}
