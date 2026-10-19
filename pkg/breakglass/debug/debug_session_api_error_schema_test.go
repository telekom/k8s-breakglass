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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// TestDebugSessionAPIErrorSchema asserts that every debug-session endpoint
// returns the standard error body (error, code, cid) on failure.
func TestDebugSessionAPIErrorSchema(t *testing.T) {
	fakeClient := fake.NewClientBuilder().
		WithScheme(testScheme()).
		WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).
		Build()
	ctrl := NewDebugSessionAPIController(zap.NewNop().Sugar(), fakeClient, nil, nil)
	router := debugSessionAPITestRouter(t, ctrl, "alice@example.com", "alice@example.com", nil)
	unauthenticated := debugSessionAPITestRouter(t, ctrl, "", "", nil)

	tests := []struct {
		name   string
		router http.Handler
		method string
		path   string
		body   string
		status int
		code   string
	}{
		{"get missing", router, http.MethodGet, "/missing", "", http.StatusNotFound, "NOT_FOUND"},
		{"join missing", router, http.MethodPost, "/missing/join", "", http.StatusNotFound, "NOT_FOUND"},
		{"leave missing", router, http.MethodPost, "/missing/leave", "", http.StatusNotFound, "NOT_FOUND"},
		{"renew missing", router, http.MethodPost, "/missing/renew", `{"extendBy":"1h"}`, http.StatusNotFound, "NOT_FOUND"},
		{"terminate missing", router, http.MethodPost, "/missing/terminate", "", http.StatusNotFound, "NOT_FOUND"},
		{"approve missing", router, http.MethodPost, "/missing/approve", "{}", http.StatusNotFound, "NOT_FOUND"},
		{"reject missing", router, http.MethodPost, "/missing/reject", `{"reason":"no"}`, http.StatusNotFound, "NOT_FOUND"},
		{"join strict body", router, http.MethodPost, "/missing/join", `{"role":"viewer","x":1}`, http.StatusBadRequest, "BAD_REQUEST"},
		{"renew strict body", router, http.MethodPost, "/missing/renew", `{"extendBy":"1h","x":1}`, http.StatusBadRequest, "BAD_REQUEST"},
		{"create invalid body", router, http.MethodPost, "", `{`, http.StatusBadRequest, "BAD_REQUEST"},
		{"join unauthenticated", unauthenticated, http.MethodPost, "/missing/join", "", http.StatusUnauthorized, "UNAUTHORIZED"},
		{"renew unauthenticated", unauthenticated, http.MethodPost, "/missing/renew", `{"extendBy":"1h"}`, http.StatusUnauthorized, "UNAUTHORIZED"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/api/v1/debugSessions"+tt.path, strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			tt.router.ServeHTTP(w, req)

			require.Equal(t, tt.status, w.Code, w.Body.String())
			var body map[string]any
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
			assert.NotEmpty(t, body["error"])
			assert.Equal(t, tt.code, body["code"])
			assert.NotEmpty(t, body["cid"])
			assert.NotContains(t, body, "errors", "validation lists go in details")
		})
	}
}

// TestRenewResponseCarriesRenewedConnectionLease pins that renew returns the
// session after the connection-lease expiry follow-up patch, so clients see
// one consistent expiry.
func TestRenewResponseCarriesRenewedConnectionLease(t *testing.T) {
	now := metav1.NewTime(time.Now().UTC().Truncate(time.Second))
	expiresAt := metav1.NewTime(now.Add(time.Hour))
	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "lease-session", Namespace: "default", UID: "session-uid"},
		Spec:       breakglassv1alpha1.DebugSessionSpec{Cluster: "production", TemplateRef: "standard-debug", RequestedBy: "alice@example.com"},
		Status: breakglassv1alpha1.DebugSessionStatus{
			State:            breakglassv1alpha1.DebugSessionStateActive,
			StartsAt:         &now,
			ExpiresAt:        &expiresAt,
			ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{},
		},
	}
	client := newLeaseClient(fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(session).WithStatusSubresource(&breakglassv1alpha1.DebugSession{}))
	leases := NewConnectionLeaseService(client)
	lease, err := leases.AcquireForSession(context.Background(), session, "cluster-uid")
	require.NoError(t, err)
	require.NoError(t, client.Get(context.Background(), ctrlclient.ObjectKeyFromObject(session), session))
	session.Status.ConnectionLease = &lease
	require.NoError(t, client.Status().Update(context.Background(), session))

	ctrl := NewDebugSessionAPIController(zap.NewNop().Sugar(), client, nil, nil)
	ctrl.connectionLeases = leases
	router := debugSessionAPITestRouter(t, ctrl, "alice@example.com", "alice@example.com", nil)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/debugSessions/lease-session/renew", strings.NewReader(`{"extendBy":"30m"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	renewed := requireUpdatedDebugSessionBody(t, w, "lease-session")
	require.NotNil(t, renewed.Status.ExpiresAt)
	assert.True(t, renewed.Status.ExpiresAt.After(expiresAt.Time))
	require.NotNil(t, renewed.Status.ConnectionLease)
	assert.True(t, renewed.Status.ConnectionLease.ExpiresAt.Equal(renewed.Status.ExpiresAt), "lease expiry %v must match session expiry %v", renewed.Status.ConnectionLease.ExpiresAt, renewed.Status.ExpiresAt)
}
