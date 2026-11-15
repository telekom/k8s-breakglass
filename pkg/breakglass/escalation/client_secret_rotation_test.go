// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package escalation

import (
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	cfgpkg "github.com/telekom/k8s-breakglass/pkg/config"
)

// rotatingKeycloak is a Keycloak fixture that accepts exactly one client
// secret, like an IdP after the old secret is revoked.
type rotatingKeycloak struct {
	mu       sync.Mutex
	accepted string
	used     []string
}

func (k *rotatingKeycloak) accept(secret string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.accepted = secret
}

func (k *rotatingKeycloak) lastUsed() string {
	k.mu.Lock()
	defer k.mu.Unlock()
	if len(k.used) == 0 {
		return ""
	}
	return k.used[len(k.used)-1]
}

func newRotatingKeycloak(t *testing.T, accepted string) (*rotatingKeycloak, string, string) {
	t.Helper()
	kc := &rotatingKeycloak{accepted: accepted}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/realms/test-realm/protocol/openid-connect/token":
			// gocloak sends client credentials with HTTP basic auth.
			_, secret, _ := r.BasicAuth()
			kc.mu.Lock()
			kc.used = append(kc.used, secret)
			ok := secret == kc.accepted
			kc.mu.Unlock()
			if !ok {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":"unauthorized_client"}`))
				return
			}
			_, _ = w.Write([]byte(`{"access_token":"token","expires_in":300,"token_type":"Bearer"}`))
		case "/admin/realms/test-realm/groups":
			_, _ = w.Write([]byte(`[{"id":"approver-group-id","name":"approvers"}]`))
		case "/admin/realms/test-realm/groups/approver-group-id":
			_, _ = w.Write([]byte(`{"id":"approver-group-id","name":"approvers","subGroups":[]}`))
		case "/admin/realms/test-realm/groups/approver-group-id/members":
			_, _ = w.Write([]byte(`[{"email":"approver@example.com"}]`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	return kc, server.URL, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}))
}

func rotateGroupSyncSecret(t *testing.T, cli client.Client, value string) {
	t.Helper()
	secret := &corev1.Secret{}
	require.NoError(t, cli.Get(context.Background(), client.ObjectKey{Namespace: "default", Name: "group-sync-secret"}, secret))
	secret.Data["clientSecret"] = []byte(value)
	require.NoError(t, cli.Update(context.Background(), secret))
}

func approverCondition(t *testing.T, cli client.Client, escalation *breakglassv1alpha1.BreakglassEscalation) string {
	t.Helper()
	updated := &breakglassv1alpha1.BreakglassEscalation{}
	require.NoError(t, cli.Get(context.Background(), client.ObjectKeyFromObject(escalation), updated))
	condition := updated.GetCondition(string(breakglassv1alpha1.BreakglassEscalationConditionApprovalGroupMembersResolved))
	require.NotNil(t, condition)
	return condition.Reason
}

// TestEscalationStatusUpdaterUsesRotatedClientSecret proves that the next
// group sync run reads a rotated Keycloak client secret without a restart,
// and shows the failure window when the IdP revokes the old secret before the
// Secret is updated.
func TestEscalationStatusUpdaterUsesRotatedClientSecret(t *testing.T) {
	kc, serverURL, ca := newRotatingKeycloak(t, "fixture-secret")
	cli, escalation := newMultiIDPStatusTestClient(t, serverURL, ca, breakglassv1alpha1.BreakglassEscalationStatus{})
	log := zap.NewNop().Sugar()
	updater := EscalationStatusUpdater{Log: log, K8sClient: cli, IDPLoader: cfgpkg.NewIdentityProviderLoader(cli), EventRecorder: fakeEventRecorder{Events: make(chan string, 50)}}
	ctx := context.Background()

	updater.runOnce(ctx, log)
	require.Equal(t, "GroupMembersResolved", approverCondition(t, cli, escalation))

	// IdP switched to the new secret first: the old one no longer works.
	kc.accept("rotated-secret")
	updater.runOnce(ctx, log)
	require.Equal(t, "GroupSyncFailed", approverCondition(t, cli, escalation))
	require.Equal(t, "fixture-secret", kc.lastUsed())

	rotateGroupSyncSecret(t, cli, "rotated-secret")
	updater.runOnce(ctx, log)
	require.Equal(t, "GroupMembersResolved", approverCondition(t, cli, escalation))
	require.Equal(t, "rotated-secret", kc.lastUsed())
}

// TestReloadedResolverUsesRotatedClientSecret proves that the resolver the
// IdentityProvider reconciler publishes on its next reconcile (onReload loads
// the IdentityProvider and calls SetResolver) uses the rotated secret.
func TestReloadedResolverUsesRotatedClientSecret(t *testing.T) {
	kc, serverURL, ca := newRotatingKeycloak(t, "fixture-secret")
	cli, _ := newMultiIDPStatusTestClient(t, serverURL, ca, breakglassv1alpha1.BreakglassEscalationStatus{})
	log := zap.NewNop().Sugar()
	ctx := context.Background()
	loader := cfgpkg.NewIdentityProviderLoader(cli)
	em := &EscalationManager{Client: cli}
	reload := func() {
		idp, err := loader.LoadIdentityProviderByName(ctx, "idp-a")
		require.NoError(t, err)
		em.SetResolver(SetupResolver(idp, log))
	}
	reload()
	members, err := em.GetResolver().Members(ctx, "approvers")
	require.NoError(t, err)
	require.Equal(t, []string{"approver@example.com"}, members)

	kc.accept("rotated-secret")
	rotateGroupSyncSecret(t, cli, "rotated-secret")
	reload()
	members, err = em.GetResolver().Members(ctx, "approvers")
	require.NoError(t, err)
	require.Equal(t, []string{"approver@example.com"}, members)
	require.Equal(t, "rotated-secret", kc.lastUsed())
}
