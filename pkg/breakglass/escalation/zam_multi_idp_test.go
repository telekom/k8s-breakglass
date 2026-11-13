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

package escalation

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	cfgpkg "github.com/telekom/k8s-breakglass/pkg/config"
)

type idpFixture struct {
	name string
	mode keycloakFixtureMode // empty: the IdentityProvider is not created and fails to load
}

// newTwoIDPStatusClient creates IdentityProviders backed by Keycloak fixtures
// and an escalation that resolves the "approvers" group from all of them.
func newTwoIDPStatusClient(t *testing.T, idps []idpFixture, status breakglassv1alpha1.BreakglassEscalationStatus) (client.Client, *breakglassv1alpha1.BreakglassEscalation) {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))

	objects := []client.Object{&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "group-sync-secret", Namespace: "default"},
		Data:       map[string][]byte{"clientSecret": []byte("fixture-secret")},
	}}
	names := make([]string, 0, len(idps))
	for _, fixture := range idps {
		names = append(names, fixture.name)
		if fixture.mode == "" {
			continue
		}
		serverURL, certificateAuthority := newKeycloakFixture(t, fixture.mode)
		objects = append(objects, &breakglassv1alpha1.IdentityProvider{
			ObjectMeta: metav1.ObjectMeta{Name: fixture.name},
			Spec: breakglassv1alpha1.IdentityProviderSpec{
				OIDC:              breakglassv1alpha1.OIDCConfig{Authority: serverURL, ClientID: "breakglass-ui", ExpectedAudience: "breakglass-ui"},
				GroupSyncProvider: breakglassv1alpha1.GroupSyncProviderKeycloak,
				Keycloak: &breakglassv1alpha1.KeycloakGroupSync{
					BaseURL: serverURL, Realm: "test-realm", ClientID: "group-sync", CertificateAuthority: certificateAuthority,
					ClientSecretRef: breakglassv1alpha1.SecretKeyReference{Name: "group-sync-secret", Namespace: "default", Key: "clientSecret"},
				},
			},
		})
	}
	escalation := &breakglassv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{Name: "two-idp-status", Namespace: "default"},
		Spec: breakglassv1alpha1.BreakglassEscalationSpec{
			EscalatedGroup:                       "admin-group",
			Allowed:                              breakglassv1alpha1.BreakglassEscalationAllowed{Clusters: []string{"fixture-cluster"}},
			Approvers:                            breakglassv1alpha1.BreakglassEscalationApprovers{Groups: []string{"approvers"}},
			AllowedIdentityProvidersForRequests:  names,
			AllowedIdentityProvidersForApprovers: names,
		},
		Status: status,
	}
	objects = append(objects, escalation)
	return fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&breakglassv1alpha1.BreakglassEscalation{}, &breakglassv1alpha1.IdentityProvider{}).
		WithObjects(objects...).
		Build(), escalation
}

// staleTwoIDPStatus is a cached status from an earlier, unambiguous sync.
func staleTwoIDPStatus() breakglassv1alpha1.BreakglassEscalationStatus {
	return breakglassv1alpha1.BreakglassEscalationStatus{
		ApproverGroupMembers: map[string][]string{"approvers": {"stale@example.com"}},
		IDPGroupMemberships: map[string]map[string][]string{
			"idp-a": {"approvers": {"stale@example.com"}},
			"idp-b": {"approvers": {"stale@example.com"}},
		},
	}
}

func TestMultiIDPAmbiguousApproverGroup(t *testing.T) {
	tests := []struct {
		name string
		idps []idpFixture
		// wantPresent false means no aggregate entry (token-group fallback).
		wantPresent bool
		wantMembers []string
		wantPerIDP  map[string][]string
	}{
		{
			// Guards: no cache retention for ambiguous lookups (idp-a keeps
			// no stale members) and idp-b's result stays authoritative.
			name:        "ambiguous in one provider, resolved in the other",
			idps:        []idpFixture{{"idp-a", keycloakFixtureAmbiguous}, {"idp-b", keycloakFixtureSuccess}},
			wantPresent: true,
			wantMembers: []string{"approver@example.com"},
			wantPerIDP:  map[string][]string{"idp-b": {"approver@example.com"}},
		},
		{
			// Guard: the aggregate entry is dropped only when every provider
			// is ambiguous.
			name: "ambiguous in both providers",
			idps: []idpFixture{{"idp-a", keycloakFixtureAmbiguous}, {"idp-b", keycloakFixtureAmbiguous}},
		},
		{
			// Guard: a provider that fails to load is not counted as
			// ambiguous, so the group keeps an empty, authoritative entry.
			name:        "ambiguous in one provider, the other fails to load",
			idps:        []idpFixture{{"idp-a", keycloakFixtureAmbiguous}, {"idp-missing", ""}},
			wantPresent: true,
			wantMembers: []string{},
		},
		{
			name:        "ambiguous in one provider, empty in the other",
			idps:        []idpFixture{{"idp-a", keycloakFixtureAmbiguous}, {"idp-b", keycloakFixtureEmpty}},
			wantPresent: true,
			wantMembers: []string{},
			wantPerIDP:  map[string][]string{"idp-b": {}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cli, escalation := newTwoIDPStatusClient(t, tt.idps, staleTwoIDPStatus())
			log := zap.NewNop().Sugar()
			updater := EscalationStatusUpdater{
				Log:           log,
				K8sClient:     cli,
				IDPLoader:     cfgpkg.NewIdentityProviderLoader(cli),
				EventRecorder: fakeEventRecorder{Events: make(chan string, 20)},
			}

			updater.runOnce(context.Background(), log)

			updated := &breakglassv1alpha1.BreakglassEscalation{}
			require.NoError(t, cli.Get(context.Background(), client.ObjectKeyFromObject(escalation), updated))
			members, present := updated.Status.ApproverGroupMembers["approvers"]
			require.Equal(t, tt.wantPresent, present, "aggregate entry presence: %v", updated.Status.ApproverGroupMembers)
			if tt.wantPresent {
				assert.ElementsMatch(t, tt.wantMembers, members)
			}
			for idp, groups := range updated.Status.IDPGroupMemberships {
				for group, groupMembers := range groups {
					assert.NotContains(t, groupMembers, "stale@example.com", "%s/%s kept a stale member", idp, group)
				}
			}
			for idp, want := range tt.wantPerIDP {
				assert.ElementsMatch(t, want, updated.Status.IDPGroupMemberships[idp]["approvers"], idp)
			}
			_, ambiguousKept := updated.Status.IDPGroupMemberships["idp-a"]["approvers"]
			assert.False(t, ambiguousKept, "the ambiguous provider must not keep an entry")
		})
	}
}

// When IdP discovery finds no enabled IdP, the updater falls back to legacy
// mode, which never refreshes per-IdP memberships. They must be dropped so a
// member removed upstream cannot keep approving.
func TestLegacyFallbackDropsStaleProviderMemberships(t *testing.T) {
	cli, escalation := newTwoIDPStatusClient(t, nil, staleTwoIDPStatus())
	log := zap.NewNop().Sugar()
	updater := EscalationStatusUpdater{
		Log:           log,
		K8sClient:     cli,
		IDPLoader:     cfgpkg.NewIdentityProviderLoader(cli),
		EventRecorder: fakeEventRecorder{Events: make(chan string, 20)},
		Resolver:      &MockResolver{members: map[string][]string{"approvers": {"current@example.com"}}},
	}
	updated := escalation.DeepCopy()
	updated.Spec.AllowedIdentityProvidersForRequests = nil
	updated.Spec.AllowedIdentityProvidersForApprovers = nil
	require.NoError(t, cli.Update(context.Background(), updated))

	updater.runOnce(context.Background(), log)

	require.NoError(t, cli.Get(context.Background(), client.ObjectKeyFromObject(escalation), updated))
	assert.Equal(t, []string{"current@example.com"}, updated.Status.ApproverGroupMembers["approvers"])
	assert.Empty(t, updated.Status.IDPGroupMemberships, "legacy mode must drop per-IdP snapshots it does not refresh")
}
