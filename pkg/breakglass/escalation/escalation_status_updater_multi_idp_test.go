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
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
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
	breakglass "github.com/telekom/k8s-breakglass/pkg/breakglass"
	cfgpkg "github.com/telekom/k8s-breakglass/pkg/config"
)

type keycloakFixtureMode string

const (
	keycloakFixtureSuccess   keycloakFixtureMode = "success"
	keycloakFixtureEmpty     keycloakFixtureMode = "empty"
	keycloakFixtureMissing   keycloakFixtureMode = "missing"
	keycloakFixtureMalformed keycloakFixtureMode = "malformed"
	keycloakFixtureDetail404 keycloakFixtureMode = "detail-404"
	keycloakFixtureTransient keycloakFixtureMode = "transient"
)

func newKeycloakFixture(t *testing.T, mode keycloakFixtureMode) (string, string) {
	t.Helper()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		writeJSON := func(body string) {
			if _, err := w.Write([]byte(body)); err != nil {
				t.Errorf("write fixture response: %v", err)
			}
		}

		switch r.URL.Path {
		case "/realms/test-realm/protocol/openid-connect/token":
			writeJSON(`{"access_token":"fixture-token","expires_in":300,"token_type":"Bearer"}`)
		case "/admin/realms/test-realm/groups":
			if mode == keycloakFixtureMissing {
				writeJSON(`[]`)
				return
			}
			if mode == keycloakFixtureMalformed {
				writeJSON(`[{"name":"approvers"}]`)
				return
			}
			writeJSON(`[{"id":"approver-group-id","name":"approvers"}]`)
		case "/admin/realms/test-realm/groups/approver-group-id/members":
			if mode == keycloakFixtureTransient {
				http.Error(w, "temporary failure", http.StatusInternalServerError)
				return
			}
			if mode == keycloakFixtureEmpty {
				writeJSON(`[]`)
				return
			}
			writeJSON(`[{"email":"approver@example.com"}]`)
		case "/admin/realms/test-realm/groups/approver-group-id":
			if mode == keycloakFixtureDetail404 {
				http.Error(w, "group deleted", http.StatusNotFound)
				return
			}
			writeJSON(`{"id":"approver-group-id","name":"approvers","subGroups":[]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	certificateAuthority := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: server.Certificate().Raw,
	})
	return server.URL, string(certificateAuthority)
}

func newMultiIDPStatusTestClient(
	t *testing.T,
	serverURL, certificateAuthority string,
	status breakglassv1alpha1.BreakglassEscalationStatus,
) (client.Client, *breakglassv1alpha1.BreakglassEscalation) {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))

	idp := &breakglassv1alpha1.IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "idp-a"},
		Spec: breakglassv1alpha1.IdentityProviderSpec{
			OIDC: breakglassv1alpha1.OIDCConfig{
				Authority:        serverURL,
				ClientID:         "breakglass-ui",
				ExpectedAudience: "breakglass-ui",
			},
			GroupSyncProvider: breakglassv1alpha1.GroupSyncProviderKeycloak,
			Keycloak: &breakglassv1alpha1.KeycloakGroupSync{
				BaseURL:              serverURL,
				Realm:                "test-realm",
				ClientID:             "group-sync",
				CertificateAuthority: certificateAuthority,
				ClientSecretRef: breakglassv1alpha1.SecretKeyReference{
					Name:      "group-sync-secret",
					Namespace: "default",
					Key:       "clientSecret",
				},
			},
		},
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "group-sync-secret", Namespace: "default"},
		Data:       map[string][]byte{"clientSecret": []byte("fixture-secret")},
	}
	escalation := &breakglassv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{Name: "multi-idp-status", Namespace: "default"},
		Spec: breakglassv1alpha1.BreakglassEscalationSpec{
			EscalatedGroup: "admin-group",
			Allowed: breakglassv1alpha1.BreakglassEscalationAllowed{
				Clusters: []string{"fixture-cluster"},
			},
			Approvers: breakglassv1alpha1.BreakglassEscalationApprovers{
				Groups: []string{"approvers"},
			},
		},
		Status: status,
	}

	return fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&breakglassv1alpha1.BreakglassEscalation{}, &breakglassv1alpha1.IdentityProvider{}).
		WithObjects(idp, secret, escalation).
		Build(), escalation
}

func TestEscalationStatusUpdaterMultiIDPClassifiesGroupResults(t *testing.T) {
	tests := []struct {
		name          string
		mode          keycloakFixtureMode
		initialStatus breakglassv1alpha1.BreakglassEscalationStatus
		wantMembers   []string
		wantStatus    metav1.ConditionStatus
		wantReason    string
	}{
		{
			name:        "members resolved",
			mode:        keycloakFixtureSuccess,
			wantMembers: []string{"approver@example.com"},
			wantStatus:  metav1.ConditionTrue,
			wantReason:  "GroupMembersResolved",
		},
		{
			name:        "existing group is empty",
			mode:        keycloakFixtureEmpty,
			wantMembers: []string{},
			wantStatus:  metav1.ConditionTrue,
			wantReason:  "GroupMembersEmpty",
		},
		{
			name:        "group is missing",
			mode:        keycloakFixtureMissing,
			wantMembers: []string{},
			wantStatus:  metav1.ConditionFalse,
			wantReason:  "GroupNotFound",
		},
		{
			name: "transient lookup failure retains stale members",
			mode: keycloakFixtureTransient,
			initialStatus: breakglassv1alpha1.BreakglassEscalationStatus{
				ApproverGroupMembers: map[string][]string{
					"approvers": {"stale@example.com"},
				},
				IDPGroupMemberships: map[string]map[string][]string{
					"idp-a": {
						"approvers": {"stale@example.com"},
					},
				},
			},
			wantMembers: []string{"stale@example.com"},
			wantStatus:  metav1.ConditionFalse,
			wantReason:  "GroupSyncFailed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			serverURL, certificateAuthority := newKeycloakFixture(t, tt.mode)
			cli, escalation := newMultiIDPStatusTestClient(t, serverURL, certificateAuthority, tt.initialStatus)
			log := zap.NewNop().Sugar()
			recorder := fakeEventRecorder{Events: make(chan string, 10)}
			updater := EscalationStatusUpdater{
				Log:           log,
				K8sClient:     cli,
				IDPLoader:     cfgpkg.NewIdentityProviderLoader(cli),
				EventRecorder: recorder,
			}

			updater.runOnce(context.Background(), log)

			updated := &breakglassv1alpha1.BreakglassEscalation{}
			require.NoError(t, cli.Get(context.Background(), client.ObjectKeyFromObject(escalation), updated))
			members, hasGroup := updated.Status.ApproverGroupMembers["approvers"]
			require.True(t, hasGroup)
			if len(tt.wantMembers) == 0 {
				assert.Empty(t, members)
			} else {
				assert.Equal(t, tt.wantMembers, members)
			}

			condition := updated.GetCondition(string(breakglassv1alpha1.BreakglassEscalationConditionApprovalGroupMembersResolved))
			require.NotNil(t, condition)
			assert.Equal(t, tt.wantStatus, condition.Status)
			assert.Equal(t, tt.wantReason, condition.Reason)
			_ = drainRecordedEvents(recorder.Events)
		})
	}
}

func TestFetchGroupMembersFromMultipleIDPsReport_FallbackRetainsCachedMembers(t *testing.T) {
	escalation := &breakglassv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{Name: "cached-fallback", Namespace: "default"},
		Status: breakglassv1alpha1.BreakglassEscalationStatus{
			IDPGroupMemberships: map[string]map[string][]string{
				"": {"approvers": {"cached@example.com"}},
			},
		},
	}

	t.Run("resolver unavailable", func(t *testing.T) {
		report := (EscalationStatusUpdater{}).fetchGroupMembersFromMultipleIDPsReport(
			context.Background(),
			escalation,
			nil,
			[]string{"approvers"},
			zap.NewNop().Sugar(),
		)

		assert.Equal(t, groupSyncStatusFailed, report.syncStatus)
		assert.Equal(t, []string{"cached@example.com"}, report.hierarchy[""]["approvers"])
	})

	t.Run("resolver returns transient error", func(t *testing.T) {
		report := (EscalationStatusUpdater{
			Resolver: &MockResolver{
				errors: map[string]error{"approvers": errors.New("temporary lookup failure")},
			},
		}).fetchGroupMembersFromMultipleIDPsReport(
			context.Background(),
			escalation,
			nil,
			[]string{"approvers"},
			zap.NewNop().Sugar(),
		)

		assert.Equal(t, groupSyncStatusFailed, report.syncStatus)
		assert.Equal(t, []string{"cached@example.com"}, report.hierarchy[""]["approvers"])
	})
}

func TestFetchGroupMembersFromMultipleIDPsReport_MixedResolverAvailability(t *testing.T) {
	serverURL, certificateAuthority := newKeycloakFixture(t, keycloakFixtureSuccess)
	cli, escalation := newMultiIDPStatusTestClient(
		t,
		serverURL,
		certificateAuthority,
		breakglassv1alpha1.BreakglassEscalationStatus{},
	)
	oidcOnlyIDP := &breakglassv1alpha1.IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "idp-without-group-sync"},
		Spec: breakglassv1alpha1.IdentityProviderSpec{
			OIDC: breakglassv1alpha1.OIDCConfig{
				Authority:        serverURL,
				ClientID:         "breakglass-ui",
				ExpectedAudience: "breakglass-ui",
			},
		},
	}
	require.NoError(t, cli.Create(context.Background(), oidcOnlyIDP))

	log := zap.NewNop().Sugar()
	recorder := fakeEventRecorder{Events: make(chan string, 2)}
	report := (EscalationStatusUpdater{
		IDPLoader:     cfgpkg.NewIdentityProviderLoader(cli),
		EventRecorder: recorder,
	}).fetchGroupMembersFromMultipleIDPsReport(
		context.Background(),
		escalation,
		[]string{"idp-a", "idp-without-group-sync"},
		[]string{"approvers"},
		log,
	)

	assert.Equal(t, groupSyncStatusPartialFailure, report.syncStatus)
	assert.Len(t, report.syncErrors, 1)
	assert.Equal(t, []string{"approver@example.com"}, report.hierarchy["idp-a"]["approvers"])
	assert.NotContains(t, report.hierarchy, "idp-without-group-sync")
	assert.True(t, recordedEventContains(drainRecordedEvents(recorder.Events), "Warning GroupSyncResolverCreationFailed"))
}

func TestEscalationStatusUpdaterRunOnceSkipsCanceledContext(t *testing.T) {
	cli := fake.NewClientBuilder().
		WithScheme(breakglass.Scheme).
		WithStatusSubresource(&breakglassv1alpha1.BreakglassEscalation{}).
		Build()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	EscalationStatusUpdater{
		K8sClient: cli,
	}.runOnce(ctx, zap.NewNop().Sugar())
}

func TestIsContextTermination(t *testing.T) {
	assert.True(t, isContextTermination(context.Canceled))
	assert.True(t, isContextTermination(errors.Join(errors.New("request stopped"), context.DeadlineExceeded)))
	assert.False(t, isContextTermination(errors.New("unavailable")))
}

func TestKeycloakGroupMemberResolverRejectsInvalidInputs(t *testing.T) {
	var nilResolver *KeycloakGroupMemberResolver
	_, err := nilResolver.Members(context.Background(), "approvers")
	require.Error(t, err)

	_, err = (&KeycloakGroupMemberResolver{}).Members(context.Background(), " ")
	require.Error(t, err)
}

func TestKeycloakGroupMemberResolverRejectsMalformedGroupResponse(t *testing.T) {
	serverURL, certificateAuthority := newKeycloakFixture(t, keycloakFixtureMalformed)
	resolver := NewKeycloakGroupMemberResolver(zap.NewNop().Sugar(), cfgpkg.KeycloakRuntimeConfig{
		BaseURL:              serverURL,
		Realm:                "test-realm",
		ClientID:             "group-sync",
		ClientSecret:         "fixture-secret",
		CertificateAuthority: certificateAuthority,
	})

	_, err := resolver.Members(context.Background(), "approvers")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "matched without an ID")
}

func TestKeycloakGroupMemberResolverClassifiesGroupDetailDeletion(t *testing.T) {
	serverURL, certificateAuthority := newKeycloakFixture(t, keycloakFixtureDetail404)
	resolver := NewKeycloakGroupMemberResolver(zap.NewNop().Sugar(), cfgpkg.KeycloakRuntimeConfig{
		BaseURL:              serverURL,
		Realm:                "test-realm",
		ClientID:             "group-sync",
		ClientSecret:         "fixture-secret",
		CertificateAuthority: certificateAuthority,
	})

	_, err := resolver.Members(context.Background(), "approvers")

	require.Error(t, err)
	assert.ErrorIs(t, err, breakglass.ErrGroupNotFound)
}

func TestKeycloakGroupMemberResolverCachesClientCredentialToken(t *testing.T) {
	serverURL, certificateAuthority := newKeycloakFixture(t, keycloakFixtureSuccess)
	resolver := NewKeycloakGroupMemberResolver(zap.NewNop().Sugar(), cfgpkg.KeycloakRuntimeConfig{
		BaseURL:              serverURL,
		Realm:                "test-realm",
		ClientID:             "group-sync",
		ClientSecret:         "fixture-secret",
		CertificateAuthority: certificateAuthority,
	})

	first, err := resolver.getToken(context.Background())
	require.NoError(t, err)
	second, err := resolver.getToken(context.Background())
	require.NoError(t, err)
	assert.Equal(t, first, second)
}

func TestKeycloakGroupMemberResolverTokenCancellation(t *testing.T) {
	serverURL, certificateAuthority := newKeycloakFixture(t, keycloakFixtureSuccess)
	resolver := NewKeycloakGroupMemberResolver(zap.NewNop().Sugar(), cfgpkg.KeycloakRuntimeConfig{
		BaseURL:              serverURL,
		Realm:                "test-realm",
		ClientID:             "group-sync",
		ClientSecret:         "fixture-secret",
		CertificateAuthority: certificateAuthority,
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := resolver.getToken(ctx)

	require.Error(t, err)
}
