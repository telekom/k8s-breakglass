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
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Nerzal/gocloak/v13"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	breakglass "github.com/telekom/k8s-breakglass/pkg/breakglass"
	cfgpkg "github.com/telekom/k8s-breakglass/pkg/config"
	"github.com/telekom/k8s-breakglass/pkg/system"
)

// ZAM role names as delivered in the OIDC groups claim: "dttcaas-" followed by
// {tenant}_{privilege}, {tenant}_{environment|cluster}_{privilege},
// {tenant}_bm4x-{shard}_{privilege} or platform_{privilege}. The LDAP CN
// (prefix plus role) is at most 64 characters; role names use [A-Za-z0-9_.-].
const (
	zamLongest     = "dttcaas-ZAM-Tenant.123_tcaas-mgmt-nord-1.prd.b_reader-restricted" // 64 characters
	zamTenant      = "dttcaas-multi-idp-tenant_appowner"
	zamShard       = "dttcaas-multi-idp-tenant_bm4x-fra-1_poweruser"
	zamPlatform    = "dttcaas-platform_poweruser"
	zamFirstLine   = "dttcaas-first-line_fixed-core"
	zamMixedCase   = "dttcaas-Tenant-A_Cluster.01_poweruser"
	zamOIDCPrefix  = "oidc:"
	zamPrefixedMax = zamOIDCPrefix + zamLongest
)

func TestZAMFixtureLengths(t *testing.T) {
	require.Len(t, zamLongest, 64, "fixture must sit exactly at the ZAM LDAP CN limit")
	require.Greater(t, len(zamPrefixedMax), 63, "prefixed form must exceed the label-value limit")
}

func kcGroup(id, name string) *gocloak.Group {
	return &gocloak.Group{ID: gocloak.StringP(id), Name: gocloak.StringP(name)}
}

func TestMatchKeycloakGroupZAMNames(t *testing.T) {
	lower := "dttcaas-tenant-a_cluster.01_poweruser"
	upper := "DTTCAAS-TENANT-A_CLUSTER.01_POWERUSER"
	tests := []struct {
		name          string
		groups        []*gocloak.Group
		lookup        string
		fallback      bool
		wantID        string
		wantAmbiguous bool
		wantErr       string
	}{
		{name: "longest exact", groups: []*gocloak.Group{kcGroup("1", zamLongest)}, lookup: zamLongest, wantID: "1"},
		{name: "special characters exact", groups: []*gocloak.Group{kcGroup("2", zamShard)}, lookup: zamShard, wantID: "2"},
		{name: "exact wins over case variant", groups: []*gocloak.Group{kcGroup("lower", lower), kcGroup("mixed", zamMixedCase)}, lookup: zamMixedCase, wantID: "mixed"},
		{name: "exact wins over case variant with fallback", groups: []*gocloak.Group{kcGroup("lower", lower), kcGroup("mixed", zamMixedCase)}, lookup: zamMixedCase, fallback: true, wantID: "mixed"},
		{name: "case variant only is not a match by default", groups: []*gocloak.Group{kcGroup("3", lower)}, lookup: zamMixedCase},
		{name: "unique case variant with fallback", groups: []*gocloak.Group{kcGroup("3", lower)}, lookup: zamMixedCase, fallback: true, wantID: "3"},
		{name: "several case variants with fallback fail closed", groups: []*gocloak.Group{kcGroup("a", lower), kcGroup("b", upper)}, lookup: zamMixedCase, fallback: true, wantAmbiguous: true},
		{name: "several case variants without fallback are no match", groups: []*gocloak.Group{kcGroup("a", lower), kcGroup("b", upper)}, lookup: zamMixedCase},
		{name: "two exact matches fail closed", groups: []*gocloak.Group{kcGroup("a", zamLongest), kcGroup("b", zamLongest)}, lookup: zamLongest, wantAmbiguous: true},
		{name: "two exact matches fail closed with fallback", groups: []*gocloak.Group{kcGroup("a", zamLongest), kcGroup("b", zamLongest)}, lookup: zamLongest, fallback: true, wantAmbiguous: true},
		{name: "underscore and hyphen are distinct", groups: []*gocloak.Group{kcGroup("4", "dttcaas-multi-idp-tenant-appowner")}, lookup: zamTenant, fallback: true},
		{name: "missing id rejected", groups: []*gocloak.Group{{Name: gocloak.StringP(zamPlatform)}}, lookup: zamPlatform, wantErr: "without an ID"},
		{name: "nil entries ignored", groups: []*gocloak.Group{nil, {ID: gocloak.StringP("x")}, kcGroup("5", zamFirstLine)}, lookup: zamFirstLine, wantID: "5"},
		{name: "no match", groups: []*gocloak.Group{kcGroup("6", zamPlatform)}, lookup: zamTenant},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := matchKeycloakGroup(tt.groups, tt.lookup, tt.fallback)
			switch {
			case tt.wantAmbiguous:
				require.Error(t, err)
				assert.True(t, breakglass.IsGroupAmbiguous(err), "ambiguity must be classified: %v", err)
				assert.False(t, breakglass.IsGroupNotFound(err), "ambiguity is not a missing group")
				assert.Nil(t, got)
				return
			case tt.wantErr != "":
				require.ErrorContains(t, err, tt.wantErr)
				assert.Nil(t, got)
				return
			}
			require.NoError(t, err)
			if tt.wantID == "" {
				assert.Nil(t, got)
				return
			}
			require.NotNil(t, got)
			assert.Equal(t, tt.wantID, *got.ID)
		})
	}
}

// keycloakCaseVariantServer serves an exact search that returns only the
// exact name (Keycloak exact search is case-sensitive) and a case-insensitive
// substring search that also returns the case variants.
func keycloakCaseVariantServer(t *testing.T, variants ...string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/admin/realms/test-realm/groups":
			search := r.URL.Query().Get("search")
			var out []map[string]string
			for i, name := range variants {
				if (r.URL.Query().Get("exact") == "true" && name == search) ||
					(r.URL.Query().Get("exact") != "true" && strings.Contains(strings.ToLower(name), strings.ToLower(search))) {
					out = append(out, map[string]string{"id": fmt.Sprintf("g%d", i), "name": name})
				}
			}
			require.NoError(t, json.NewEncoder(w).Encode(out))
		case strings.HasSuffix(r.URL.Path, "/members"):
			id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/admin/realms/test-realm/groups/"), "/members")
			_, _ = fmt.Fprintf(w, `[{"id":"u-%s","username":"member-%s","email":"member-%s@example.com"}]`, id, id, id)
		case strings.HasPrefix(r.URL.Path, "/admin/realms/test-realm/groups/"):
			id := strings.TrimPrefix(r.URL.Path, "/admin/realms/test-realm/groups/")
			_, _ = fmt.Fprintf(w, `{"id":%q,"subGroups":[]}`, id)
		default:
			t.Errorf("unexpected Keycloak path %q", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
}

func newTestKeycloakResolver(url string) *KeycloakGroupMemberResolver {
	return NewKeycloakGroupMemberResolver(zap.NewNop().Sugar(), cfgpkg.KeycloakRuntimeConfig{
		BaseURL: url, Realm: "test-realm", ClientID: "test-client", ServiceAccountToken: "test-token",
	})
}

// The resolver is exact-only by default and accepts only a unique case
// variant when the transitional kubernetes.approverGroupCaseInsensitiveFallback
// is enabled; several variants fail closed in both modes.
func TestKeycloakResolverCaseInsensitiveFallbackOptOut(t *testing.T) {
	const configured = "dttcaas-ZAM-Tenant.123_appowner"
	tests := []struct {
		name          string
		fallback      bool
		variants      []string
		wantMember    string
		wantNotFound  bool
		wantAmbiguous bool
	}{
		{name: "default exact", variants: []string{configured, "dttcaas-ZAM-TENANT.123_appowner"}, wantMember: "member-g0@example.com"},
		{name: "default ignores unique case variant", variants: []string{"dttcaas-zam-tenant.123_appowner"}, wantNotFound: true},
		{name: "opt-out accepts unique case variant", fallback: true, variants: []string{"dttcaas-zam-tenant.123_appowner"}, wantMember: "member-g0@example.com"},
		{name: "opt-out prefers exact", fallback: true, variants: []string{"dttcaas-ZAM-TENANT.123_appowner", configured}, wantMember: "member-g1@example.com"},
		{name: "opt-out fails closed on several variants", fallback: true, variants: []string{"dttcaas-zam-tenant.123_appowner", "dttcaas-ZAM-TENANT.123_appowner"}, wantAmbiguous: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			SetApproverGroupCaseInsensitiveFallback(tt.fallback)
			t.Cleanup(func() { SetApproverGroupCaseInsensitiveFallback(false) })
			server := keycloakCaseVariantServer(t, tt.variants...)
			defer server.Close()

			members, err := newTestKeycloakResolver(server.URL).Members(context.Background(), configured)
			switch {
			case tt.wantNotFound:
				require.Error(t, err)
				assert.True(t, breakglass.IsGroupNotFound(err), "%v", err)
			case tt.wantAmbiguous:
				require.Error(t, err)
				assert.True(t, breakglass.IsGroupAmbiguous(err), "%v", err)
			default:
				require.NoError(t, err)
				assert.Equal(t, []string{tt.wantMember}, members)
			}
		})
	}
}

// An ambiguous group drops its cached members and its status entry, so
// approval falls back to exact token groups, and emits ApproverGroupAmbiguous.
func TestEscalationStatusUpdaterAmbiguousApproverGroupDropsCachedMembers(t *testing.T) {
	cli := fake.NewClientBuilder().
		WithScheme(breakglass.Scheme).
		WithStatusSubresource(&breakglassv1alpha1.BreakglassEscalation{}).
		Build()
	escalation := &breakglassv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{Name: "ambiguous-approver-group", Namespace: "default", Generation: 2},
		Spec: breakglassv1alpha1.BreakglassEscalationSpec{
			EscalatedGroup: "admin-group",
			Allowed:        breakglassv1alpha1.BreakglassEscalationAllowed{Clusters: []string{"my-cluster"}},
			Approvers:      breakglassv1alpha1.BreakglassEscalationApprovers{Groups: []string{zamMixedCase, zamPlatform}},
		},
		Status: breakglassv1alpha1.BreakglassEscalationStatus{
			ApproverGroupMembers: map[string][]string{
				zamMixedCase: {"first-match@example.com"},
				zamPlatform:  {"old@example.com"},
			},
		},
	}
	require.NoError(t, cli.Create(context.Background(), escalation))
	require.NoError(t, cli.Status().Update(context.Background(), escalation))

	recorder := fakeEventRecorder{Events: make(chan string, 4)}
	updater := EscalationStatusUpdater{
		Log:           zap.NewNop().Sugar(),
		K8sClient:     cli,
		EventRecorder: recorder,
		Resolver: &MockResolver{
			members: map[string][]string{zamPlatform: {"platform@example.com"}},
			errors:  map[string]error{zamMixedCase: breakglass.NewGroupAmbiguousError(zamMixedCase, 2)},
		},
	}
	updater.runOnce(context.Background(), zap.NewNop().Sugar())

	updated := &breakglassv1alpha1.BreakglassEscalation{}
	require.NoError(t, cli.Get(context.Background(), client.ObjectKeyFromObject(escalation), updated))
	_, present := updated.Status.ApproverGroupMembers[zamMixedCase]
	assert.False(t, present, "ambiguous group must have no entry, not cached or empty members")
	assert.Equal(t, []string{"platform@example.com"}, updated.Status.ApproverGroupMembers[zamPlatform])
	condition := updated.GetCondition(string(breakglassv1alpha1.BreakglassEscalationConditionApprovalGroupMembersResolved))
	require.NotNil(t, condition)
	assert.Equal(t, metav1.ConditionFalse, condition.Status)
	assert.Contains(t, condition.Message, "ambiguous: "+zamMixedCase)
	assert.True(t, recordedEventContains(drainRecordedEvents(recorder.Events), "Warning ApproverGroupAmbiguous", zamMixedCase))
}

// The multi-IDP report never retains cached members for an ambiguous group.
func TestFetchGroupMembersReportAmbiguousGroupSkipsCache(t *testing.T) {
	escalation := &breakglassv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{Name: "esc", Namespace: "default"},
		Status: breakglassv1alpha1.BreakglassEscalationStatus{
			IDPGroupMemberships: map[string]map[string][]string{"": {zamMixedCase: {"first-match@example.com"}}},
		},
	}
	updater := EscalationStatusUpdater{Resolver: &MockResolver{
		members: map[string][]string{},
		errors:  map[string]error{zamMixedCase: breakglass.NewGroupAmbiguousError(zamMixedCase, 2)},
	}}
	report := updater.fetchGroupMembersFromMultipleIDPsReport(context.Background(), escalation, []string{"idp"}, []string{zamMixedCase}, zap.NewNop().Sugar())
	assert.Equal(t, []string{zamMixedCase}, report.ambiguousGroups)
	assert.Equal(t, []string{zamMixedCase}, report.ambiguousEverywhere, "a single resolver is every provider")
	assert.Empty(t, report.missingGroups)
	assert.Empty(t, deduplicateMembersFromHierarchy(report.hierarchy, zamMixedCase))
}

func TestGroupsMatchZAMNames(t *testing.T) {
	tests := []struct {
		name         string
		userGroups   []string
		allowed      []string
		oidcPrefixes []string
		want         bool
	}{
		{name: "longest unprefixed", userGroups: []string{zamLongest}, allowed: []string{zamLongest}, want: true},
		{name: "allowed in prefixed form", userGroups: []string{zamLongest}, allowed: []string{zamPrefixedMax}, oidcPrefixes: []string{zamOIDCPrefix}, want: true},
		{name: "prefixed allowed without configured prefix", userGroups: []string{zamLongest}, allowed: []string{zamPrefixedMax}},
		{name: "mixed case is exact", userGroups: []string{"dttcaas-tenant-a_cluster.01_poweruser"}, allowed: []string{zamMixedCase}},
		{name: "mixed case match", userGroups: []string{zamMixedCase}, allowed: []string{zamOIDCPrefix + zamMixedCase}, oidcPrefixes: []string{zamOIDCPrefix}, want: true},
		{name: "shard separators preserved", userGroups: []string{zamShard}, allowed: []string{zamShard}, want: true},
		{name: "underscore not equal hyphen", userGroups: []string{"dttcaas-multi-idp-tenant-appowner"}, allowed: []string{zamTenant}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, groupsMatch(tt.userGroups, tt.allowed, tt.oidcPrefixes))
		})
	}
}

func TestEscalationGroupIndexLookupValuesZAMNames(t *testing.T) {
	assert.Equal(t, []string{zamLongest, zamPrefixedMax},
		escalationGroupIndexLookupValues([]string{zamLongest}, []string{zamOIDCPrefix}))
	assert.Equal(t, []string{zamPrefixedMax, zamLongest},
		escalationGroupIndexLookupValues([]string{zamPrefixedMax}, []string{zamOIDCPrefix}))
}

// Only a group that every queried provider reports as ambiguous loses its
// aggregate entry; a provider that resolved it (even as empty) stays
// authoritative.
func TestGroupsAmbiguousInAllProviders(t *testing.T) {
	counts := map[string]int{"both": 2, "only-a": 1}
	assert.Equal(t, []string{"both"}, groupsAmbiguousInAllProviders(counts, 2))
	assert.Equal(t, []string{"both", "only-a"}, groupsAmbiguousInAllProviders(map[string]int{"both": 1, "only-a": 1}, 1))
	assert.Empty(t, groupsAmbiguousInAllProviders(counts, 0))
}

// Ambiguity errors are logged verbatim, so they must honor server.redactLogs
// while keeping their classification.
func TestAmbiguousLookupErrorHonorsLogRedaction(t *testing.T) {
	system.SetLogRedaction(true)
	t.Cleanup(func() { system.SetLogRedaction(false) })
	server := keycloakCaseVariantServer(t, zamLongest, zamLongest)
	defer server.Close()

	_, err := newTestKeycloakResolver(server.URL).Members(context.Background(), zamLongest)
	require.Error(t, err)
	assert.True(t, breakglass.IsGroupAmbiguous(err))
	assert.NotContains(t, err.Error(), zamLongest)
	assert.NotContains(t, breakglass.NewGroupNotFoundError(zamLongest).Error(), zamLongest)
}
