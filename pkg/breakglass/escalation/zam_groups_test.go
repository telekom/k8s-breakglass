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
	"testing"

	"github.com/Nerzal/gocloak/v13"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	breakglass "github.com/telekom/k8s-breakglass/pkg/breakglass"
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
	tests := []struct {
		name    string
		groups  []*gocloak.Group
		lookup  string
		wantID  string
		wantErr string
	}{
		{name: "longest exact", groups: []*gocloak.Group{kcGroup("1", zamLongest)}, lookup: zamLongest, wantID: "1"},
		{name: "special characters exact", groups: []*gocloak.Group{kcGroup("2", zamShard)}, lookup: zamShard, wantID: "2"},
		{name: "exact wins over case variant", groups: []*gocloak.Group{
			kcGroup("lower", "dttcaas-tenant-a_cluster.01_poweruser"),
			kcGroup("mixed", zamMixedCase),
		}, lookup: zamMixedCase, wantID: "mixed"},
		{name: "unique case-insensitive fallback", groups: []*gocloak.Group{kcGroup("3", "dttcaas-tenant-a_cluster.01_poweruser")}, lookup: zamMixedCase, wantID: "3"},
		{name: "ambiguous case variants fail closed", groups: []*gocloak.Group{
			kcGroup("a", "dttcaas-tenant-a_cluster.01_poweruser"),
			kcGroup("b", "DTTCAAS-TENANT-A_CLUSTER.01_POWERUSER"),
		}, lookup: zamMixedCase, wantErr: "ambiguously"},
		{name: "underscore and hyphen are distinct", groups: []*gocloak.Group{kcGroup("4", "dttcaas-multi-idp-tenant-appowner")}, lookup: zamTenant},
		{name: "missing id rejected", groups: []*gocloak.Group{{Name: gocloak.StringP(zamPlatform)}}, lookup: zamPlatform, wantErr: "without an ID"},
		{name: "nil entries ignored", groups: []*gocloak.Group{nil, {ID: gocloak.StringP("x")}, kcGroup("5", zamFirstLine)}, lookup: zamFirstLine, wantID: "5"},
		{name: "no match", groups: []*gocloak.Group{kcGroup("6", zamPlatform)}, lookup: zamTenant},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := matchKeycloakGroup(tt.groups, tt.lookup)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				assert.Nil(t, got)
				// Ambiguity must clear cached approver members like a missing group.
				assert.Equal(t, tt.wantErr == "ambiguously", breakglass.IsGroupNotFound(err))
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
