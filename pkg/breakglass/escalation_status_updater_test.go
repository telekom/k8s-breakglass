/*
Copyright 2024.

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

package breakglass

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	telekomv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	cfgpkg "github.com/telekom/k8s-breakglass/pkg/config"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// MockResolver implements GroupMemberResolver for testing
type MockResolver struct {
	members map[string][]string
	errors  map[string]error
}

func (m *MockResolver) Members(ctx context.Context, group string) ([]string, error) {
	if err, exists := m.errors[group]; exists {
		return nil, err
	}
	return m.members[group], nil
}

// TestFetchGroupMembersFromMultipleIDPs_SingleIDPFallback_HappyPath tests fallback to single IDP when IDPLoader is nil
func TestFetchGroupMembersFromMultipleIDPs_SingleIDPFallback_HappyPath(t *testing.T) {
	log, _ := zap.NewProduction()
	defer func() { _ = log.Sync() }()
	slog := log.Sugar()

	resolver := &MockResolver{
		members: map[string][]string{
			"admin-group": {"user1@example.com", "user2@example.com"},
		},
		errors: map[string]error{},
	}

	updater := &EscalationStatusUpdater{
		Resolver:      resolver,
		IDPLoader:     nil, // No IDPLoader = fallback mode
		EventRecorder: nil,
	}

	escalation := &telekomv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-escalation",
			Namespace: "default",
		},
	}

	ctx := context.Background()
	hierarchy, status, syncErrors := updater.fetchGroupMembersFromMultipleIDPs(
		ctx, escalation, []string{}, []string{"admin-group"}, slog)

	assert.Equal(t, "Success", status)
	assert.Len(t, syncErrors, 0)
	assert.NotNil(t, hierarchy)
	assert.Contains(t, hierarchy, "")
	assert.Len(t, hierarchy[""], 1)
	assert.Len(t, hierarchy[""]["admin-group"], 2)
	assert.Contains(t, hierarchy[""]["admin-group"], "user1@example.com")
	assert.Contains(t, hierarchy[""]["admin-group"], "user2@example.com")
}

// TestFetchGroupMembersFromMultipleIDPs_MultipleGroups_HappyPath tests fetching multiple groups
func TestFetchGroupMembersFromMultipleIDPs_MultipleGroups_HappyPath(t *testing.T) {
	log, _ := zap.NewProduction()
	defer func() { _ = log.Sync() }()
	slog := log.Sugar()

	resolver := &MockResolver{
		members: map[string][]string{
			"admin-group":    {"user1@example.com", "user2@example.com"},
			"approver-group": {"approver1@example.com", "approver2@example.com"},
		},
		errors: map[string]error{},
	}

	updater := &EscalationStatusUpdater{
		Resolver:      resolver,
		IDPLoader:     nil,
		EventRecorder: nil,
	}

	escalation := &telekomv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-escalation",
			Namespace: "default",
		},
	}

	ctx := context.Background()
	groups := []string{"admin-group", "approver-group"}
	hierarchy, status, syncErrors := updater.fetchGroupMembersFromMultipleIDPs(
		ctx, escalation, []string{}, groups, slog)

	assert.Equal(t, "Success", status)
	assert.Len(t, syncErrors, 0)
	assert.NotNil(t, hierarchy)
	assert.Len(t, hierarchy[""], 2)
	assert.Len(t, hierarchy[""]["admin-group"], 2)
	assert.Len(t, hierarchy[""]["approver-group"], 2)
}

// TestFetchGroupMembersFromMultipleIDPs_EmptyGroups tests with empty groups list
func TestFetchGroupMembersFromMultipleIDPs_EmptyGroups(t *testing.T) {
	log, _ := zap.NewProduction()
	defer func() { _ = log.Sync() }()
	slog := log.Sugar()

	resolver := &MockResolver{
		members: map[string][]string{},
		errors:  map[string]error{},
	}

	updater := &EscalationStatusUpdater{
		Resolver:      resolver,
		IDPLoader:     nil,
		EventRecorder: nil,
	}

	escalation := &telekomv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-escalation",
			Namespace: "default",
		},
	}

	ctx := context.Background()
	hierarchy, status, syncErrors := updater.fetchGroupMembersFromMultipleIDPs(
		ctx, escalation, []string{}, []string{}, slog)

	assert.Equal(t, "Success", status)
	assert.Len(t, syncErrors, 0)
	assert.NotNil(t, hierarchy)
	assert.Empty(t, hierarchy)
}

// TestFetchGroupMembersFromMultipleIDPs_NilResolver tests with nil resolver
func TestFetchGroupMembersFromMultipleIDPs_NilResolver(t *testing.T) {
	log, _ := zap.NewProduction()
	defer func() { _ = log.Sync() }()
	slog := log.Sugar()

	updater := &EscalationStatusUpdater{
		Resolver:      nil,
		IDPLoader:     nil,
		EventRecorder: nil,
	}

	escalation := &telekomv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-escalation",
			Namespace: "default",
		},
	}

	ctx := context.Background()
	hierarchy, status, syncErrors := updater.fetchGroupMembersFromMultipleIDPs(
		ctx, escalation, []string{}, []string{"admin-group"}, slog)

	assert.Equal(t, "Success", status)
	assert.Len(t, syncErrors, 0)
	assert.NotNil(t, hierarchy)
}

// TestNormalizeMembers_Deduplication tests member normalization removes duplicates
func TestNormalizeMembers_Deduplication(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			name:     "No duplicates",
			input:    []string{"user1@example.com", "user2@example.com"},
			expected: []string{"user1@example.com", "user2@example.com"},
		},
		{
			name:     "Case insensitive duplicates",
			input:    []string{"user1@example.com", "USER1@EXAMPLE.COM", "user2@example.com"},
			expected: []string{"user1@example.com", "user2@example.com"},
		},
		{
			name:     "Whitespace normalization",
			input:    []string{"  user1@example.com  ", "user2@example.com"},
			expected: []string{"user1@example.com", "user2@example.com"},
		},
		{
			name:     "Empty strings removed",
			input:    []string{"user1@example.com", "", "user2@example.com", "  "},
			expected: []string{"user1@example.com", "user2@example.com"},
		},
		{
			name:     "Mixed case and whitespace",
			input:    []string{"  User1@Example.COM  ", "USER1@EXAMPLE.COM", " user2@example.com"},
			expected: []string{"user1@example.com", "user2@example.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizeMembers(tt.input)
			assert.ElementsMatch(t, tt.expected, result)
		})
	}
}

// TestDeduplicateMembersFromHierarchy_SingleGroup_SingleIDP tests deduplication with single IDP
func TestDeduplicateMembersFromHierarchy_SingleGroup_SingleIDP(t *testing.T) {
	hierarchy := map[string]map[string][]string{
		"": {
			"admin-group": {"user1@example.com", "user2@example.com"},
		},
	}

	result := deduplicateMembersFromHierarchy(hierarchy, "admin-group")
	assert.Len(t, result, 2)
	assert.Contains(t, result, "user1@example.com")
	assert.Contains(t, result, "user2@example.com")
}

// TestDeduplicateMembersFromHierarchy_MultipleIDPs_HappyPath tests deduplication with multiple IDPs
func TestDeduplicateMembersFromHierarchy_MultipleIDPs_HappyPath(t *testing.T) {
	hierarchy := map[string]map[string][]string{
		"idp-1": {
			"admin-group": {"user1@example.com", "user2@example.com"},
		},
		"idp-2": {
			"admin-group": {"user2@example.com", "user3@example.com"},
		},
		"idp-3": {
			"admin-group": {"user1@example.com", "user4@example.com"},
		},
	}

	result := deduplicateMembersFromHierarchy(hierarchy, "admin-group")
	assert.Len(t, result, 4)
	assert.Contains(t, result, "user1@example.com")
	assert.Contains(t, result, "user2@example.com")
	assert.Contains(t, result, "user3@example.com")
	assert.Contains(t, result, "user4@example.com")
}

// TestDeduplicateMembersFromHierarchy_EmptyHierarchy tests with empty hierarchy
func TestDeduplicateMembersFromHierarchy_EmptyHierarchy(t *testing.T) {
	hierarchy := map[string]map[string][]string{}

	result := deduplicateMembersFromHierarchy(hierarchy, "admin-group")
	assert.Len(t, result, 0)
}

// TestDeduplicateMembersFromHierarchy_GroupNotFound tests when group doesn't exist
func TestDeduplicateMembersFromHierarchy_GroupNotFound(t *testing.T) {
	hierarchy := map[string]map[string][]string{
		"idp-1": {
			"other-group": {"user1@example.com"},
		},
	}

	result := deduplicateMembersFromHierarchy(hierarchy, "admin-group")
	assert.Len(t, result, 0)
}

// TestDeduplicateMembersFromHierarchy_CaseInsensitive tests case insensitive deduplication
func TestDeduplicateMembersFromHierarchy_CaseInsensitive(t *testing.T) {
	hierarchy := map[string]map[string][]string{
		"idp-1": {
			"admin-group": {"User1@Example.COM", "user2@example.com"},
		},
		"idp-2": {
			"admin-group": {"user1@example.com", "USER2@EXAMPLE.COM"},
		},
	}

	result := deduplicateMembersFromHierarchy(hierarchy, "admin-group")
	// Should deduplicate case-insensitively and normalize to lowercase
	assert.Len(t, result, 2)
}

// TestDeduplicateMembersFromHierarchy_WhitespaceHandling tests whitespace handling
func TestDeduplicateMembersFromHierarchy_WhitespaceHandling(t *testing.T) {
	hierarchy := map[string]map[string][]string{
		"idp-1": {
			"admin-group": {"  user1@example.com  ", "user2@example.com"},
		},
		"idp-2": {
			"admin-group": {"user1@example.com", "  user2@example.com  "},
		},
	}

	result := deduplicateMembersFromHierarchy(hierarchy, "admin-group")
	assert.Len(t, result, 2)
}

// TestCreateResolverForIDP_WithValidConfig tests resolver creation with valid config
func TestCreateResolverForIDP_WithValidConfig(t *testing.T) {
	log, _ := zap.NewProduction()
	defer func() { _ = log.Sync() }()
	slog := log.Sugar()

	updater := &EscalationStatusUpdater{}

	kcConfig := cfgpkg.KeycloakRuntimeConfig{
		BaseURL:      "https://keycloak.example.com",
		Realm:        "master",
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	}

	idpConfig := &cfgpkg.IdentityProviderConfig{
		Keycloak: &kcConfig,
	}

	resolver := updater.createResolverForIDP(idpConfig, slog)
	assert.NotNil(t, resolver)
}

// TestCreateResolverForIDP_WithNilConfig tests resolver creation with nil config
func TestCreateResolverForIDP_WithNilConfig(t *testing.T) {
	log, _ := zap.NewProduction()
	defer func() { _ = log.Sync() }()
	slog := log.Sugar()

	updater := &EscalationStatusUpdater{}

	resolver := updater.createResolverForIDP(nil, slog)
	assert.Nil(t, resolver)
}

// TestCreateResolverForIDP_NoKeycloakConfig tests resolver creation without Keycloak config
func TestCreateResolverForIDP_NoKeycloakConfig(t *testing.T) {
	log, _ := zap.NewProduction()
	defer func() { _ = log.Sync() }()
	slog := log.Sugar()

	updater := &EscalationStatusUpdater{}

	idpConfig := &cfgpkg.IdentityProviderConfig{
		Keycloak: nil,
	}

	resolver := updater.createResolverForIDP(idpConfig, slog)
	assert.Nil(t, resolver)
}

// TestEqualStringSlices_HappyPath tests string slice equality
func TestEqualStringSlices_HappyPath(t *testing.T) {
	tests := []struct {
		name     string
		a        []string
		b        []string
		expected bool
	}{
		{
			name:     "Equal slices",
			a:        []string{"user1", "user2"},
			b:        []string{"user1", "user2"},
			expected: true,
		},
		{
			name:     "Different order but equal",
			a:        []string{"user1", "user2"},
			b:        []string{"user2", "user1"},
			expected: true, // Function compares as sets, not ordered
		},
		{
			name:     "Different length",
			a:        []string{"user1", "user2"},
			b:        []string{"user1"},
			expected: false,
		},
		{
			name:     "Empty slices",
			a:        []string{},
			b:        []string{},
			expected: true,
		},
		{
			name:     "One empty",
			a:        []string{"user1"},
			b:        []string{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := equalStringSlices(tt.a, tt.b)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// BenchmarkDeduplicateMembersFromHierarchy benchmarks the deduplication function
func BenchmarkDeduplicateMembersFromHierarchy(b *testing.B) {
	hierarchy := map[string]map[string][]string{
		"idp-1": {
			"group-1": make([]string, 100),
			"group-2": make([]string, 100),
		},
		"idp-2": {
			"group-1": make([]string, 100),
			"group-2": make([]string, 100),
		},
		"idp-3": {
			"group-1": make([]string, 100),
		},
	}

	// Populate with test data
	for i := 0; i < 100; i++ {
		hierarchy["idp-1"]["group-1"][i] = fmt.Sprintf("user%d@example.com", i)
		hierarchy["idp-1"]["group-2"][i] = fmt.Sprintf("user%d@example.com", i+50)
		hierarchy["idp-2"]["group-1"][i] = fmt.Sprintf("user%d@example.com", i+25)
		hierarchy["idp-2"]["group-2"][i] = fmt.Sprintf("user%d@example.com", i+75)
		hierarchy["idp-3"]["group-1"][i] = fmt.Sprintf("user%d@example.com", i)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = deduplicateMembersFromHierarchy(hierarchy, "group-1")
	}
}

// BenchmarkNormalizeMembers benchmarks the normalize function
func BenchmarkNormalizeMembers(b *testing.B) {
	members := make([]string, 1000)
	for i := 0; i < 1000; i++ {
		members[i] = fmt.Sprintf("user%d@example.com", i)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = normalizeMembers(members)
	}
}
