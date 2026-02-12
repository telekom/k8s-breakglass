package breakglass_test

import (
	"context"
	"os"
	"testing"
	"time"

	telekomv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/breakglass"
	cfgpkg "github.com/telekom/k8s-breakglass/pkg/config"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestEscalationManager_GetAllBreakglassEscalations(t *testing.T) {
	// TestEscalationManager_GetAllBreakglassEscalations
	//
	// Purpose:
	//   Validates the EscalationManager helper that lists all BreakglassEscalation
	//   resources from the client.
	//
	// Reasoning:
	//   Listing escalations is central to determining available escalations for
	//   users. The test checks empty, single and multiple escalation scenarios.
	//
	// Flow pattern:
	//   - Build fake client with zero/one/multiple escalation objects.
	//   - Call GetAllBreakglassEscalations and assert returned count and error
	//     expectation.
	//
	scheme := breakglass.Scheme

	tests := []struct {
		name            string
		existingObjects []client.Object
		expectedCount   int
		expectError     bool
	}{
		{
			name:            "no escalations",
			existingObjects: []client.Object{},
			expectedCount:   0,
			expectError:     false,
		},
		{
			name: "single escalation",
			existingObjects: []client.Object{
				&telekomv1alpha1.BreakglassEscalation{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-escalation",
						Namespace: "default",
					},
					Spec: telekomv1alpha1.BreakglassEscalationSpec{
						Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
							Clusters: []string{"test-cluster"},
							Groups:   []string{"admin"},
						},
					},
				},
			},
			expectedCount: 1,
			expectError:   false,
		},
		{
			name: "multiple escalations",
			existingObjects: []client.Object{
				&telekomv1alpha1.BreakglassEscalation{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-escalation-1",
						Namespace: "default",
					},
					Spec: telekomv1alpha1.BreakglassEscalationSpec{
						Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
							Clusters: []string{"test-cluster"},
							Groups:   []string{"admin"},
						},
					},
				},
				&telekomv1alpha1.BreakglassEscalation{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-escalation-2",
						Namespace: "default",
					},
					Spec: telekomv1alpha1.BreakglassEscalationSpec{
						Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
							Clusters: []string{"test-cluster-2"},
							Groups:   []string{"user"},
						},
					},
				},
			},
			expectedCount: 2,
			expectError:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(tt.existingObjects...).
				Build()

			em := breakglass.EscalationManager{Client: fakeClient}

			result, err := em.GetAllBreakglassEscalations(context.Background())

			if tt.expectError {
				if err == nil {
					t.Errorf("GetAllBreakglassEscalations() expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("GetAllBreakglassEscalations() unexpected error: %v", err)
				return
			}

			if len(result) != tt.expectedCount {
				t.Errorf("GetAllBreakglassEscalations() count = %v, want %v", len(result), tt.expectedCount)
			}
		})
	}
}

func TestEscalationManager_GetBreakglassEscalationsWithFilter(t *testing.T) {
	// TestEscalationManager_GetBreakglassEscalationsWithFilter
	//
	// Purpose:
	//   Ensures the manager's filter-based listing returns only escalation objects
	//   matching the provided predicate.
	//
	// Reasoning:
	//   Higher-level logic frequently needs filtered escalation lists (e.g., by
	//   group). This test covers several predicates to ensure filtering works.
	//
	scheme := breakglass.Scheme

	escalation1 := &telekomv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "admin-escalation",
			Namespace: "default",
		},
		Spec: telekomv1alpha1.BreakglassEscalationSpec{
			Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
				Clusters: []string{"test-cluster"},
				Groups:   []string{"admin"},
			},
		},
	}

	escalation2 := &telekomv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "user-escalation",
			Namespace: "default",
		},
		Spec: telekomv1alpha1.BreakglassEscalationSpec{
			Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
				Clusters: []string{"test-cluster"},
				Groups:   []string{"user"},
			},
		},
	}

	tests := []struct {
		name            string
		existingObjects []client.Object
		filter          func(telekomv1alpha1.BreakglassEscalation) bool
		expectedCount   int
		expectError     bool
	}{
		{
			name:            "filter for admin groups",
			existingObjects: []client.Object{escalation1, escalation2},
			filter: func(e telekomv1alpha1.BreakglassEscalation) bool {
				for _, group := range e.Spec.Allowed.Groups {
					if group == "admin" {
						return true
					}
				}
				return false
			},
			expectedCount: 1,
			expectError:   false,
		},
		{
			name:            "filter for non-existing groups",
			existingObjects: []client.Object{escalation1, escalation2},
			filter: func(e telekomv1alpha1.BreakglassEscalation) bool {
				for _, group := range e.Spec.Allowed.Groups {
					if group == "nonexistent" {
						return true
					}
				}
				return false
			},
			expectedCount: 0,
			expectError:   false,
		},
		{
			name:            "filter all",
			existingObjects: []client.Object{escalation1, escalation2},
			filter: func(e telekomv1alpha1.BreakglassEscalation) bool {
				return true
			},
			expectedCount: 2,
			expectError:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(tt.existingObjects...).
				Build()

			em := breakglass.EscalationManager{Client: fakeClient}

			result, err := em.GetBreakglassEscalationsWithFilter(context.Background(), tt.filter)

			if tt.expectError {
				if err == nil {
					t.Errorf("GetBreakglassEscalationsWithFilter() expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("GetBreakglassEscalationsWithFilter() unexpected error: %v", err)
				return
			}

			if len(result) != tt.expectedCount {
				t.Errorf("GetBreakglassEscalationsWithFilter() count = %v, want %v", len(result), tt.expectedCount)
			}
		})
	}
}

func TestEscalationManager_GetGroupBreakglassEscalations(t *testing.T) {
	// TestEscalationManager_GetGroupBreakglassEscalations
	//
	// Purpose:
	//   Verifies retrieval of escalations applicable to a given set of user
	//   groups.
	//
	// Reasoning:
	//   Users belong to multiple groups; escalations may specify several groups
	//   and overlap. The test ensures matching logic returns correct counts for
	//   different combinations of user groups.
	//
	scheme := breakglass.Scheme

	escalation1 := &telekomv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "admin-escalation",
			Namespace: "default",
		},
		Spec: telekomv1alpha1.BreakglassEscalationSpec{
			Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
				Clusters: []string{"test-cluster"},
				Groups:   []string{"admin", "system:authenticated"},
			},
		},
	}

	escalation2 := &telekomv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "user-escalation",
			Namespace: "default",
		},
		Spec: telekomv1alpha1.BreakglassEscalationSpec{
			Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
				Clusters: []string{"test-cluster"},
				Groups:   []string{"user"},
			},
		},
	}

	tests := []struct {
		name            string
		existingObjects []client.Object
		userGroups      []string
		expectedCount   int
		expectError     bool
	}{
		{
			name:            "user has admin group",
			existingObjects: []client.Object{escalation1, escalation2},
			userGroups:      []string{"admin", "system:authenticated"},
			expectedCount:   1,
			expectError:     false,
		},
		{
			name:            "user has system:authenticated group",
			existingObjects: []client.Object{escalation1, escalation2},
			userGroups:      []string{"system:authenticated"},
			expectedCount:   1,
			expectError:     false,
		},
		{
			name:            "user has no matching groups",
			existingObjects: []client.Object{escalation1, escalation2},
			userGroups:      []string{"guest"},
			expectedCount:   0,
			expectError:     false,
		},
		{
			name:            "user has multiple matching groups",
			existingObjects: []client.Object{escalation1, escalation2},
			userGroups:      []string{"admin", "user"},
			expectedCount:   2,
			expectError:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(tt.existingObjects...).
				Build()

			em := breakglass.EscalationManager{Client: fakeClient}

			result, err := em.GetGroupBreakglassEscalations(context.Background(), tt.userGroups)

			if tt.expectError {
				if err == nil {
					t.Errorf("GetGroupBreakglassEscalations() expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("GetGroupBreakglassEscalations() unexpected error: %v", err)
				return
			}

			if len(result) != tt.expectedCount {
				t.Errorf("GetGroupBreakglassEscalations() count = %v, want %v", len(result), tt.expectedCount)
			}
		})
	}
}

func TestEscalationManager_GetClusterGroupBreakglassEscalations(t *testing.T) {
	scheme := breakglass.Scheme

	escalation1 := &telekomv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cluster1-admin-escalation",
			Namespace: "default",
		},
		Spec: telekomv1alpha1.BreakglassEscalationSpec{
			Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
				Clusters: []string{"cluster1"},
				Groups:   []string{"admin"},
			},
		},
	}

	escalation2 := &telekomv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cluster2-admin-escalation",
			Namespace: "default",
		},
		Spec: telekomv1alpha1.BreakglassEscalationSpec{
			Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
				Clusters: []string{"cluster2"},
				Groups:   []string{"admin"},
			},
		},
	}

	escalation3 := &telekomv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cluster1-user-escalation",
			Namespace: "default",
		},
		Spec: telekomv1alpha1.BreakglassEscalationSpec{
			Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
				Clusters: []string{"cluster1"},
				Groups:   []string{"user"},
			},
		},
	}

	// Global escalation - applies to all clusters (uses "*" wildcard for ClusterConfigRefs and Allowed.Clusters)
	globalEscalation := &telekomv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "global-readonly-escalation",
			Namespace: "default",
		},
		Spec: telekomv1alpha1.BreakglassEscalationSpec{
			ClusterConfigRefs: []string{"*"}, // "*" = global (matches any cluster)
			Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
				Clusters: []string{"*"}, // "*" = global (matches any cluster)
				Groups:   []string{"readonly-users"},
			},
		},
	}

	tests := []struct {
		name            string
		existingObjects []client.Object
		cluster         string
		userGroups      []string
		expectedCount   int
		expectError     bool
	}{
		{
			name:            "cluster1 admin user",
			existingObjects: []client.Object{escalation1, escalation2, escalation3},
			cluster:         "cluster1",
			userGroups:      []string{"admin"},
			expectedCount:   1,
			expectError:     false,
		},
		{
			name:            "cluster2 admin user",
			existingObjects: []client.Object{escalation1, escalation2, escalation3},
			cluster:         "cluster2",
			userGroups:      []string{"admin"},
			expectedCount:   1,
			expectError:     false,
		},
		{
			name:            "cluster1 user with admin and user groups",
			existingObjects: []client.Object{escalation1, escalation2, escalation3},
			cluster:         "cluster1",
			userGroups:      []string{"admin", "user"},
			expectedCount:   2,
			expectError:     false,
		},
		{
			name:            "nonexistent cluster",
			existingObjects: []client.Object{escalation1, escalation2, escalation3},
			cluster:         "nonexistent",
			userGroups:      []string{"admin"},
			expectedCount:   0,
			expectError:     false,
		},
		{
			name:            "user with no matching groups",
			existingObjects: []client.Object{escalation1, escalation2, escalation3},
			cluster:         "cluster1",
			userGroups:      []string{"guest"},
			expectedCount:   0,
			expectError:     false,
		},
		{
			name:            "global escalation matches any cluster",
			existingObjects: []client.Object{escalation1, escalation2, globalEscalation},
			cluster:         "any-random-cluster",
			userGroups:      []string{"readonly-users"},
			expectedCount:   1,
			expectError:     false,
		},
		{
			name:            "global escalation matches alongside cluster-specific",
			existingObjects: []client.Object{escalation1, globalEscalation},
			cluster:         "cluster1",
			userGroups:      []string{"admin", "readonly-users"},
			expectedCount:   2,
			expectError:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(tt.existingObjects...).
				Build()

			em := breakglass.EscalationManager{Client: fakeClient}

			result, err := em.GetClusterGroupBreakglassEscalations(context.Background(), tt.cluster, tt.userGroups)

			if tt.expectError {
				if err == nil {
					t.Errorf("GetClusterGroupBreakglassEscalations() expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("GetClusterGroupBreakglassEscalations() unexpected error: %v", err)
				return
			}

			if len(result) != tt.expectedCount {
				t.Errorf("GetClusterGroupBreakglassEscalations() count = %v, want %v", len(result), tt.expectedCount)
			}
		})
	}
}

func TestEscalationManager_GlobPatternMatching(t *testing.T) {
	// TestEscalationManager_GlobPatternMatching
	//
	// Purpose:
	//   Validates glob pattern matching for cluster selection in escalations.
	//   Tests various glob patterns like "*", "prod-*", "*-staging", etc.
	//
	// Reasoning:
	//   Glob patterns enable flexible cluster targeting without listing
	//   every cluster explicitly. This is essential for multi-cluster
	//   environments with naming conventions.
	//
	scheme := breakglass.Scheme

	// Escalation with prefix pattern (prod-*)
	prefixEscalation := &telekomv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "prod-escalation",
			Namespace: "default",
		},
		Spec: telekomv1alpha1.BreakglassEscalationSpec{
			ClusterConfigRefs: []string{"prod-*"},
			Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
				Clusters: []string{"prod-*"},
				Groups:   []string{"prod-team"},
			},
			EscalatedGroup: "prod-admin",
		},
	}

	// Escalation with suffix pattern (*-staging)
	suffixEscalation := &telekomv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "staging-escalation",
			Namespace: "default",
		},
		Spec: telekomv1alpha1.BreakglassEscalationSpec{
			ClusterConfigRefs: []string{"*-staging"},
			Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
				Clusters: []string{"*-staging"},
				Groups:   []string{"dev-team"},
			},
			EscalatedGroup: "staging-admin",
		},
	}

	// Escalation with single char pattern (cluster-?)
	singleCharEscalation := &telekomv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "numbered-escalation",
			Namespace: "default",
		},
		Spec: telekomv1alpha1.BreakglassEscalationSpec{
			ClusterConfigRefs: []string{"cluster-?"},
			Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
				Clusters: []string{"cluster-?"},
				Groups:   []string{"ops-team"},
			},
			EscalatedGroup: "cluster-admin",
		},
	}

	// Global escalation with "*"
	globalEscalation := &telekomv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "global-escalation",
			Namespace: "default",
		},
		Spec: telekomv1alpha1.BreakglassEscalationSpec{
			ClusterConfigRefs: []string{"*"},
			Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
				Clusters: []string{"*"},
				Groups:   []string{"emergency-team"},
			},
			EscalatedGroup: "emergency-admin",
		},
	}

	// Escalation with empty arrays (should NOT match anything)
	emptyEscalation := &telekomv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "empty-escalation",
			Namespace: "default",
		},
		Spec: telekomv1alpha1.BreakglassEscalationSpec{
			ClusterConfigRefs: []string{}, // Empty = matches NOTHING
			Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
				Clusters: []string{}, // Empty = matches NOTHING
				Groups:   []string{"any-team"},
			},
			EscalatedGroup: "some-admin",
		},
	}

	// Exact match escalation
	exactEscalation := &telekomv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "exact-escalation",
			Namespace: "default",
		},
		Spec: telekomv1alpha1.BreakglassEscalationSpec{
			ClusterConfigRefs: []string{"prod-eu-west"},
			Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
				Clusters: []string{"prod-eu-west"},
				Groups:   []string{"eu-team"},
			},
			EscalatedGroup: "eu-admin",
		},
	}

	tests := []struct {
		name            string
		existingObjects []client.Object
		cluster         string
		userGroups      []string
		expectedCount   int
		expectedNames   []string // Optional: verify specific escalation names matched
	}{
		{
			name:            "prefix pattern matches prod-eu-west",
			existingObjects: []client.Object{prefixEscalation},
			cluster:         "prod-eu-west",
			userGroups:      []string{"prod-team"},
			expectedCount:   1,
			expectedNames:   []string{"prod-escalation"},
		},
		{
			name:            "prefix pattern matches prod-us-east",
			existingObjects: []client.Object{prefixEscalation},
			cluster:         "prod-us-east",
			userGroups:      []string{"prod-team"},
			expectedCount:   1,
		},
		{
			name:            "prefix pattern does NOT match staging-eu",
			existingObjects: []client.Object{prefixEscalation},
			cluster:         "staging-eu",
			userGroups:      []string{"prod-team"},
			expectedCount:   0,
		},
		{
			name:            "suffix pattern matches eu-staging",
			existingObjects: []client.Object{suffixEscalation},
			cluster:         "eu-staging",
			userGroups:      []string{"dev-team"},
			expectedCount:   1,
		},
		{
			name:            "suffix pattern matches us-staging",
			existingObjects: []client.Object{suffixEscalation},
			cluster:         "us-staging",
			userGroups:      []string{"dev-team"},
			expectedCount:   1,
		},
		{
			name:            "suffix pattern does NOT match eu-production",
			existingObjects: []client.Object{suffixEscalation},
			cluster:         "eu-production",
			userGroups:      []string{"dev-team"},
			expectedCount:   0,
		},
		{
			name:            "single char pattern matches cluster-1",
			existingObjects: []client.Object{singleCharEscalation},
			cluster:         "cluster-1",
			userGroups:      []string{"ops-team"},
			expectedCount:   1,
		},
		{
			name:            "single char pattern matches cluster-a",
			existingObjects: []client.Object{singleCharEscalation},
			cluster:         "cluster-a",
			userGroups:      []string{"ops-team"},
			expectedCount:   1,
		},
		{
			name:            "single char pattern does NOT match cluster-10",
			existingObjects: []client.Object{singleCharEscalation},
			cluster:         "cluster-10",
			userGroups:      []string{"ops-team"},
			expectedCount:   0,
		},
		{
			name:            "global pattern matches any cluster",
			existingObjects: []client.Object{globalEscalation},
			cluster:         "random-cluster-name",
			userGroups:      []string{"emergency-team"},
			expectedCount:   1,
		},
		{
			name:            "global pattern matches prod-eu-west",
			existingObjects: []client.Object{globalEscalation},
			cluster:         "prod-eu-west",
			userGroups:      []string{"emergency-team"},
			expectedCount:   1,
		},
		{
			name:            "empty arrays do NOT match any cluster",
			existingObjects: []client.Object{emptyEscalation},
			cluster:         "any-cluster",
			userGroups:      []string{"any-team"},
			expectedCount:   0,
		},
		{
			name:            "exact match works for prod-eu-west",
			existingObjects: []client.Object{exactEscalation},
			cluster:         "prod-eu-west",
			userGroups:      []string{"eu-team"},
			expectedCount:   1,
		},
		{
			name:            "exact match does NOT match prod-eu-east",
			existingObjects: []client.Object{exactEscalation},
			cluster:         "prod-eu-east",
			userGroups:      []string{"eu-team"},
			expectedCount:   0,
		},
		{
			name:            "multiple patterns - global and exact both match",
			existingObjects: []client.Object{globalEscalation, exactEscalation},
			cluster:         "prod-eu-west",
			userGroups:      []string{"emergency-team", "eu-team"},
			expectedCount:   2,
		},
		{
			name:            "multiple patterns - prefix and global match same cluster",
			existingObjects: []client.Object{globalEscalation, prefixEscalation},
			cluster:         "prod-us-east",
			userGroups:      []string{"emergency-team", "prod-team"},
			expectedCount:   2,
		},
		{
			name:            "no match when user not in allowed groups",
			existingObjects: []client.Object{globalEscalation, prefixEscalation},
			cluster:         "prod-us-east",
			userGroups:      []string{"random-group"},
			expectedCount:   0,
		},
	}

	// Add test cases for allowed.clusters glob patterns WITHOUT clusterConfigRefs
	// This tests that allowed.clusters alone supports glob patterns

	// Escalation using only allowed.clusters with glob (no clusterConfigRefs)
	allowedClustersOnlyGlob := &telekomv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "allowed-clusters-only-glob",
			Namespace: "default",
		},
		Spec: telekomv1alpha1.BreakglassEscalationSpec{
			// No clusterConfigRefs - only using allowed.clusters
			Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
				Clusters: []string{"dev-*"}, // Glob pattern in allowed.clusters only
				Groups:   []string{"dev-team"},
			},
			EscalatedGroup: "dev-admin",
		},
	}

	// Escalation using only allowed.clusters with global wildcard (no clusterConfigRefs)
	allowedClustersOnlyGlobal := &telekomv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "allowed-clusters-only-global",
			Namespace: "default",
		},
		Spec: telekomv1alpha1.BreakglassEscalationSpec{
			// No clusterConfigRefs - only using allowed.clusters
			Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
				Clusters: []string{"*"}, // Global wildcard in allowed.clusters only
				Groups:   []string{"global-team"},
			},
			EscalatedGroup: "global-admin",
		},
	}

	allowedClustersOnlyTests := []struct {
		name            string
		existingObjects []client.Object
		cluster         string
		userGroups      []string
		expectedCount   int
		expectedNames   []string
	}{
		{
			name:            "allowed.clusters glob matches dev-eu without clusterConfigRefs",
			existingObjects: []client.Object{allowedClustersOnlyGlob},
			cluster:         "dev-eu",
			userGroups:      []string{"dev-team"},
			expectedCount:   1,
			expectedNames:   []string{"allowed-clusters-only-glob"},
		},
		{
			name:            "allowed.clusters glob matches dev-us without clusterConfigRefs",
			existingObjects: []client.Object{allowedClustersOnlyGlob},
			cluster:         "dev-us",
			userGroups:      []string{"dev-team"},
			expectedCount:   1,
		},
		{
			name:            "allowed.clusters glob does NOT match prod-eu without clusterConfigRefs",
			existingObjects: []client.Object{allowedClustersOnlyGlob},
			cluster:         "prod-eu",
			userGroups:      []string{"dev-team"},
			expectedCount:   0,
		},
		{
			name:            "allowed.clusters global wildcard matches any cluster",
			existingObjects: []client.Object{allowedClustersOnlyGlobal},
			cluster:         "random-cluster-123",
			userGroups:      []string{"global-team"},
			expectedCount:   1,
			expectedNames:   []string{"allowed-clusters-only-global"},
		},
		{
			name:            "allowed.clusters global wildcard works alongside clusterConfigRefs glob",
			existingObjects: []client.Object{allowedClustersOnlyGlobal, prefixEscalation},
			cluster:         "prod-eu-west",
			userGroups:      []string{"global-team", "prod-team"},
			expectedCount:   2,
		},
	}
	tests = append(tests, allowedClustersOnlyTests...)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(tt.existingObjects...).
				Build()

			em := breakglass.EscalationManager{Client: fakeClient}

			result, err := em.GetClusterGroupBreakglassEscalations(context.Background(), tt.cluster, tt.userGroups)

			if err != nil {
				t.Errorf("GetClusterGroupBreakglassEscalations() unexpected error: %v", err)
				return
			}

			if len(result) != tt.expectedCount {
				names := make([]string, len(result))
				for i, e := range result {
					names[i] = e.Name
				}
				t.Errorf("GetClusterGroupBreakglassEscalations() count = %v (got: %v), want %v", len(result), names, tt.expectedCount)
			}

			// Verify specific expected names if provided
			if len(tt.expectedNames) > 0 {
				gotNames := make(map[string]bool)
				for _, e := range result {
					gotNames[e.Name] = true
				}
				for _, expectedName := range tt.expectedNames {
					if !gotNames[expectedName] {
						t.Errorf("GetClusterGroupBreakglassEscalations() missing expected escalation %q", expectedName)
					}
				}
			}
		})
	}
}

func TestEscalationManager_GetBreakglassEscalation(t *testing.T) {
	// TestEscalationManager_GetBreakglassEscalation
	//
	// Purpose:
	//   Validates retrieving a single BreakglassEscalation by name and namespace.
	//
	// Reasoning:
	//   Individual escalation lookup is needed for detailed views and actions.
	//
	scheme := breakglass.Scheme

	escalation := &telekomv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-escalation",
			Namespace: "default",
		},
		Spec: telekomv1alpha1.BreakglassEscalationSpec{
			Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
				Clusters: []string{"cluster1"},
				Groups:   []string{"admin"},
			},
			EscalatedGroup: "admin-access",
		},
	}

	tests := []struct {
		name            string
		existingObjects []client.Object
		searchName      string
		searchNamespace string
		expectError     bool
	}{
		{
			name:            "escalation exists",
			existingObjects: []client.Object{escalation},
			searchName:      "test-escalation",
			searchNamespace: "default",
			expectError:     false,
		},
		{
			name:            "escalation not found",
			existingObjects: []client.Object{},
			searchName:      "nonexistent",
			searchNamespace: "default",
			expectError:     true,
		},
		{
			name:            "wrong namespace",
			existingObjects: []client.Object{escalation},
			searchName:      "test-escalation",
			searchNamespace: "other-ns",
			expectError:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(tt.existingObjects...).
				Build()

			em := breakglass.EscalationManager{Client: fakeClient}

			result, err := em.GetBreakglassEscalation(context.Background(), tt.searchNamespace, tt.searchName)

			if tt.expectError {
				if err == nil {
					t.Errorf("GetBreakglassEscalation() expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("GetBreakglassEscalation() unexpected error: %v", err)
				return
			}

			if result.Name != tt.searchName {
				t.Errorf("GetBreakglassEscalation() name = %v, want %v", result.Name, tt.searchName)
			}
		})
	}
}

func TestNewEscalationManagerWithClient(t *testing.T) {
	// TestNewEscalationManagerWithClient
	//
	// Purpose:
	//   Validates the constructor that creates an EscalationManager with an existing client.
	//   Verifies functional options are applied by testing observable behavior.
	//
	scheme := breakglass.Scheme

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()

	t.Run("basic construction without options", func(t *testing.T) {
		em := breakglass.NewEscalationManagerWithClient(fakeClient, nil)
		if em.Client == nil {
			t.Error("NewEscalationManagerWithClient() returned nil client")
		}
		if em.GetResolver() != nil {
			t.Error("resolver should be nil when passed as nil")
		}
	})

	t.Run("with logger option verifiable via SetResolver log", func(t *testing.T) {
		// WithLogger injects a logger; verify it's used by calling SetResolver
		// which logs "EscalationManager resolver updated" via the injected logger.
		core, obs := observer.New(zap.InfoLevel)
		logger := zap.New(core).Sugar()
		em := breakglass.NewEscalationManagerWithClient(fakeClient, nil, breakglass.WithLogger(logger))
		if em.Client == nil {
			t.Error("NewEscalationManagerWithClient() returned nil client")
		}
		// Trigger a log via SetResolver to verify the injected logger is used
		em.SetResolver(nil)
		entries := obs.FilterMessage("EscalationManager resolver updated")
		if entries.Len() == 0 {
			t.Error("WithLogger: injected logger was not used by SetResolver")
		}
	})

	t.Run("with config loader option", func(t *testing.T) {
		cfgFile := t.TempDir() + "/config.yaml"
		_ = os.WriteFile(cfgFile, []byte("{}"), 0o644)
		loader := cfgpkg.NewCachedLoader(cfgFile, 5*time.Second)
		em := breakglass.NewEscalationManagerWithClient(fakeClient, nil, breakglass.WithConfigLoader(loader))
		if em.Client == nil {
			t.Error("NewEscalationManagerWithClient() returned nil client")
		}
	})

	t.Run("SetResolver(nil) clears resolver", func(t *testing.T) {
		em := breakglass.NewEscalationManagerWithClient(fakeClient, nil)
		em.SetResolver(nil)
		if em.GetResolver() != nil {
			t.Error("resolver should be nil after SetResolver(nil)")
		}
	})

	t.Run("with multiple options", func(t *testing.T) {
		logger := zap.NewNop().Sugar()
		cfgFile := t.TempDir() + "/config.yaml"
		_ = os.WriteFile(cfgFile, []byte("{}"), 0o644)
		loader := cfgpkg.NewCachedLoader(cfgFile, 5*time.Second)
		em := breakglass.NewEscalationManagerWithClient(fakeClient, nil, breakglass.WithLogger(logger), breakglass.WithConfigLoader(loader))
		if em.Client == nil {
			t.Error("NewEscalationManagerWithClient() returned nil client")
		}
	})

	t.Run("nil option is safely skipped", func(t *testing.T) {
		em := breakglass.NewEscalationManagerWithClient(fakeClient, nil, nil, breakglass.WithLogger(zap.NewNop().Sugar()), nil)
		if em.Client == nil {
			t.Error("NewEscalationManagerWithClient() returned nil client")
		}
	})

	t.Run("WithLogger(nil) is a no-op", func(t *testing.T) {
		// Passing nil to WithLogger should not overwrite the existing logger.
		core, obs := observer.New(zap.InfoLevel)
		logger := zap.New(core).Sugar()
		em := breakglass.NewEscalationManagerWithClient(fakeClient, nil, breakglass.WithLogger(logger), breakglass.WithLogger(nil))
		em.SetResolver(nil)
		entries := obs.FilterMessage("EscalationManager resolver updated")
		if entries.Len() == 0 {
			t.Error("WithLogger(nil) should not overwrite a previously set logger")
		}
	})

	t.Run("WithConfigLoader(nil) is a no-op", func(t *testing.T) {
		// Passing nil to WithConfigLoader should not overwrite the existing loader.
		// Verify by calling a method that invokes getConfig() internally and checking
		// that the fallback warning ("configLoader not set") is NOT logged.
		core, obs := observer.New(zap.DebugLevel)
		logger := zap.New(core).Sugar()

		// Create a config file in a temp dir so the CachedLoader has a real path.
		cfgDir := t.TempDir()
		cfgFile := cfgDir + "/config.yaml"
		if err := os.WriteFile(cfgFile, []byte("{}"), 0o644); err != nil {
			t.Fatalf("failed to write temp config: %v", err)
		}
		loader := cfgpkg.NewCachedLoader(cfgFile, 5*time.Second)

		em := breakglass.NewEscalationManagerWithClient(fakeClient, nil,
			breakglass.WithLogger(logger),
			breakglass.WithConfigLoader(loader),
			breakglass.WithConfigLoader(nil), // should be ignored
		)
		if em.Client == nil {
			t.Error("NewEscalationManagerWithClient() returned nil client")
		}
		// Trigger getConfig() indirectly via GetClusterGroupBreakglassEscalations,
		// which calls getOIDCPrefixes() → getConfig().
		// If WithConfigLoader(nil) overwrote the loader, the fallback warning would be logged.
		_, _ = em.GetClusterGroupBreakglassEscalations(t.Context(), "test-cluster", []string{"test-group"})
		entries := obs.FilterMessage("EscalationManager: configLoader not set, falling back to disk read (performance impact)")
		if entries.Len() > 0 {
			t.Error("WithConfigLoader(nil) should not have overwritten the existing loader; fallback warning was logged")
		}
	})
}

func TestEscalationManager_UpdateBreakglassEscalationStatus(t *testing.T) {
	// TestEscalationManager_UpdateBreakglassEscalationStatus
	//
	// Purpose:
	//   Validates updating the status subresource of a BreakglassEscalation.
	//
	scheme := breakglass.Scheme

	escalation := &telekomv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-escalation",
			Namespace: "default",
		},
		Spec: telekomv1alpha1.BreakglassEscalationSpec{
			EscalatedGroup: "admin-access",
		},
		Status: telekomv1alpha1.BreakglassEscalationStatus{
			ObservedGeneration: 0,
		},
	}

	t.Run("updates status successfully", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(escalation).
			WithStatusSubresource(escalation).
			Build()

		em := breakglass.EscalationManager{Client: fakeClient}

		// Modify the status
		updatedEsc := *escalation
		updatedEsc.Status.ObservedGeneration = 5

		err := em.UpdateBreakglassEscalationStatus(context.Background(), updatedEsc)
		if err != nil {
			t.Errorf("UpdateBreakglassEscalationStatus() unexpected error: %v", err)
		}

		// Verify the status was updated
		var fetched telekomv1alpha1.BreakglassEscalation
		if err := fakeClient.Get(context.Background(), client.ObjectKey{Name: "test-escalation", Namespace: "default"}, &fetched); err != nil {
			t.Fatalf("Failed to fetch escalation: %v", err)
		}
		if fetched.Status.ObservedGeneration != 5 {
			t.Errorf("Status.ObservedGeneration was not updated, got %d", fetched.Status.ObservedGeneration)
		}
	})

	t.Run("error when escalation does not exist", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			Build()

		em := breakglass.EscalationManager{Client: fakeClient}

		missingEsc := *escalation
		missingEsc.ResourceVersion = ""
		err := em.UpdateBreakglassEscalationStatus(context.Background(), missingEsc)
		if err == nil {
			t.Error("UpdateBreakglassEscalationStatus() expected error for nonexistent escalation")
		}
	})
}

func TestEscalationManager_GetClusterGroupTargetBreakglassEscalation(t *testing.T) {
	// TestEscalationManager_GetClusterGroupTargetBreakglassEscalation
	//
	// Purpose:
	//   Validates retrieving escalations for specific cluster, user groups, AND target group.
	//
	scheme := breakglass.Scheme

	escalation1 := &telekomv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "escalation-1",
			Namespace: "default",
		},
		Spec: telekomv1alpha1.BreakglassEscalationSpec{
			Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
				Clusters: []string{"cluster1"},
				Groups:   []string{"admin"},
			},
			EscalatedGroup: "admin-access",
		},
	}

	escalation2 := &telekomv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "escalation-2",
			Namespace: "default",
		},
		Spec: telekomv1alpha1.BreakglassEscalationSpec{
			Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
				Clusters: []string{"cluster1"},
				Groups:   []string{"user"},
			},
			EscalatedGroup: "user-access",
		},
	}

	tests := []struct {
		name            string
		existingObjects []client.Object
		cluster         string
		userGroups      []string
		targetGroup     string
		expectedCount   int
	}{
		{
			name:            "matches cluster, groups, and target",
			existingObjects: []client.Object{escalation1, escalation2},
			cluster:         "cluster1",
			userGroups:      []string{"admin"},
			targetGroup:     "admin-access",
			expectedCount:   1,
		},
		{
			name:            "wrong target group",
			existingObjects: []client.Object{escalation1, escalation2},
			cluster:         "cluster1",
			userGroups:      []string{"admin"},
			targetGroup:     "user-access",
			expectedCount:   0,
		},
		{
			name:            "wrong cluster",
			existingObjects: []client.Object{escalation1, escalation2},
			cluster:         "cluster2",
			userGroups:      []string{"admin"},
			targetGroup:     "admin-access",
			expectedCount:   0,
		},
		{
			name:            "wrong user groups",
			existingObjects: []client.Object{escalation1, escalation2},
			cluster:         "cluster1",
			userGroups:      []string{"guest"},
			targetGroup:     "admin-access",
			expectedCount:   0,
		},
		{
			name:            "no escalations",
			existingObjects: []client.Object{},
			cluster:         "cluster1",
			userGroups:      []string{"admin"},
			targetGroup:     "admin-access",
			expectedCount:   0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(tt.existingObjects...).
				Build()

			em := breakglass.EscalationManager{Client: fakeClient}

			result, err := em.GetClusterGroupTargetBreakglassEscalation(context.Background(), tt.cluster, tt.userGroups, tt.targetGroup)

			if err != nil {
				t.Errorf("GetClusterGroupTargetBreakglassEscalation() unexpected error: %v", err)
				return
			}

			if len(result) != tt.expectedCount {
				t.Errorf("GetClusterGroupTargetBreakglassEscalation() count = %v, want %v", len(result), tt.expectedCount)
			}
		})
	}
}
