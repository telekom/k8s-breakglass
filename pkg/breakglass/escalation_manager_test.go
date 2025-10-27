package breakglass_test

import (
	"context"
	"testing"

	telekomv1alpha1 "gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/api/v1alpha1"
	"gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/pkg/breakglass"
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
