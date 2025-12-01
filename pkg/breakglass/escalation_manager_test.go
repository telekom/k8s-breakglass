package breakglass_test

import (
	"context"
	"testing"

	telekomv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/breakglass"
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
	//
	scheme := breakglass.Scheme

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()

	em := breakglass.NewEscalationManagerWithClient(fakeClient, nil)

	if em.Client == nil {
		t.Error("NewEscalationManagerWithClient() returned nil client")
	}
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

		err := em.UpdateBreakglassEscalationStatus(context.Background(), *escalation)
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
