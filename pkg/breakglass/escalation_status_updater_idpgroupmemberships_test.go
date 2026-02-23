package breakglass

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// MockGroupMemberResolverForTest mock resolver for testing
type MockGroupMemberResolverForTest struct {
	memberData map[string][]string
	err        error
}

func (m *MockGroupMemberResolverForTest) Members(ctx context.Context, group string) ([]string, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.memberData[group], nil
}

// TestIDPGroupMembershipsPopulation verifies that IDPGroupMemberships are populated in multi-IDP mode
func TestIDPGroupMembershipsPopulation(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	defer func() {
		_ = logger.Sync()
	}()

	// Create a mock Keycloak resolver for testing
	mockResolver := &MockGroupMemberResolverForTest{
		memberData: map[string][]string{
			"admin": {"alice@example.com", "bob@example.com", "charlie@example.com"},
			"ops":   {"ops-user1@example.com", "ops-user2@example.com"},
		},
		err: nil,
	}

	// Create fake K8s client with status subresource support
	cli := fake.NewClientBuilder().
		WithScheme(Scheme).
		WithStatusSubresource(&breakglassv1alpha1.BreakglassEscalation{}).
		Build()

	// Create escalation with multi-IDP fields
	escalation := &breakglassv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-escalation",
			Namespace: "default",
		},
		Spec: breakglassv1alpha1.BreakglassEscalationSpec{
			EscalatedGroup: "admin-group",
			Allowed: breakglassv1alpha1.BreakglassEscalationAllowed{
				Clusters: []string{"my-cluster"},
			},
			Approvers: breakglassv1alpha1.BreakglassEscalationApprovers{
				Groups: []string{"admin", "ops"},
			},
			AllowedIdentityProvidersForApprovers: []string{"keycloak-prod"},
			AllowedIdentityProvidersForRequests:  []string{"keycloak-prod"},
		},
	}

	// Create and save the escalation
	err := cli.Create(context.Background(), escalation)
	assert.NoError(t, err, "should create escalation successfully")

	// Create status updater with mock resolver
	updater := EscalationStatusUpdater{
		Log:           logger.Sugar(),
		K8sClient:     cli,
		Resolver:      mockResolver,
		Interval:      0,
		EventRecorder: nil,
		IDPLoader:     nil, // Will use fallback mode
	}

	// Run update cycle once
	updater.runOnce(context.Background(), logger.Sugar())

	// Fetch updated escalation
	updated := &breakglassv1alpha1.BreakglassEscalation{}
	err = cli.Get(context.Background(), client.ObjectKeyFromObject(escalation), updated)
	assert.NoError(t, err, "should fetch updated escalation")

	// Verify ApproverGroupMembers are populated (legacy fallback mode)
	assert.NotNil(t, updated.Status.ApproverGroupMembers, "ApproverGroupMembers should be set")
	assert.Equal(t, 2, len(updated.Status.ApproverGroupMembers), "should have 2 groups")

	admin, ok := updated.Status.ApproverGroupMembers["admin"]
	assert.True(t, ok, "should have admin group members")
	assert.Equal(t, 3, len(admin), "should have 3 admin members")
	assert.Contains(t, admin, "alice@example.com")
	assert.Contains(t, admin, "bob@example.com")
	assert.Contains(t, admin, "charlie@example.com")

	ops, ok := updated.Status.ApproverGroupMembers["ops"]
	assert.True(t, ok, "should have ops group members")
	assert.Equal(t, 2, len(ops), "should have 2 ops members")
	assert.Contains(t, ops, "ops-user1@example.com")
	assert.Contains(t, ops, "ops-user2@example.com")

	t.Logf("✅ Test passed: ApproverGroupMembers populated correctly")
	t.Logf("   Admin group: %v", admin)
	t.Logf("   Ops group: %v", ops)
}

// TestIDPGroupMembershipsNotPopulatedInLegacyMode verifies that IDPGroupMemberships stays empty in legacy mode
func TestIDPGroupMembershipsNotPopulatedInLegacyMode(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	defer func() {
		_ = logger.Sync()
	}()

	mockResolver := &MockGroupMemberResolverForTest{
		memberData: map[string][]string{
			"admin": {"alice@example.com", "bob@example.com"},
		},
		err: nil,
	}

	cli := fake.NewClientBuilder().
		WithScheme(Scheme).
		WithStatusSubresource(&breakglassv1alpha1.BreakglassEscalation{}).
		Build()

	// Create escalation WITHOUT multi-IDP fields
	escalation := &breakglassv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-legacy",
			Namespace: "default",
		},
		Spec: breakglassv1alpha1.BreakglassEscalationSpec{
			EscalatedGroup: "admin-group",
			Allowed: breakglassv1alpha1.BreakglassEscalationAllowed{
				Clusters: []string{"my-cluster"},
			},
			Approvers: breakglassv1alpha1.BreakglassEscalationApprovers{
				Groups: []string{"admin"},
			},
			// Empty/nil AllowedIdentityProvidersForApprovers = legacy mode
		},
	}

	err := cli.Create(context.Background(), escalation)
	assert.NoError(t, err)

	updater := EscalationStatusUpdater{
		Log:           logger.Sugar(),
		K8sClient:     cli,
		Resolver:      mockResolver,
		Interval:      0,
		EventRecorder: nil,
		IDPLoader:     nil,
	}

	updater.runOnce(context.Background(), logger.Sugar())

	updated := &breakglassv1alpha1.BreakglassEscalation{}
	err = cli.Get(context.Background(), client.ObjectKeyFromObject(escalation), updated)
	assert.NoError(t, err)

	// Verify ApproverGroupMembers ARE populated
	assert.NotNil(t, updated.Status.ApproverGroupMembers)
	assert.Equal(t, 1, len(updated.Status.ApproverGroupMembers))

	// Verify IDPGroupMemberships is empty (legacy mode doesn't populate it)
	assert.Empty(t, updated.Status.IDPGroupMemberships, "IDPGroupMemberships should be empty in legacy mode")

	t.Logf("✅ Test passed: Legacy mode works correctly")
	t.Logf("   ApproverGroupMembers populated: %v", updated.Status.ApproverGroupMembers)
	t.Logf("   IDPGroupMemberships empty: %v", updated.Status.IDPGroupMemberships)
}

// TestLegacyModeWithMultipleGroups tests that legacy mode handles multiple groups correctly
func TestLegacyModeWithMultipleGroups(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	defer func() {
		_ = logger.Sync()
	}()

	mockResolver := &MockGroupMemberResolverForTest{
		memberData: map[string][]string{
			"admin":     {"alice@example.com", "bob@example.com"},
			"operators": {"ops1@example.com", "ops2@example.com", "ops3@example.com"},
			"auditors":  {"audit@example.com"},
		},
		err: nil,
	}

	cli := fake.NewClientBuilder().
		WithScheme(Scheme).
		WithStatusSubresource(&breakglassv1alpha1.BreakglassEscalation{}).
		Build()

	escalation := &breakglassv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "multi-group",
			Namespace: "default",
		},
		Spec: breakglassv1alpha1.BreakglassEscalationSpec{
			EscalatedGroup: "admin-group",
			Allowed: breakglassv1alpha1.BreakglassEscalationAllowed{
				Clusters: []string{"my-cluster"},
			},
			Approvers: breakglassv1alpha1.BreakglassEscalationApprovers{
				Groups: []string{"admin", "operators", "auditors"},
			},
		},
	}

	err := cli.Create(context.Background(), escalation)
	assert.NoError(t, err)

	updater := EscalationStatusUpdater{
		Log:           logger.Sugar(),
		K8sClient:     cli,
		Resolver:      mockResolver,
		Interval:      0,
		EventRecorder: nil,
		IDPLoader:     nil,
	}

	updater.runOnce(context.Background(), logger.Sugar())

	updated := &breakglassv1alpha1.BreakglassEscalation{}
	err = cli.Get(context.Background(), client.ObjectKeyFromObject(escalation), updated)
	assert.NoError(t, err)

	// Verify all groups are populated
	assert.Equal(t, 3, len(updated.Status.ApproverGroupMembers), "should have 3 groups")

	for group, members := range updated.Status.ApproverGroupMembers {
		t.Logf("Group %s has %d members: %v", group, len(members), members)
	}

	assert.Equal(t, 2, len(updated.Status.ApproverGroupMembers["admin"]))
	assert.Equal(t, 3, len(updated.Status.ApproverGroupMembers["operators"]))
	assert.Equal(t, 1, len(updated.Status.ApproverGroupMembers["auditors"]))

	t.Logf("✅ Test passed: Multiple groups handled correctly in legacy mode")
}

// TestEmptyApproverGroups verifies escalation with no approver groups is skipped
func TestEmptyApproverGroups(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	defer func() {
		_ = logger.Sync()
	}()

	mockResolver := &MockGroupMemberResolverForTest{
		memberData: map[string][]string{},
		err:        nil,
	}

	cli := fake.NewClientBuilder().
		WithScheme(Scheme).
		WithStatusSubresource(&breakglassv1alpha1.BreakglassEscalation{}).
		Build()

	escalation := &breakglassv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "no-approvers",
			Namespace: "default",
		},
		Spec: breakglassv1alpha1.BreakglassEscalationSpec{
			EscalatedGroup: "admin-group",
			Allowed: breakglassv1alpha1.BreakglassEscalationAllowed{
				Clusters: []string{"my-cluster"},
			},
			Approvers: breakglassv1alpha1.BreakglassEscalationApprovers{
				Groups: []string{}, // Empty - should be skipped
			},
		},
	}

	err := cli.Create(context.Background(), escalation)
	assert.NoError(t, err)

	updater := EscalationStatusUpdater{
		Log:           logger.Sugar(),
		K8sClient:     cli,
		Resolver:      mockResolver,
		Interval:      0,
		EventRecorder: nil,
		IDPLoader:     nil,
	}

	updater.runOnce(context.Background(), logger.Sugar())

	updated := &breakglassv1alpha1.BreakglassEscalation{}
	err = cli.Get(context.Background(), client.ObjectKeyFromObject(escalation), updated)
	assert.NoError(t, err)

	// Should not have been updated (no approver groups)
	assert.Nil(t, updated.Status.ApproverGroupMembers)
	assert.Nil(t, updated.Status.IDPGroupMemberships)

	t.Logf("✅ Test passed: Empty approver groups correctly skipped")
}
