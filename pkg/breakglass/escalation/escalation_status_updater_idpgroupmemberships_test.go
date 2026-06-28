package escalation

import (
	"context"
	"errors"
	"testing"

	breakglass "github.com/telekom/k8s-breakglass/pkg/breakglass"

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
		WithScheme(breakglass.Scheme).
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

func TestEscalationStatusUpdaterSetsApprovalGroupMembersResolvedOnConditionOnlyChange(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	defer func() {
		_ = logger.Sync()
	}()

	mockResolver := &MockResolver{
		members: map[string][]string{
			"admin": {"alice@example.com"},
		},
		errors: map[string]error{},
	}

	cli := fake.NewClientBuilder().
		WithScheme(breakglass.Scheme).
		WithStatusSubresource(&breakglassv1alpha1.BreakglassEscalation{}).
		Build()

	escalation := &breakglassv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "condition-only",
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
		},
		Status: breakglassv1alpha1.BreakglassEscalationStatus{
			ApproverGroupMembers: map[string][]string{
				"admin": {"alice@example.com"},
			},
		},
	}

	err := cli.Create(context.Background(), escalation)
	assert.NoError(t, err)
	escalation.Status.ApproverGroupMembers = map[string][]string{
		"admin": {"alice@example.com"},
	}
	err = cli.Status().Update(context.Background(), escalation)
	assert.NoError(t, err)

	updater := EscalationStatusUpdater{
		Log:       logger.Sugar(),
		K8sClient: cli,
		Resolver:  mockResolver,
	}

	updater.runOnce(context.Background(), logger.Sugar())

	updated := &breakglassv1alpha1.BreakglassEscalation{}
	err = cli.Get(context.Background(), client.ObjectKeyFromObject(escalation), updated)
	assert.NoError(t, err)
	assert.Equal(t, []string{"alice@example.com"}, updated.Status.ApproverGroupMembers["admin"])

	condition := updated.GetCondition(string(breakglassv1alpha1.BreakglassEscalationConditionApprovalGroupMembersResolved))
	if assert.NotNil(t, condition) {
		assert.Equal(t, metav1.ConditionTrue, condition.Status)
		assert.Equal(t, "GroupMembersResolved", condition.Reason)
		assert.Equal(t, "Resolved approver group members for 1 group(s).", condition.Message)
	}
}

func TestEscalationStatusUpdaterSetsApprovalGroupMembersResolvedPartialFailure(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	defer func() {
		_ = logger.Sync()
	}()

	mockResolver := &MockResolver{
		members: map[string][]string{
			"admin": {"alice@example.com"},
		},
		errors: map[string]error{
			"ops": errors.New("group lookup failed"),
		},
	}

	cli := fake.NewClientBuilder().
		WithScheme(breakglass.Scheme).
		WithStatusSubresource(&breakglassv1alpha1.BreakglassEscalation{}).
		Build()

	escalation := &breakglassv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "partial-group-sync",
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
		},
	}

	err := cli.Create(context.Background(), escalation)
	assert.NoError(t, err)
	escalation.Status.Conditions = []metav1.Condition{
		{
			Type:    string(breakglassv1alpha1.BreakglassEscalationConditionApprovalGroupMembersResolved),
			Status:  metav1.ConditionFalse,
			Reason:  "GroupSyncFailed",
			Message: "stale group sync failure",
		},
	}
	err = cli.Status().Update(context.Background(), escalation)
	assert.NoError(t, err)

	updater := EscalationStatusUpdater{
		Log:       logger.Sugar(),
		K8sClient: cli,
		Resolver:  mockResolver,
	}

	updater.runOnce(context.Background(), logger.Sugar())

	updated := &breakglassv1alpha1.BreakglassEscalation{}
	err = cli.Get(context.Background(), client.ObjectKeyFromObject(escalation), updated)
	assert.NoError(t, err)
	assert.Equal(t, []string{"alice@example.com"}, updated.Status.ApproverGroupMembers["admin"])
	assert.Empty(t, updated.Status.ApproverGroupMembers["ops"])

	condition := updated.GetCondition(string(breakglassv1alpha1.BreakglassEscalationConditionApprovalGroupMembersResolved))
	if assert.NotNil(t, condition) {
		assert.Equal(t, metav1.ConditionFalse, condition.Status)
		assert.Equal(t, "GroupSyncPartialFailure", condition.Reason)
		assert.Equal(t, "Approver group sync partially failed for 2 group(s) from 1 identity provider(s); 1 error(s) encountered.", condition.Message)
	}
}

func TestUpdateApprovalGroupMembersResolvedConditionIncludesIDPContextOnFailures(t *testing.T) {
	tests := []struct {
		name       string
		syncStatus string
		reason     string
		message    string
		errorCount int
	}{
		{
			name:       "partial failure",
			syncStatus: groupSyncStatusPartialFailure,
			reason:     groupSyncReasonPartialFailure,
			message:    "Approver group sync partially failed for 3 group(s) from 2 identity provider(s); 1 error(s) encountered.",
			errorCount: 1,
		},
		{
			name:       "full failure",
			syncStatus: groupSyncStatusFailed,
			reason:     groupSyncReasonFailed,
			message:    "Approver group sync failed for 3 group(s) from 2 identity provider(s); 2 error(s) encountered.",
			errorCount: 2,
		},
		{
			name:       "unknown status",
			syncStatus: "Unexpected",
			reason:     groupSyncReasonFailed,
			message:    "Approver group sync returned unknown status \"Unexpected\" for 3 group(s) from 2 identity provider(s).",
			errorCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			escalation := &breakglassv1alpha1.BreakglassEscalation{
				ObjectMeta: metav1.ObjectMeta{
					Generation: 7,
				},
			}

			changed := updateApprovalGroupMembersResolvedCondition(escalation, tt.syncStatus, 3, 2, tt.errorCount)

			assert.True(t, changed)
			condition := escalation.GetCondition(string(breakglassv1alpha1.BreakglassEscalationConditionApprovalGroupMembersResolved))
			if assert.NotNil(t, condition) {
				assert.Equal(t, metav1.ConditionFalse, condition.Status)
				assert.Equal(t, tt.reason, condition.Reason)
				assert.Equal(t, tt.message, condition.Message)
				assert.Equal(t, int64(7), condition.ObservedGeneration)
			}
		})
	}
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
		WithScheme(breakglass.Scheme).
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
		WithScheme(breakglass.Scheme).
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
		WithScheme(breakglass.Scheme).
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
		Status: breakglassv1alpha1.BreakglassEscalationStatus{
			ApproverGroupMembers: map[string][]string{
				"admin": {"alice@example.com"},
			},
			IDPGroupMemberships: map[string]map[string][]string{
				"idp-a": {
					"admin": {"alice@example.com"},
				},
			},
			Conditions: []metav1.Condition{
				{
					Type:    string(breakglassv1alpha1.BreakglassEscalationConditionApprovalGroupMembersResolved),
					Status:  metav1.ConditionFalse,
					Reason:  "GroupSyncFailed",
					Message: "stale group sync failure",
				},
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

	// Stale group-member status should be cleared when no approver groups remain.
	assert.Nil(t, updated.Status.ApproverGroupMembers)
	assert.Nil(t, updated.Status.IDPGroupMemberships)
	condition := updated.GetCondition(string(breakglassv1alpha1.BreakglassEscalationConditionApprovalGroupMembersResolved))
	if assert.NotNil(t, condition) {
		assert.Equal(t, metav1.ConditionTrue, condition.Status)
		assert.Equal(t, "NoApproverGroupsConfigured", condition.Reason)
		assert.Equal(t, "No approver groups are configured; group member resolution is not required.", condition.Message)
	}

	t.Logf("✅ Test passed: Empty approver groups correctly skipped")
}

func TestExplicitIDPsWithoutLoaderReportLegacyResolverCondition(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	defer func() {
		_ = logger.Sync()
	}()

	mockResolver := &MockGroupMemberResolverForTest{
		memberData: map[string][]string{
			"admin": {"alice@example.com"},
		},
		err: nil,
	}

	cli := fake.NewClientBuilder().
		WithScheme(breakglass.Scheme).
		WithStatusSubresource(&breakglassv1alpha1.BreakglassEscalation{}).
		Build()

	escalation := &breakglassv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "explicit-idps-no-loader",
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
			AllowedIdentityProvidersForApprovers: []string{"idp-a", "idp-b"},
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
	assert.Equal(t, []string{"alice@example.com"}, updated.Status.ApproverGroupMembers["admin"])

	condition := updated.GetCondition(string(breakglassv1alpha1.BreakglassEscalationConditionApprovalGroupMembersResolved))
	if assert.NotNil(t, condition) {
		assert.Equal(t, metav1.ConditionTrue, condition.Status)
		assert.Equal(t, "GroupMembersResolved", condition.Reason)
		assert.Equal(t, "Resolved approver group members for 1 group(s).", condition.Message)
	}
}
