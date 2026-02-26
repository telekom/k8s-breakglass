package escalation_test

import (
	"context"
	"fmt"
	"testing"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	breakglass "github.com/telekom/k8s-breakglass/pkg/breakglass"
	"github.com/telekom/k8s-breakglass/pkg/breakglass/escalation"
	"go.uber.org/zap"
)

const (
	SampleBaseGroup       = "system:authenticated"
	SampleEscalationGroup = "breakglass-create-all"
	SampleCluster         = "test"
)

var (
	SampleUserData = breakglass.ClusterUserGroup{
		Username:    "test",
		Clustername: SampleCluster,
		GroupName:   "testgroup",
	}
	SampleApproverData = breakglass.ClusterUserGroup{
		Username:    "approver",
		Clustername: SampleCluster,
		GroupName:   "testgroup",
	}
	testLogger = zap.NewNop().Sugar() // No-op logger for tests
)

func extractGroups(context.Context, breakglass.ClusterUserGroup) ([]string, error) {
	return []string{SampleBaseGroup}, nil
}

func TestFilterForUserPossibleEscalations(t *testing.T) {
	// TestFilterForUserPossibleEscalations
	//
	// Purpose:
	//   Verifies that EscalationFiltering.FilterForUserPossibleEscalations returns
	//   only those escalations that are applicable for the provided user context.
	//
	// Reasoning:
	//   The system must present only eligible escalation targets to a user based
	//   on their cluster membership and token groups. This test covers simple
	//   positive cases, selection from multiple escalations, and an extraction error
	//   path to ensure error propagation.
	//
	// Flow pattern:
	//   - For each test case a Filter object is prepared with a fake group-extractor
	//     and sample user data.
	//   - A slice of escalation objects describes allowed clusters/groups and
	//     escalated groups.
	//   - Call FilterForUserPossibleEscalations and assert:
	//       * function returns expected escalations in order/quantity
	//       * errors occur when group extraction fails
	//
	testCases := []struct {
		TestName             string
		Filter               escalation.EscalationFiltering
		Escalations          []breakglassv1alpha1.BreakglassEscalation
		ExpectedOutputGroups []string
		ErrExpected          bool
	}{
		// case 1 simple
		{
			TestName: "Single escalation",
			Filter: escalation.EscalationFiltering{
				Log:              testLogger,
				FilterUserData:   SampleUserData,
				UserGroupExtract: extractGroups,
			},

			Escalations: []breakglassv1alpha1.BreakglassEscalation{
				{Spec: breakglassv1alpha1.BreakglassEscalationSpec{
					Allowed: breakglassv1alpha1.BreakglassEscalationAllowed{
						Clusters: []string{SampleUserData.Clustername},
						Groups:   []string{SampleBaseGroup},
					},
					EscalatedGroup: SampleEscalationGroup,
					Approvers:      breakglassv1alpha1.BreakglassEscalationApprovers{},
				}},
				{Spec: breakglassv1alpha1.BreakglassEscalationSpec{
					Allowed: breakglassv1alpha1.BreakglassEscalationAllowed{
						Clusters: []string{SampleUserData.Clustername},
						Groups:   []string{SampleBaseGroup},
					},
					EscalatedGroup: SampleEscalationGroup,
					Approvers:      breakglassv1alpha1.BreakglassEscalationApprovers{},
				}},
			},
			ExpectedOutputGroups: []string{SampleEscalationGroup, SampleEscalationGroup},
			ErrExpected:          false,
		},
		// case 2 multiple out escalations
		{
			TestName: "Multiple escalation",
			Filter: escalation.EscalationFiltering{
				Log:            testLogger,
				FilterUserData: SampleUserData,
				UserGroupExtract: func(context.Context, breakglass.ClusterUserGroup) ([]string, error) {
					return []string{"other_group"}, nil
				},
			},

			Escalations: []breakglassv1alpha1.BreakglassEscalation{
				{Spec: breakglassv1alpha1.BreakglassEscalationSpec{
					Allowed: breakglassv1alpha1.BreakglassEscalationAllowed{
						Clusters: []string{SampleUserData.Clustername},
						Groups:   []string{SampleBaseGroup, "other_group"},
					},
					EscalatedGroup: SampleEscalationGroup,
					Approvers:      breakglassv1alpha1.BreakglassEscalationApprovers{},
				}},
				{Spec: breakglassv1alpha1.BreakglassEscalationSpec{
					Allowed: breakglassv1alpha1.BreakglassEscalationAllowed{
						Clusters: []string{SampleUserData.Clustername},
						Groups:   []string{"other_group"},
					},
					EscalatedGroup: "escalation_2",
					Approvers:      breakglassv1alpha1.BreakglassEscalationApprovers{},
				}},
				{Spec: breakglassv1alpha1.BreakglassEscalationSpec{
					Allowed: breakglassv1alpha1.BreakglassEscalationAllowed{
						Clusters: []string{SampleUserData.Clustername},
						Groups:   []string{"third_group"},
					},
					EscalatedGroup: SampleEscalationGroup,
					Approvers:      breakglassv1alpha1.BreakglassEscalationApprovers{},
				}},
				{Spec: breakglassv1alpha1.BreakglassEscalationSpec{
					Allowed: breakglassv1alpha1.BreakglassEscalationAllowed{
						Clusters: []string{SampleUserData.Clustername},
						Groups:   []string{"other_group", "yet_another"},
					},
					EscalatedGroup: "escalation_3",
					Approvers:      breakglassv1alpha1.BreakglassEscalationApprovers{},
				}},
			},
			ExpectedOutputGroups: []string{SampleEscalationGroup, "escalation_2", "escalation_3"},
			ErrExpected:          false,
		},
		// case error
		{
			TestName: "GrantedGroup extract error",
			Filter: escalation.EscalationFiltering{
				Log:            testLogger,
				FilterUserData: SampleUserData,
				UserGroupExtract: func(context.Context, breakglass.ClusterUserGroup) ([]string, error) {
					return []string{}, fmt.Errorf("failed to extract group")
				},
			},

			Escalations: []breakglassv1alpha1.BreakglassEscalation{
				{Spec: breakglassv1alpha1.BreakglassEscalationSpec{
					Allowed: breakglassv1alpha1.BreakglassEscalationAllowed{
						Clusters: []string{SampleUserData.Clustername},
						Groups:   []string{SampleBaseGroup},
					},
					EscalatedGroup: SampleEscalationGroup,
					Approvers:      breakglassv1alpha1.BreakglassEscalationApprovers{},
				}},
			},
			ExpectedOutputGroups: []string{},
			ErrExpected:          true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.TestName, func(t *testing.T) {
			filter := testCase.Filter
			escalations := testCase.Escalations
			expected := testCase.ExpectedOutputGroups
			out, err := filter.FilterForUserPossibleEscalations(
				context.Background(),
				escalations)

			if err != nil && !testCase.ErrExpected {
				t.Errorf("Expected not to get error Error: %v", err)
			} else if err == nil && testCase.ErrExpected {
				t.Error("Expected to get error, but go nil")
			}

			if testCase.ErrExpected {
				return
			}

			if l := len(out); l != len(expected) {
				t.Errorf("Expected to get %d escalation after filtering got: %d", len(expected), l)
			}

			for i, escal := range out {
				if escal.Spec.EscalatedGroup != expected[i] {
					t.Errorf("Expected to get %q escalation group as output number %d got %q instead", expected[i], i, escal.Spec.EscalatedGroup)
				}
			}
		})
	}
}

func TestFilterSessionsForUserApprovable(t *testing.T) {
	// TestFilterSessionsForUserApprovable
	//
	// Purpose:
	//   Ensures EscalationFiltering.FilterSessionsForUserApprovable filters an input
	//   list of BreakglassSession objects down to sessions that the current user
	//   may approve (either by username or by membership in approver groups).
	//
	// Reasoning:
	//   Approvers may be specified directly (users) or via groups. The controller
	//   must match sessions against escalations and the approver identity to
	//   surface only approvable sessions. The test covers:
	//     - direct user-based approval
	//     - group-based approval
	//     - empty escalation list returns nothing
	//
	// Flow pattern:
	//   - Construct a Filter with a get-groups function returning test groups.
	//   - Create escalation specs mapping groups to escalated groups and approvers.
	//   - Create sessions with various granted groups and cluster values.
	//   - Call FilterSessionsForUserApprovable and assert the returned sessions
	//     contain exactly the expected GrantedGroup names and count.
	//
	testCases := []struct {
		TestName                     string
		Filter                       escalation.EscalationFiltering
		Escalations                  []breakglassv1alpha1.BreakglassEscalation
		InputSessions                []breakglassv1alpha1.BreakglassSession
		ExpectedOutputSessionsGroups []string
		ErrExpected                  bool
	}{
		// Case 1 - check for filtering based on approver name and belonging group
		{
			TestName: "User and group based session filter",
			Filter: escalation.EscalationFiltering{
				Log:            testLogger,
				FilterUserData: SampleApproverData,
				UserGroupExtract: func(context.Context, breakglass.ClusterUserGroup) ([]string, error) {
					return []string{"admins1"}, nil
				},
			},
			Escalations: []breakglassv1alpha1.BreakglassEscalation{
				// test_group -> escalation1 for sample user aprovable by name
				{
					Spec: breakglassv1alpha1.BreakglassEscalationSpec{
						Allowed: breakglassv1alpha1.BreakglassEscalationAllowed{
							Clusters: []string{SampleUserData.Clustername},
							Groups:   []string{"test_group"},
						},
						EscalatedGroup: "escalation1",
						Approvers: breakglassv1alpha1.BreakglassEscalationApprovers{
							Users:  []string{SampleApproverData.Username},
							Groups: []string{},
						},
					},
				},
				// test_group2 -> escalation2 for sample user approvable by group admins1
				{
					Spec: breakglassv1alpha1.BreakglassEscalationSpec{
						Allowed: breakglassv1alpha1.BreakglassEscalationAllowed{
							Clusters: []string{SampleUserData.Clustername},
							Groups:   []string{"test_group2"},
						},
						EscalatedGroup: "escalation2",
						Approvers: breakglassv1alpha1.BreakglassEscalationApprovers{
							Users:  []string{},
							Groups: []string{"admins1"},
						},
					},
				},
				// test_group3 -> escalation3 for sample user approvable by group admins2
				{
					Spec: breakglassv1alpha1.BreakglassEscalationSpec{
						Allowed: breakglassv1alpha1.BreakglassEscalationAllowed{
							Clusters: []string{SampleApproverData.Clustername},
							Groups:   []string{"test_group3"},
						},
						EscalatedGroup: "escalation3",
						Approvers: breakglassv1alpha1.BreakglassEscalationApprovers{
							Users:  []string{},
							Groups: []string{"admins2"},
						},
					},
				},
			},
			InputSessions: []breakglassv1alpha1.BreakglassSession{
				{
					Spec: breakglassv1alpha1.BreakglassSessionSpec{
						Cluster:      SampleApproverData.Clustername,
						User:         SampleUserData.Username,
						GrantedGroup: "escalation1",
					},
				},
				{
					Spec: breakglassv1alpha1.BreakglassSessionSpec{
						Cluster:      SampleApproverData.Clustername,
						User:         SampleUserData.Username,
						GrantedGroup: "escalation10",
					},
				},
				{
					Spec: breakglassv1alpha1.BreakglassSessionSpec{
						Cluster:      SampleApproverData.Clustername,
						User:         SampleUserData.Username,
						GrantedGroup: "escalation2",
					},
				},
				{
					Spec: breakglassv1alpha1.BreakglassSessionSpec{
						Cluster:      SampleApproverData.Clustername,
						User:         SampleUserData.Username,
						GrantedGroup: "escalation3",
					},
				},
			},
			ExpectedOutputSessionsGroups: []string{"escalation1", "escalation2"},
		},
		// Case 2 - make sure no escalations does not return all sessions
		{
			TestName: "Empty escalations return no session",
			Filter: escalation.EscalationFiltering{
				Log:            testLogger,
				FilterUserData: SampleApproverData,
				UserGroupExtract: func(context.Context, breakglass.ClusterUserGroup) ([]string, error) {
					return []string{"admins1"}, nil
				},
			},
			Escalations: []breakglassv1alpha1.BreakglassEscalation{},
			InputSessions: []breakglassv1alpha1.BreakglassSession{
				{
					Spec: breakglassv1alpha1.BreakglassSessionSpec{
						Cluster:      SampleApproverData.Clustername,
						User:         SampleUserData.Username,
						GrantedGroup: "escalation1",
					},
				},
				{
					Spec: breakglassv1alpha1.BreakglassSessionSpec{
						Cluster:      SampleApproverData.Clustername,
						User:         SampleUserData.Username,
						GrantedGroup: "escalation10",
					},
				},
				{
					Spec: breakglassv1alpha1.BreakglassSessionSpec{
						Cluster:      SampleApproverData.Clustername,
						User:         SampleUserData.Username,
						GrantedGroup: "escalation2",
					},
				},
				{
					Spec: breakglassv1alpha1.BreakglassSessionSpec{
						Cluster:      SampleApproverData.Clustername,
						User:         SampleUserData.Username,
						GrantedGroup: "escalation3",
					},
				},
			},
			ExpectedOutputSessionsGroups: []string{},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.TestName, func(t *testing.T) {
			filter := testCase.Filter
			insessions := testCase.InputSessions
			inescalations := testCase.Escalations
			expectedGroups := testCase.ExpectedOutputSessionsGroups

			sessions, err := filter.FilterSessionsForUserApprovable(context.Background(),
				insessions,
				inescalations,
			)

			if err != nil && !testCase.ErrExpected {
				t.Errorf("Expected not to get error Error: %v", err)
			} else if err == nil && testCase.ErrExpected {
				t.Error("Expected to get error, but go nil")
			}

			if testCase.ErrExpected {
				return
			}

			if l := len(sessions); l != len(expectedGroups) {
				t.Errorf("Expected to get %d sessions after filtering got: %d", len(expectedGroups), l)
			}
			for i, ses := range sessions {
				if ses.Spec.GrantedGroup != expectedGroups[i] {
					t.Errorf("Expected to get %q session group as output number %d got %q instead", expectedGroups[i], i, ses.Spec.GrantedGroup)
				}
			}
		})
	}
}
