package breakglass_test

import (
	"context"
	"fmt"
	"testing"

	"gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/api/v1alpha1"
	"gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/pkg/breakglass"
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
		Groupname:   "testgroup",
	}
	SampleApproverData = breakglass.ClusterUserGroup{
		Username:    "approver",
		Clustername: SampleCluster,
		Groupname:   "testgroup",
	}
)

func extractGroups(context.Context, breakglass.ClusterUserGroup) ([]string, error) {
	return []string{SampleBaseGroup}, nil
}

func TestFilterForUserPossibleEscalations(t *testing.T) {
	testCases := []struct {
		TestName             string
		Filter               breakglass.EscalationFiltering
		Escalations          []v1alpha1.BreakglassEscalation
		ExpectedOutputGroups []string
		ErrExpected          bool
	}{
		// case 1 simple
		{
			TestName: "Single escalation",
			Filter: breakglass.EscalationFiltering{
				FilterUserData:   SampleUserData,
				UserGroupExtract: extractGroups,
			},

			Escalations: []v1alpha1.BreakglassEscalation{
				{Spec: v1alpha1.BreakglassEscalationSpec{
					Cluster:        SampleUserData.Clustername,
					Username:       SampleUserData.Username,
					AllowedGroups:  []string{SampleBaseGroup},
					EscalatedGroup: SampleEscalationGroup,
					Approvers:      v1alpha1.BreakglassEscalationApprovers{},
				}},
				{Spec: v1alpha1.BreakglassEscalationSpec{
					Cluster:        SampleUserData.Clustername,
					Username:       "other_user",
					AllowedGroups:  []string{SampleBaseGroup},
					EscalatedGroup: SampleEscalationGroup,
					Approvers:      v1alpha1.BreakglassEscalationApprovers{},
				}},
			},
			ExpectedOutputGroups: []string{SampleEscalationGroup},
			ErrExpected:          false,
		},
		// case 2 multiple out escalations
		{
			TestName: "Multiple escalation",
			Filter: breakglass.EscalationFiltering{
				FilterUserData: SampleUserData,
				UserGroupExtract: func(context.Context, breakglass.ClusterUserGroup) ([]string, error) {
					return []string{"other_group"}, nil
				},
			},

			Escalations: []v1alpha1.BreakglassEscalation{
				{Spec: v1alpha1.BreakglassEscalationSpec{
					Cluster:        SampleUserData.Clustername,
					Username:       SampleUserData.Username,
					AllowedGroups:  []string{SampleBaseGroup, "other_group"},
					EscalatedGroup: SampleEscalationGroup,
					Approvers:      v1alpha1.BreakglassEscalationApprovers{},
				}},
				{Spec: v1alpha1.BreakglassEscalationSpec{
					Cluster:        SampleUserData.Clustername,
					Username:       SampleUserData.Username,
					AllowedGroups:  []string{"other_group"},
					EscalatedGroup: "escalation_2",
					Approvers:      v1alpha1.BreakglassEscalationApprovers{},
				}},
				{Spec: v1alpha1.BreakglassEscalationSpec{
					Cluster:        SampleUserData.Clustername,
					Username:       SampleUserData.Username,
					AllowedGroups:  []string{"third_group"},
					EscalatedGroup: SampleEscalationGroup,
					Approvers:      v1alpha1.BreakglassEscalationApprovers{},
				}},
				{Spec: v1alpha1.BreakglassEscalationSpec{
					Cluster:        SampleUserData.Clustername,
					Username:       SampleUserData.Username,
					AllowedGroups:  []string{"other_group", "yet_another"},
					EscalatedGroup: "escalation_3",
					Approvers:      v1alpha1.BreakglassEscalationApprovers{},
				}},
			},
			ExpectedOutputGroups: []string{SampleEscalationGroup, "escalation_2", "escalation_3"},
			ErrExpected:          false,
		},
		// case error
		{
			TestName: "Group extract error",
			Filter: breakglass.EscalationFiltering{
				FilterUserData: SampleUserData,
				UserGroupExtract: func(context.Context, breakglass.ClusterUserGroup) ([]string, error) {
					return []string{}, fmt.Errorf("failed to extract group")
				},
			},

			Escalations: []v1alpha1.BreakglassEscalation{
				{Spec: v1alpha1.BreakglassEscalationSpec{
					Cluster:        SampleUserData.Clustername,
					Username:       SampleUserData.Username,
					AllowedGroups:  []string{SampleBaseGroup},
					EscalatedGroup: SampleEscalationGroup,
					Approvers:      v1alpha1.BreakglassEscalationApprovers{},
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
	testCases := []struct {
		TestName                     string
		Filter                       breakglass.EscalationFiltering
		Escalations                  []v1alpha1.BreakglassEscalation
		InputSessions                []v1alpha1.BreakglassSession
		ExpectedOutputSessionsGroups []string
		ErrExpected                  bool
	}{
		{
			TestName: "User and group based session filter",
			Filter: breakglass.EscalationFiltering{
				FilterUserData: SampleApproverData,
				UserGroupExtract: func(context.Context, breakglass.ClusterUserGroup) ([]string, error) {
					return []string{"admins1"}, nil
				},
			},
			Escalations: []v1alpha1.BreakglassEscalation{
				// test_group -> escalation1 for sample user aprovable by name
				{
					Spec: v1alpha1.BreakglassEscalationSpec{
						Cluster:        SampleApproverData.Clustername,
						Username:       SampleUserData.Username,
						AllowedGroups:  []string{"test_group"},
						EscalatedGroup: "escalation1",
						Approvers: v1alpha1.BreakglassEscalationApprovers{
							Users:  []string{SampleApproverData.Username},
							Groups: []string{},
						},
					},
				},
				// test_group2 -> escalation2 for sample user approvable by group admins1
				{
					Spec: v1alpha1.BreakglassEscalationSpec{
						Cluster:        SampleApproverData.Clustername,
						Username:       SampleUserData.Username,
						AllowedGroups:  []string{"test_group2"},
						EscalatedGroup: "escalation2",
						Approvers: v1alpha1.BreakglassEscalationApprovers{
							Users:  []string{},
							Groups: []string{"admins1"},
						},
					},
				},
				// test_group3 -> escalation3 for sample user approvable by group admins2
				{
					Spec: v1alpha1.BreakglassEscalationSpec{
						Cluster:        SampleApproverData.Clustername,
						Username:       SampleUserData.Username,
						AllowedGroups:  []string{"test_group3"},
						EscalatedGroup: "escalation3",
						Approvers: v1alpha1.BreakglassEscalationApprovers{
							Users:  []string{},
							Groups: []string{"admins2"},
						},
					},
				},
			},
			InputSessions: []v1alpha1.BreakglassSession{
				{
					Spec: v1alpha1.BreakglassSessionSpec{
						Cluster:  SampleApproverData.Clustername,
						Username: SampleUserData.Username,
						Group:    "escalation1",
					},
				},
				{
					Spec: v1alpha1.BreakglassSessionSpec{
						Cluster:  SampleApproverData.Clustername,
						Username: SampleUserData.Username,
						Group:    "escalation10",
					},
				},
				{
					Spec: v1alpha1.BreakglassSessionSpec{
						Cluster:  SampleApproverData.Clustername,
						Username: SampleUserData.Username,
						Group:    "escalation2",
					},
				},
				{
					Spec: v1alpha1.BreakglassSessionSpec{
						Cluster:  SampleApproverData.Clustername,
						Username: SampleUserData.Username,
						Group:    "escalation3",
					},
				},
			},
			ExpectedOutputSessionsGroups: []string{"escalation1", "escalation2"},
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
				if ses.Spec.Group != expectedGroups[i] {
					t.Errorf("Expected to get %q session group as output number %d got %q instead", expectedGroups[i], i, ses.Spec.Group)
				}
			}
		})
	}
}
