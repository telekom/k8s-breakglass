package breakglass_test

import (
	"context"
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

func TestFilterForUserPossibleEscalations(t *testing.T) {
	extract := func(context.Context, breakglass.ClusterUserGroup) ([]string, error) {
		return []string{SampleBaseGroup}, nil
	}
	filter := breakglass.EscalationFiltering{
		FilterUserData:   SampleUserData,
		UserGroupExtract: extract,
	}
	escalations := []v1alpha1.BreakglassEscalation{
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
	}
	out, err := filter.FilterForUserPossibleEscalations(
		context.Background(),
		escalations)
	if err != nil {
		t.Errorf("Expected not to get error Error: %v", err)
	}
	if l := len(out); l != 1 {
		t.Errorf("Expected to get only one escalation after got: %d", l)
	}
}

func TestFilterSessionsForUserApprovable(t *testing.T) {
}
