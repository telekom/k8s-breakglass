package breakglass

import (
	"context"

	"github.com/pkg/errors"
	"gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/api/v1alpha1"
	telekomv1alpha1 "gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/api/v1alpha1"
	"golang.org/x/exp/slices"
)

// EscalationFiltering filters given breakglass escalations and sessions based on user their definition
// compared with user assigned groups.
// User assigned groups are extracted using injected function which probably corresponds to `kubectl auth whoami`.
type EscalationFiltering struct {
	FilterUserData   ClusterUserGroup
	UserGroupExtract func(context.Context, ClusterUserGroup) ([]string, error)
}

// FilterForUserPossibleEscalations filters provided escalations for those that are available based on user assigned
// extractable groups.
func (ef EscalationFiltering) FilterForUserPossibleEscalations(ctx context.Context,
	escalations []telekomv1alpha1.BreakglassEscalation,
) ([]telekomv1alpha1.BreakglassEscalation, error) {
	userGroups, err := ef.UserGroupExtract(ctx, ef.FilterUserData)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get user groups")
	}
	groups := make(map[string]any, len(userGroups))
	for _, group := range userGroups {
		groups[group] = struct{}{}
	}

	isEscalationForUser := func(esc telekomv1alpha1.BreakglassEscalation) bool {
		return esc.Spec.Cluster == ef.FilterUserData.Clustername &&
			esc.Spec.Username == ef.FilterUserData.Username
	}

	possible := make([]telekomv1alpha1.BreakglassEscalation, 0, len(escalations))
	for _, esc := range escalations {
		if isEscalationForUser(esc) &&
			intersects(groups, esc.Spec.AllowedGroups) {
			possible = append(possible, esc)
		}
	}

	return possible, nil
}

// FilterSessionsForUserApprovable filters sessions for the ones that filter user
// could approve, based on provided escalations joined with user extracted groups.
func (ef EscalationFiltering) FilterSessionsForUserApprovable(ctx context.Context,
	sessions []telekomv1alpha1.BreakglassSession,
	escalations []telekomv1alpha1.BreakglassEscalation,
) ([]telekomv1alpha1.BreakglassSession, error) {
	userGroups, err := ef.UserGroupExtract(ctx, ef.FilterUserData)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get user rbac cluster groups")
	}
	userCluserGroups := map[string]any{}
	for _, g := range userGroups {
		userCluserGroups[g] = struct{}{}
	}

	displayable := []v1alpha1.BreakglassSession{}

	for _, ses := range sessions {
		for _, esc := range escalations {
			if ses.Spec.Group != esc.Spec.EscalatedGroup ||
				ses.Spec.Cluster != esc.Spec.Cluster {
				continue
			}

			if slices.Contains(esc.Spec.Approvers.Users, ef.FilterUserData.Username) {
				displayable = append(displayable, ses)
				break
			} else if intersects(userCluserGroups, esc.Spec.Approvers.Groups) {
				displayable = append(displayable, ses)
				break
			}
		}
	}
	return displayable, nil
}

func intersects(amap map[string]any, b []string) bool {
	for _, v := range b {
		if _, has := amap[v]; has {
			return true
		}
	}

	return false
}
