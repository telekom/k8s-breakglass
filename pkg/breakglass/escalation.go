package breakglass

import (
	"context"

	"github.com/pkg/errors"
	"gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/api/v1alpha1"
	telekomv1alpha1 "gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/api/v1alpha1"
	"golang.org/x/exp/slices"
)

func FilterForUserPossibleEscalations(ctx context.Context,
	escalations []telekomv1alpha1.BreakglassEscalation,
	cug ClusterUserGroup,
) ([]telekomv1alpha1.BreakglassEscalation, error) {
	userGroups, err := GetUserGroups(ctx, cug)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get user groups")
	}
	groups := make(map[string]any, len(userGroups))
	for _, group := range userGroups {
		groups[group] = struct{}{}
	}

	possible := make([]telekomv1alpha1.BreakglassEscalation, 0, len(escalations))
	for _, esc := range escalations {
		if intersects(groups, esc.Spec.AllowedGroups) {
			possible = append(possible, esc)
		}
	}

	return possible, nil
}

func FilterSessionsForUserApprovable(ctx context.Context,
	userInfo ClusterUserGroup,
	escalations []telekomv1alpha1.BreakglassEscalation,
	sessions []telekomv1alpha1.BreakglassSession,
) ([]telekomv1alpha1.BreakglassSession, error) {
	userGroups, err := GetUserGroups(ctx, userInfo)
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
			if slices.Contains(esc.Spec.Approvers.Users, userInfo.Username) {
				displayable = append(displayable, ses)
			} else if intersects(userCluserGroups, esc.Spec.Approvers.Groups) {
				displayable = append(displayable, ses)
			}
		}
	}
	return displayable, nil
}

func FilterForUserApprovableEscalations(ctx context.Context,
	escalations []telekomv1alpha1.BreakglassEscalation,
	cug ClusterUserGroup,
) ([]telekomv1alpha1.BreakglassEscalation, error) {
	userGroups, err := GetUserGroups(ctx, cug)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get user groups")
	}
	groups := make(map[string]any, len(userGroups))
	for _, group := range userGroups {
		groups[group] = struct{}{}
	}

	approvable := make([]telekomv1alpha1.BreakglassEscalation, 0, len(escalations))
	for _, esc := range escalations {
		if slices.Contains(esc.Spec.Approvers.Users, cug.Username) {
			approvable = append(approvable, esc)
		}
		if intersects(groups, esc.Spec.Approvers.Groups) {
			approvable = append(approvable, esc)
		}
	}

	return approvable, nil
}

func intersects(amap map[string]any, b []string) bool {
	for _, v := range b {
		if _, has := amap[v]; has {
			return true
		}
	}

	return false
}
