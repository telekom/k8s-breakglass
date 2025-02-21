package breakglass

import (
	"context"

	"github.com/pkg/errors"
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

// func FilterSessionsForUserApprovable(ctx context.Context,
// 	sessions []telekomv1alpha1.BreakglassSession,
// 	escalations []telekomv1alpha1.BreakglassEscalation,
// 	cug ClusterUserGroup,
// ) ([]telekomv1alpha1.BreakglassSession, error) {
// 	userGroups, err := GetUserGroups(ctx, cug)
// 	if err != nil {
// 		return nil, errors.Wrap(err, "failed to get user groups")
// 	}
// 	for _, es := range escalations {
//     if slices.Contains(es.Spec.Approvers.Groups,
//     // if es.Spec.Approvers.Groups
// 	}
// 	fmt.Println(userGroups)
// 	return nil, nil
// }

func intersects(amap map[string]any, b []string) bool {
	for _, v := range b {
		if _, has := amap[v]; has {
			return true
		}
	}

	return false
}
