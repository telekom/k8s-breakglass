package breakglass

import (
	"context"

	"github.com/pkg/errors"
	telekomv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"go.uber.org/zap"
	"golang.org/x/exp/slices"

	"github.com/telekom/k8s-breakglass/pkg/config"
)

// EscalationFiltering filters given breakglass escalations and sessions based on user their definition
// compared with user assigned groups.
// User assigned groups are extracted using injected function which probably corresponds to `kubectl auth whoami`.
type EscalationFiltering struct {
	Log              *zap.SugaredLogger
	FilterUserData   ClusterUserGroup
	UserGroupExtract func(context.Context, ClusterUserGroup) ([]string, error)
}

// FilterForUserPossibleEscalations filters provided escalations for those that are available based on user assigned
// extractable groups.
func (ef EscalationFiltering) FilterForUserPossibleEscalations(ctx context.Context,
	escalations []telekomv1alpha1.BreakglassEscalation,
) ([]telekomv1alpha1.BreakglassEscalation, error) {
	ef.Log.Debugw("Filtering for user possible escalations", "user", ef.FilterUserData.Username, "cluster", ef.FilterUserData.Clustername, "escalationCount", len(escalations))
	userGroups, err := ef.UserGroupExtract(ctx, ef.FilterUserData)
	if err != nil {
		ef.Log.Errorw("Failed to get user groups for escalation filtering", "error", err)
		return nil, errors.Wrap(err, "failed to get user groups")
	}
	ef.Log.Debugw("Retrieved user groups for escalation filtering", "userGroups", userGroups)
	// Load config to determine OIDC prefixes for normalization
	var oidcPrefixes []string
	if cfg, errCfg := config.Load(); errCfg == nil && len(cfg.Kubernetes.OIDCPrefixes) > 0 {
		oidcPrefixes = cfg.Kubernetes.OIDCPrefixes
		// Normalize user groups (strip prefixes if configured)
		userGroups = stripOIDCPrefixes(userGroups, oidcPrefixes)
		ef.Log.Debugw("Normalized user groups with OIDC prefixes", "originalUserGroups", userGroups, "oidcPrefixes", oidcPrefixes)
	}

	groups := make(map[string]any, len(userGroups))
	for _, group := range userGroups {
		groups[group] = struct{}{}
	}

	isEscalationForUser := func(esc telekomv1alpha1.BreakglassEscalation) bool {
		clusterMatch := clusterMatchesPatterns(ef.FilterUserData.Clustername, esc.Spec.Allowed.Clusters)
		ef.Log.Debugw("Checking cluster match for escalation", "escalation", esc.Name, "requiredClusters", esc.Spec.Allowed.Clusters, "userCluster", ef.FilterUserData.Clustername, "clusterMatch", clusterMatch)
		return clusterMatch
	}

	possible := make([]telekomv1alpha1.BreakglassEscalation, 0, len(escalations))
	for _, esc := range escalations {
		// Normalize escalation allowed groups the same way as user groups for fair comparison
		normalizedAllowedGroups := esc.Spec.Allowed.Groups
		if len(oidcPrefixes) > 0 {
			normalizedAllowedGroups = stripOIDCPrefixes(normalizedAllowedGroups, oidcPrefixes)
		}
		clusterEligible := isEscalationForUser(esc)
		groupEligible := intersects(groups, normalizedAllowedGroups)

		ef.Log.Debugw("Evaluating escalation eligibility",
			"escalation", esc.Name,
			"clusterEligible", clusterEligible,
			"groupEligible", groupEligible,
			"requiredGroups", esc.Spec.Allowed.Groups,
			"normalizedRequiredGroups", normalizedAllowedGroups,
			"userGroups", userGroups)

		if clusterEligible && groupEligible {
			ef.Log.Debugw("Escalation is possible for user", "escalation", esc.Name)
			possible = append(possible, esc)
		} else {
			ef.Log.Debugw("Escalation not possible for user",
				"escalation", esc.Name,
				"clusterEligible", clusterEligible,
				"groupEligible", groupEligible)
		}
	}

	ef.Log.Infow("Filtered possible escalations", "possibleCount", len(possible))
	return possible, nil
}

// FilterSessionsForUserApprovable filters sessions for the ones that filter user
// could approve, based on provided escalations joined with user extracted groups.
func (ef EscalationFiltering) FilterSessionsForUserApprovable(ctx context.Context,
	sessions []telekomv1alpha1.BreakglassSession,
	escalations []telekomv1alpha1.BreakglassEscalation,
) ([]telekomv1alpha1.BreakglassSession, error) {
	ef.Log.Debugw("Filtering sessions for user approvable", "user", ef.FilterUserData.Username, "cluster", ef.FilterUserData.Clustername, "sessionCount", len(sessions), "escalationCount", len(escalations))
	userGroups, err := ef.UserGroupExtract(ctx, ef.FilterUserData)
	if err != nil {
		ef.Log.Errorw("Failed to get user rbac cluster groups for session filtering", "error", err)
		return nil, errors.Wrap(err, "failed to get user rbac cluster groups")
	}
	ef.Log.Debugw("Retrieved user groups for session filtering", "userGroups", userGroups)

	userCluserGroups := map[string]any{}
	for _, g := range userGroups {
		userCluserGroups[g] = struct{}{}
	}

	displayable := []telekomv1alpha1.BreakglassSession{}

	for _, ses := range sessions {
		ef.Log.Debugw("Processing session for approvability", "session", ses.Name, "requestedGroup", ses.Spec.GrantedGroup)
		sessionApprovable := false

		for _, esc := range escalations {
			if ses.Spec.GrantedGroup != esc.Spec.EscalatedGroup ||
				!clusterMatchesPatterns(ses.Spec.Cluster, esc.Spec.Allowed.Clusters) {
				ef.Log.Debugw("Session-escalation mismatch", "session", ses.Name, "escalation", esc.Name, "sessionGroup", ses.Spec.GrantedGroup, "escalationGroup", esc.Spec.EscalatedGroup)
				continue
			}

			if slices.Contains(esc.Spec.Approvers.Users, ef.FilterUserData.Username) {
				ef.Log.Debugw("Session approvable by user directly", "session", ses.Name, "escalation", esc.Name, "user", ef.FilterUserData.Username)
				displayable = append(displayable, ses)
				sessionApprovable = true
				break
			} else if intersects(userCluserGroups, esc.Spec.Approvers.Groups) {
				ef.Log.Debugw("Session approvable by user group", "session", ses.Name, "escalation", esc.Name, "userGroups", userGroups, "approverGroups", esc.Spec.Approvers.Groups)
				displayable = append(displayable, ses)
				sessionApprovable = true
				break
			} else {
				ef.Log.Debugw("Session not approvable by user for this escalation", "session", ses.Name, "escalation", esc.Name, "userGroups", userGroups, "approverGroups", esc.Spec.Approvers.Groups)
			}
		}

		if !sessionApprovable {
			ef.Log.Debugw("Session not approvable by user", "session", ses.Name)
		}
	}
	ef.Log.Infow("Filtered approvable sessions", "approvableCount", len(displayable))
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
