package breakglass

import (
	"context"
	"slices"
	"strings"

	"github.com/pkg/errors"
	telekomv1alpha1 "gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/api/v1alpha1"
	"go.uber.org/zap"
	"k8s.io/apimachinery/pkg/fields"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"

	cfgpkg "gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/pkg/config"
)

type EscalationManager struct {
	client.Client
	Resolver GroupMemberResolver
}

// Get all stored BreakglassEscalations
func (em EscalationManager) GetAllBreakglassEscalations(ctx context.Context) ([]telekomv1alpha1.BreakglassEscalation, error) {
	zap.S().Debug("Fetching all BreakglassEscalations")
	escal := telekomv1alpha1.BreakglassEscalationList{}
	if err := em.List(ctx, &escal); err != nil {
		zap.S().Errorw("Failed to get BreakglassEscalationList", "error", err)
		return nil, errors.Wrap(err, "failed to get BreakglassEscalationList")
	}
	zap.S().Infow("Fetched BreakglassEscalations", "count", len(escal.Items))
	return escal.Items, nil
}

func (em EscalationManager) GetBreakglassEscalationsWithFilter(ctx context.Context,
	filter func(telekomv1alpha1.BreakglassEscalation) bool,
) ([]telekomv1alpha1.BreakglassEscalation, error) {
	zap.S().Debug("Fetching BreakglassEscalations with filter")
	ess := telekomv1alpha1.BreakglassEscalationList{}

	if err := em.List(ctx, &ess); err != nil {
		zap.S().Errorw("Failed to list BreakglassEscalation for filtered get", "error", err)
		return nil, errors.Wrapf(err, "failed to list BreakglassEscalation for filtered get")
	}
	zap.S().Debugw("Retrieved escalations for filtering", "totalCount", len(ess.Items))

	output := make([]telekomv1alpha1.BreakglassEscalation, 0, len(ess.Items))
	for _, it := range ess.Items {
		if filter(it) {
			zap.S().Debugw("Escalation matched filter", "name", it.Name, "namespace", it.Namespace)
			output = append(output, it)
		} else {
			zap.S().Debugw("Escalation did not match filter", "name", it.Name, "namespace", it.Namespace)
		}
	}

	zap.S().Infow("Filtered BreakglassEscalations", "count", len(output), "totalEvaluated", len(ess.Items))
	return output, nil
}

// GetBreakglassEscalationsWithSelector with custom field selector.
func (em EscalationManager) GetBreakglassEscalationsWithSelector(ctx context.Context,
	fs fields.Selector,
) ([]telekomv1alpha1.BreakglassEscalation, error) {
	zap.S().Debugw("Fetching BreakglassEscalations with selector", "selector", fs.String())
	ess := telekomv1alpha1.BreakglassEscalationList{}

	if err := em.List(ctx, &ess, &client.ListOptions{FieldSelector: fs}); err != nil {
		zap.S().Errorw("Failed to list BreakglassEscalation with selector", "selector", fs.String(), "error", err)
		return nil, errors.Wrapf(err, "failed to list BreakglassEscalation with selector")
	}

	zap.S().Infow("Fetched BreakglassEscalations with selector", "count", len(ess.Items), "selector", fs.String())
	return ess.Items, nil
}

// GetGroupBreakglassEscalations returns escalations available to users in the specified groups
func (em EscalationManager) GetGroupBreakglassEscalations(ctx context.Context,
	groups []string,
) ([]telekomv1alpha1.BreakglassEscalation, error) {
	zap.S().Debugw("Fetching group BreakglassEscalations", "groups", groups)
	// Load config for OIDC prefixes to normalize allowed groups
	var oidcPrefixes []string
	if cfg, err := cfgpkg.Load(); err == nil && len(cfg.Kubernetes.OIDCPrefixes) > 0 {
		oidcPrefixes = cfg.Kubernetes.OIDCPrefixes
		zap.S().Debugw("Loaded OIDC prefixes for group normalization", "prefixes", oidcPrefixes)
	}
	return em.GetBreakglassEscalationsWithFilter(ctx, func(be telekomv1alpha1.BreakglassEscalation) bool {
		allowedGroups := be.Spec.Allowed.Groups
		if len(oidcPrefixes) > 0 {
			allowedGroups = stripOIDCPrefixes(allowedGroups, oidcPrefixes)
		}
		matched := false
		for _, group := range groups {
			if slices.Contains(allowedGroups, group) {
				zap.S().Debugw("Escalation matches user group", "escalation", be.Name, "matchingGroup", group, "allowedGroups", be.Spec.Allowed.Groups, "normalizedAllowedGroups", allowedGroups)
				matched = true
				break
			} else {
				zap.S().Debugw("Group not in allowed list", "escalation", be.Name, "candidateGroup", group, "normalizedAllowedGroups", allowedGroups)
			}
		}
		if !matched {
			zap.S().Debugw("Escalation does not match any user groups", "escalation", be.Name, "userGroups", groups, "allowedGroups", be.Spec.Allowed.Groups, "normalizedAllowedGroups", allowedGroups)
		}
		return matched
	})
}

func (em EscalationManager) GetClusterBreakglassEscalations(ctx context.Context, cluster string) ([]telekomv1alpha1.BreakglassEscalation, error) {
	zap.S().Debugw("Fetching cluster BreakglassEscalations", "cluster", cluster)
	return em.GetBreakglassEscalationsWithFilter(ctx, func(be telekomv1alpha1.BreakglassEscalation) bool {
		// match against legacy allowed.clusters or new clusterConfigRefs (names assumed to contain cluster id for now)
		if slices.Contains(be.Spec.Allowed.Clusters, cluster) {
			return true
		}
		for _, ref := range be.Spec.ClusterConfigRefs {
			if ref == cluster || strings.Contains(ref, cluster) {
				return true
			}
		}
		return false
	})
}

// GetClusterGroupBreakglassEscalations returns escalations for specific cluster and user groups
func (em EscalationManager) GetClusterGroupBreakglassEscalations(ctx context.Context, cluster string, groups []string) ([]telekomv1alpha1.BreakglassEscalation, error) {
	zap.S().Debugw("Fetching cluster-group BreakglassEscalations", "cluster", cluster, "groups", groups)
	var oidcPrefixes []string
	if cfg, err := cfgpkg.Load(); err == nil && len(cfg.Kubernetes.OIDCPrefixes) > 0 {
		oidcPrefixes = cfg.Kubernetes.OIDCPrefixes
	}
	return em.GetBreakglassEscalationsWithFilter(ctx, func(be telekomv1alpha1.BreakglassEscalation) bool {
		clusterMatch := slices.Contains(be.Spec.Allowed.Clusters, cluster)
		if !clusterMatch {
			for _, ref := range be.Spec.ClusterConfigRefs {
				if ref == cluster || strings.Contains(ref, cluster) {
					clusterMatch = true
					break
				}
			}
		}
		if !clusterMatch {
			return false
		}
		allowedGroups := be.Spec.Allowed.Groups
		if len(oidcPrefixes) > 0 {
			allowedGroups = stripOIDCPrefixes(allowedGroups, oidcPrefixes)
		}
		for _, group := range groups {
			if slices.Contains(allowedGroups, group) {
				zap.S().Debugw("Cluster-group escalation matches", "escalation", be.Name, "cluster", cluster, "group", group, "normalizedAllowedGroups", allowedGroups)
				return true
			} else {
				zap.S().Debugw("Cluster-group escalation no match", "escalation", be.Name, "cluster", cluster, "candidateGroup", group, "normalizedAllowedGroups", allowedGroups)
			}
		}
		return false
	})
}

// GetClusterGroupTargetBreakglassEscalation returns escalations for specific cluster, user groups, and target group
func (em EscalationManager) GetClusterGroupTargetBreakglassEscalation(ctx context.Context, cluster string, userGroups []string, targetGroup string) ([]telekomv1alpha1.BreakglassEscalation, error) {
	zap.S().Debugw("Fetching cluster-group-target BreakglassEscalations", "cluster", cluster, "userGroups", userGroups, "targetGroup", targetGroup)
	var oidcPrefixes []string
	if cfg, err := cfgpkg.Load(); err == nil && len(cfg.Kubernetes.OIDCPrefixes) > 0 {
		oidcPrefixes = cfg.Kubernetes.OIDCPrefixes
	}
	return em.GetBreakglassEscalationsWithFilter(ctx, func(be telekomv1alpha1.BreakglassEscalation) bool {
		if be.Spec.EscalatedGroup != targetGroup {
			return false
		}
		clusterMatch := slices.Contains(be.Spec.Allowed.Clusters, cluster)
		if !clusterMatch {
			for _, ref := range be.Spec.ClusterConfigRefs {
				if ref == cluster || strings.Contains(ref, cluster) {
					clusterMatch = true
					break
				}
			}
		}
		if !clusterMatch {
			return false
		}
		allowedGroups := be.Spec.Allowed.Groups
		if len(oidcPrefixes) > 0 {
			allowedGroups = stripOIDCPrefixes(allowedGroups, oidcPrefixes)
		}
		for _, g := range userGroups {
			if slices.Contains(allowedGroups, g) {
				zap.S().Debugw("Cluster-group-target escalation matches", "escalation", be.Name, "cluster", cluster, "group", g, "targetGroup", targetGroup, "normalizedAllowedGroups", allowedGroups)
				return true
			} else {
				zap.S().Debugw("Cluster-group-target escalation no match", "escalation", be.Name, "cluster", cluster, "candidateGroup", g, "targetGroup", targetGroup, "normalizedAllowedGroups", allowedGroups)
			}
		}
		return false
	})
}

func NewEscalationManager(contextName string, resolver GroupMemberResolver) (EscalationManager, error) {
	zap.S().Infow("Initializing EscalationManager", "context", contextName)
	cfg, err := config.GetConfigWithContext(contextName)
	if err != nil {
		zap.S().Errorw("Failed to get config with context", "context", contextName, "error", err)
		return EscalationManager{}, errors.Wrapf(err, "failed to get config with context %q", contextName)
	}

	c, err := client.New(cfg, client.Options{
		Scheme: Scheme,
	})
	if err != nil {
		zap.S().Errorw("Failed to create new client", "error", err)
		return EscalationManager{}, errors.Wrap(err, "failed to create new client")
	}

	zap.S().Info("EscalationManager initialized successfully")
	return EscalationManager{Client: c, Resolver: resolver}, nil
}

// UpdateBreakglassEscalationStatus updates the given escalation resource status
func (em EscalationManager) UpdateBreakglassEscalationStatus(ctx context.Context, esc telekomv1alpha1.BreakglassEscalation) error {
	zap.S().Infow("Updating BreakglassEscalation status", "name", esc.Name)
	if err := em.Status().Update(ctx, &esc); err != nil {
		zap.S().Errorw("Failed to update BreakglassEscalation status", "name", esc.Name, "error", err)
		return errors.Wrapf(err, "failed to update BreakglassEscalation status %s", esc.Name)
	}
	zap.S().Infow("BreakglassEscalation status updated", "name", esc.Name)
	return nil
}
