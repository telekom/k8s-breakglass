// SPDX-FileCopyrightText: 2025 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package breakglass

import (
	"context"
	"slices"
	"strings"

	"github.com/pkg/errors"
	telekomv1alpha1 "github.com/telekom/das-schiff-breakglass/api/v1alpha1"
	"github.com/telekom/das-schiff-breakglass/pkg/system"
	"go.uber.org/zap"
	"k8s.io/apimachinery/pkg/fields"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"

	cfgpkg "github.com/telekom/das-schiff-breakglass/pkg/config"
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
			zap.S().Debugw("Escalation matched filter", system.NamespacedFields(it.Name, it.Namespace)...)
			output = append(output, it)
		} else {
			zap.S().Debugw("Escalation did not match filter", system.NamespacedFields(it.Name, it.Namespace)...)
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
	// First try index-based lookup for each group and collect results (deduped)
	collectedMap := map[string]telekomv1alpha1.BreakglassEscalation{}
	for _, g := range groups {
		list := telekomv1alpha1.BreakglassEscalationList{}
		if err := em.List(ctx, &list, client.MatchingFields{"spec.allowed.group": g}); err == nil {
			zap.S().Debugw("Index lookup for group returned items", "group", g, "count", len(list.Items))
			for _, it := range list.Items {
				// apply group normalization check to be safe (fake client may ignore MatchingFields)
				allowed := it.Spec.Allowed.Groups
				// normalize OIDC prefixes for comparison
				normAllowed := allowed
				if cfg, err := cfgpkg.Load(); err == nil && len(cfg.Kubernetes.OIDCPrefixes) > 0 {
					normAllowed = stripOIDCPrefixes(allowed, cfg.Kubernetes.OIDCPrefixes)
				}
				if slices.Contains(normAllowed, g) {
					collectedMap[it.Namespace+"/"+it.Name] = it
				}
			}
		}
	}
	if len(collectedMap) > 0 {
		collected := make([]telekomv1alpha1.BreakglassEscalation, 0, len(collectedMap))
		for _, v := range collectedMap {
			collected = append(collected, v)
		}
		return collected, nil
	}

	// Fallback to full filter if indices not available or returned nothing
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
		for _, group := range groups {
			if slices.Contains(allowedGroups, group) {
				zap.S().Debugw("Escalation matches user group", append(system.NamespacedFields(be.Name, ""), "matchingGroup", group, "allowedGroups", be.Spec.Allowed.Groups, "normalizedAllowedGroups", allowedGroups)...)
				return true
			}
		}
		zap.S().Debugw("Escalation does not match any user groups", append(system.NamespacedFields(be.Name, ""), "userGroups", groups, "allowedGroups", be.Spec.Allowed.Groups, "normalizedAllowedGroups", allowedGroups)...)
		return false
	})
}

func (em EscalationManager) GetClusterBreakglassEscalations(ctx context.Context, cluster string) ([]telekomv1alpha1.BreakglassEscalation, error) {
	zap.S().Debugw("Fetching cluster BreakglassEscalations", "cluster", cluster)
	list := telekomv1alpha1.BreakglassEscalationList{}
	if err := em.List(ctx, &list, client.MatchingFields{"spec.allowed.cluster": cluster}); err == nil && len(list.Items) > 0 {
		// filter results to ensure cluster actually matches (fake client may ignore MatchingFields)
		out := make([]telekomv1alpha1.BreakglassEscalation, 0)
		for _, be := range list.Items {
			if slices.Contains(be.Spec.Allowed.Clusters, cluster) {
				out = append(out, be)
				continue
			}
			for _, ref := range be.Spec.ClusterConfigRefs {
				if ref == cluster || strings.Contains(ref, cluster) {
					out = append(out, be)
					break
				}
			}
		}
		if len(out) > 0 {
			return out, nil
		}
	}

	// Fallback to filter-based scan
	return em.GetBreakglassEscalationsWithFilter(ctx, func(be telekomv1alpha1.BreakglassEscalation) bool {
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
	// Try to perform index-based lookups. We will collect matches from cluster index and then filter by group.
	collected := make([]telekomv1alpha1.BreakglassEscalation, 0)
	list := telekomv1alpha1.BreakglassEscalationList{}
	if err := em.List(ctx, &list, client.MatchingFields{"spec.allowed.cluster": cluster}); err == nil && len(list.Items) > 0 {
		collected = append(collected, list.Items...)
	}
	// If index returned nothing, fall back to scanning all escalations
	if len(collected) == 0 {
		all, err := em.GetAllBreakglassEscalations(ctx)
		if err != nil {
			return nil, err
		}
		collected = append(collected, all...)
	}

	// Now filter collected by groups and OIDC normalization
	var oidcPrefixes []string
	if cfg, err := cfgpkg.Load(); err == nil && len(cfg.Kubernetes.OIDCPrefixes) > 0 {
		oidcPrefixes = cfg.Kubernetes.OIDCPrefixes
	}
	out := make([]telekomv1alpha1.BreakglassEscalation, 0)
	for _, be := range collected {
		// ensure escalation applies to the requested cluster
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
			continue
		}
		allowedGroups := be.Spec.Allowed.Groups
		if len(oidcPrefixes) > 0 {
			allowedGroups = stripOIDCPrefixes(allowedGroups, oidcPrefixes)
		}
		matched := false
		for _, g := range groups {
			if slices.Contains(allowedGroups, g) {
				matched = true
				break
			}
		}
		if matched {
			out = append(out, be)
		}
	}
	return out, nil
}

// GetClusterGroupTargetBreakglassEscalation returns escalations for specific cluster, user groups, and target group
func (em EscalationManager) GetClusterGroupTargetBreakglassEscalation(ctx context.Context, cluster string, userGroups []string, targetGroup string) ([]telekomv1alpha1.BreakglassEscalation, error) {
	zap.S().Debugw("Fetching cluster-group-target BreakglassEscalations", "cluster", cluster, "userGroups", userGroups, "targetGroup", targetGroup)
	// Try index-based lookup by escalatedGroup first
	collected := make([]telekomv1alpha1.BreakglassEscalation, 0)
	list := telekomv1alpha1.BreakglassEscalationList{}
	if err := em.List(ctx, &list, client.MatchingFields{"spec.escalatedGroup": targetGroup}); err == nil && len(list.Items) > 0 {
		collected = append(collected, list.Items...)
	}
	// If not found via index, fall back to scanning all escalations
	if len(collected) == 0 {
		all, err := em.GetAllBreakglassEscalations(ctx)
		if err != nil {
			return nil, err
		}
		collected = append(collected, all...)
	}

	// Filter collected by cluster and allowed groups
	var oidcPrefixes []string
	if cfg, err := cfgpkg.Load(); err == nil && len(cfg.Kubernetes.OIDCPrefixes) > 0 {
		oidcPrefixes = cfg.Kubernetes.OIDCPrefixes
	}
	out := make([]telekomv1alpha1.BreakglassEscalation, 0)
	for _, be := range collected {
		if be.Spec.EscalatedGroup != targetGroup {
			continue
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
			continue
		}
		allowedGroups := be.Spec.Allowed.Groups
		if len(oidcPrefixes) > 0 {
			allowedGroups = stripOIDCPrefixes(allowedGroups, oidcPrefixes)
		}
		for _, g := range userGroups {
			if slices.Contains(allowedGroups, g) {
				out = append(out, be)
				break
			}
		}
	}
	return out, nil
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
