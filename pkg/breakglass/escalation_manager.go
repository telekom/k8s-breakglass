package breakglass

import (
	"context"
	"path/filepath"
	"slices"
	"sync"

	"github.com/pkg/errors"
	telekomv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/system"
	"go.uber.org/zap"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/fields"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"

	cfgpkg "github.com/telekom/k8s-breakglass/pkg/config"
	"github.com/telekom/k8s-breakglass/pkg/metrics"
)

type EscalationManager struct {
	client.Client
	resolver     GroupMemberResolver  // Protected by resolverMu - use GetResolver/SetResolver
	resolverMu   sync.RWMutex         // Protects concurrent access to resolver field
	log          *zap.SugaredLogger   // Injected logger (falls back to global if nil)
	configLoader *cfgpkg.CachedLoader // Cached config loader to avoid disk reads per request
}

// GetResolver returns the current GroupMemberResolver in a thread-safe manner.
func (em *EscalationManager) GetResolver() GroupMemberResolver {
	em.resolverMu.RLock()
	defer em.resolverMu.RUnlock()
	return em.resolver
}

// getLogger returns the injected logger or falls back to the global logger.
func (em *EscalationManager) getLogger() *zap.SugaredLogger {
	if em.log != nil {
		return em.log
	}
	return zap.S()
}

// getConfig returns config from the cached loader or falls back to disk read.
// Logs a warning when falling back to avoid per-request disk I/O.
func (em *EscalationManager) getConfig() (cfgpkg.Config, error) {
	if em.configLoader != nil {
		return em.configLoader.Get()
	}
	// Fallback: log warning and load from disk (this should be avoided in production)
	em.getLogger().Warn("EscalationManager: configLoader not set, falling back to disk read (performance impact)")
	return cfgpkg.Load()
}

// Get all stored BreakglassEscalations
func (em *EscalationManager) GetAllBreakglassEscalations(ctx context.Context) ([]telekomv1alpha1.BreakglassEscalation, error) {
	log := em.getLogger()
	log.Debug("Fetching all BreakglassEscalations")
	metrics.APIEndpointRequests.WithLabelValues("GetAllBreakglassEscalations").Inc()
	escal := telekomv1alpha1.BreakglassEscalationList{}
	if err := em.List(ctx, &escal); err != nil {
		log.Errorw("Failed to get BreakglassEscalationList", "error", err)
		return nil, errors.Wrap(err, "failed to get BreakglassEscalationList")
	}
	log.Infow("Fetched BreakglassEscalations", "count", len(escal.Items))
	return escal.Items, nil
}

func (em *EscalationManager) GetBreakglassEscalationsWithFilter(ctx context.Context,
	filter func(telekomv1alpha1.BreakglassEscalation) bool,
) ([]telekomv1alpha1.BreakglassEscalation, error) {
	log := em.getLogger()
	log.Debug("Fetching BreakglassEscalations with filter")
	metrics.APIEndpointRequests.WithLabelValues("GetBreakglassEscalationsWithFilter").Inc()
	ess := telekomv1alpha1.BreakglassEscalationList{}

	if err := em.List(ctx, &ess); err != nil {
		log.Errorw("Failed to list BreakglassEscalation for filtered get", "error", err)
		return nil, errors.Wrapf(err, "failed to list BreakglassEscalation for filtered get")
	}
	log.Debugw("Retrieved escalations for filtering", "totalCount", len(ess.Items))

	output := make([]telekomv1alpha1.BreakglassEscalation, 0, len(ess.Items))
	for _, it := range ess.Items {
		if filter(it) {
			log.Debugw("Escalation matched filter", system.NamespacedFields(it.Name, it.Namespace)...)
			output = append(output, it)
		} else {
			log.Debugw("Escalation did not match filter", system.NamespacedFields(it.Name, it.Namespace)...)
		}
	}

	log.Infow("Filtered BreakglassEscalations", "count", len(output), "totalEvaluated", len(ess.Items))
	return output, nil
}

// GetBreakglassEscalationsWithSelector with custom field selector.
func (em *EscalationManager) GetBreakglassEscalationsWithSelector(ctx context.Context,
	fs fields.Selector,
) ([]telekomv1alpha1.BreakglassEscalation, error) {
	log := em.getLogger()
	log.Debugw("Fetching BreakglassEscalations with selector", "selector", fs.String())
	metrics.APIEndpointRequests.WithLabelValues("GetBreakglassEscalationsWithSelector").Inc()
	ess := telekomv1alpha1.BreakglassEscalationList{}

	if err := em.List(ctx, &ess, &client.ListOptions{FieldSelector: fs}); err != nil {
		log.Errorw("Failed to list BreakglassEscalation with selector", "selector", fs.String(), "error", err)
		return nil, errors.Wrapf(err, "failed to list BreakglassEscalation with selector")
	}

	log.Infow("Fetched BreakglassEscalations with selector", "count", len(ess.Items), "selector", fs.String())
	return ess.Items, nil
}

// GetBreakglassEscalation retrieves a single BreakglassEscalation by namespace/name using the cached controller-runtime client.
// Prefer this over filter-based scans when the owner reference is known to minimize cache iterations.
func (em *EscalationManager) GetBreakglassEscalation(ctx context.Context, namespace, name string) (*telekomv1alpha1.BreakglassEscalation, error) {
	log := em.getLogger()
	log.Debugw("Fetching BreakglassEscalation by name", "namespace", namespace, "name", name)
	metrics.APIEndpointRequests.WithLabelValues("GetBreakglassEscalation").Inc()
	got := &telekomv1alpha1.BreakglassEscalation{}
	if err := em.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, got); err != nil {
		status := "500"
		if apierrors.IsNotFound(err) {
			status = "404"
		}
		metrics.APIEndpointErrors.WithLabelValues("GetBreakglassEscalation", status).Inc()
		return nil, errors.Wrapf(err, "failed to get BreakglassEscalation %s/%s", namespace, name)
	}
	return got, nil
}

// GetGroupBreakglassEscalations returns escalations available to users in the specified groups
func (em *EscalationManager) GetGroupBreakglassEscalations(ctx context.Context,
	groups []string,
) ([]telekomv1alpha1.BreakglassEscalation, error) {
	log := em.getLogger()
	log.Debugw("Fetching group BreakglassEscalations", "groups", groups)
	metrics.APIEndpointRequests.WithLabelValues("GetGroupBreakglassEscalations").Inc()
	// First try index-based lookup for each group and collect results (deduped)
	collectedMap := map[string]telekomv1alpha1.BreakglassEscalation{}
	for _, g := range groups {
		list := telekomv1alpha1.BreakglassEscalationList{}
		if err := em.List(ctx, &list, client.MatchingFields{"spec.allowed.group": g}); err == nil {
			log.Debugw("Index lookup for group returned items", "group", g, "count", len(list.Items))
			for _, it := range list.Items {
				// apply group normalization check to be safe (fake client may ignore MatchingFields)
				allowed := it.Spec.Allowed.Groups
				// normalize OIDC prefixes for comparison
				normAllowed := allowed
				if cfg, err := em.getConfig(); err == nil && len(cfg.Kubernetes.OIDCPrefixes) > 0 {
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
	if cfg, err := em.getConfig(); err == nil && len(cfg.Kubernetes.OIDCPrefixes) > 0 {
		oidcPrefixes = cfg.Kubernetes.OIDCPrefixes
		log.Debugw("Loaded OIDC prefixes for group normalization", "prefixes", oidcPrefixes)
	}
	return em.GetBreakglassEscalationsWithFilter(ctx, func(be telekomv1alpha1.BreakglassEscalation) bool {
		allowedGroups := be.Spec.Allowed.Groups
		if len(oidcPrefixes) > 0 {
			allowedGroups = stripOIDCPrefixes(allowedGroups, oidcPrefixes)
		}
		for _, group := range groups {
			if slices.Contains(allowedGroups, group) {
				log.Debugw("Escalation matches user group", append(system.NamespacedFields(be.Name, ""), "matchingGroup", group, "allowedGroups", be.Spec.Allowed.Groups, "normalizedAllowedGroups", allowedGroups)...)
				return true
			}
		}
		log.Debugw("Escalation does not match any user groups", append(system.NamespacedFields(be.Name, ""), "userGroups", groups, "allowedGroups", be.Spec.Allowed.Groups, "normalizedAllowedGroups", allowedGroups)...)
		return false
	})
}

// GetClusterBreakglassEscalations returns escalations that apply to a specific cluster.
// Supports glob patterns in both Allowed.Clusters and ClusterConfigRefs fields.
func (em *EscalationManager) GetClusterBreakglassEscalations(ctx context.Context, cluster string) ([]telekomv1alpha1.BreakglassEscalation, error) {
	em.getLogger().Debugw("Fetching cluster BreakglassEscalations", "cluster", cluster)
	metrics.APIEndpointRequests.WithLabelValues("GetClusterBreakglassEscalations").Inc()
	// Try index-based lookup for exact cluster match and global "*" pattern
	list := telekomv1alpha1.BreakglassEscalationList{}
	collected := make([]telekomv1alpha1.BreakglassEscalation, 0)
	if err := em.List(ctx, &list, client.MatchingFields{"spec.allowed.cluster": cluster}); err == nil && len(list.Items) > 0 {
		collected = append(collected, list.Items...)
	}
	globalList := telekomv1alpha1.BreakglassEscalationList{}
	if err := em.List(ctx, &globalList, client.MatchingFields{"spec.allowed.cluster": "*"}); err == nil && len(globalList.Items) > 0 {
		collected = append(collected, globalList.Items...)
	}

	// If index returned results, filter using shared helper and return
	if len(collected) > 0 {
		out := make([]telekomv1alpha1.BreakglassEscalation, 0)
		for _, be := range collected {
			if escalationMatchesCluster(be, cluster) {
				out = append(out, be)
			}
		}
		if len(out) > 0 {
			return out, nil
		}
	}

	// Fallback to filter-based scan for glob patterns
	return em.GetBreakglassEscalationsWithFilter(ctx, func(be telekomv1alpha1.BreakglassEscalation) bool {
		return escalationMatchesCluster(be, cluster)
	})
}

// matchesGlobPattern checks if a pattern matches a value using filepath.Match glob semantics.
// Returns false if the pattern is invalid.
func matchesGlobPattern(pattern, value string) bool {
	matched, err := filepath.Match(pattern, value)
	return err == nil && matched
}

// clusterMatchesPatterns checks if a cluster name matches any pattern in the list.
// Supports exact matches and glob patterns (*, ?, [abc], etc.).
func clusterMatchesPatterns(cluster string, patterns []string) bool {
	for _, pattern := range patterns {
		if pattern == cluster || matchesGlobPattern(pattern, cluster) {
			return true
		}
	}
	return false
}

// escalationMatchesCluster checks if an escalation applies to a given cluster.
// Both Allowed.Clusters and ClusterConfigRefs are checked with glob pattern support.
// Empty values in both fields means the escalation applies to no clusters (use "*" for global).
func escalationMatchesCluster(be telekomv1alpha1.BreakglassEscalation, cluster string) bool {
	return clusterMatchesPatterns(cluster, be.Spec.Allowed.Clusters) ||
		clusterMatchesPatterns(cluster, be.Spec.ClusterConfigRefs)
}

// getOIDCPrefixes retrieves OIDC prefixes from config, returning nil on error.
// This is a convenience helper that handles config loading errors gracefully.
func (em *EscalationManager) getOIDCPrefixes() []string {
	cfg, err := em.getConfig()
	if err == nil && len(cfg.Kubernetes.OIDCPrefixes) > 0 {
		return cfg.Kubernetes.OIDCPrefixes
	}
	return nil
}

// normalizeAndMatchGroups checks if any of the user's groups match the escalation's allowed groups.
// Handles OIDC prefix stripping when configured.
func groupsMatch(userGroups, allowedGroups, oidcPrefixes []string) bool {
	normalized := allowedGroups
	if len(oidcPrefixes) > 0 {
		normalized = stripOIDCPrefixes(allowedGroups, oidcPrefixes)
	}
	for _, g := range userGroups {
		if slices.Contains(normalized, g) {
			return true
		}
	}
	return false
}

// GetClusterGroupBreakglassEscalations returns escalations for specific cluster and user groups
func (em *EscalationManager) GetClusterGroupBreakglassEscalations(ctx context.Context, cluster string, groups []string) ([]telekomv1alpha1.BreakglassEscalation, error) {
	em.getLogger().Debugw("Fetching cluster-group BreakglassEscalations", "cluster", cluster, "groups", groups)
	metrics.APIEndpointRequests.WithLabelValues("GetClusterGroupBreakglassEscalations").Inc()

	// Try index-based lookup first for exact cluster matches
	collected := make([]telekomv1alpha1.BreakglassEscalation, 0)
	list := telekomv1alpha1.BreakglassEscalationList{}
	if err := em.List(ctx, &list, client.MatchingFields{"spec.allowed.cluster": cluster}); err == nil && len(list.Items) > 0 {
		collected = append(collected, list.Items...)
	}

	// Also check for glob pattern "*" (global escalations) via index
	globalList := telekomv1alpha1.BreakglassEscalationList{}
	if err := em.List(ctx, &globalList, client.MatchingFields{"spec.allowed.cluster": "*"}); err == nil && len(globalList.Items) > 0 {
		collected = append(collected, globalList.Items...)
	}

	// If index returned nothing, fall back to scanning all escalations for glob patterns
	if len(collected) == 0 {
		all, err := em.GetAllBreakglassEscalations(ctx)
		if err != nil {
			return nil, err
		}
		collected = all
	}

	// Filter collected by cluster matching and groups using shared helpers
	oidcPrefixes := em.getOIDCPrefixes()
	out := make([]telekomv1alpha1.BreakglassEscalation, 0)
	for _, be := range collected {
		if !escalationMatchesCluster(be, cluster) {
			continue
		}
		if groupsMatch(groups, be.Spec.Allowed.Groups, oidcPrefixes) {
			out = append(out, be)
		}
	}
	return out, nil
}

// GetClusterGroupTargetBreakglassEscalation returns escalations for specific cluster, user groups, and target group
func (em *EscalationManager) GetClusterGroupTargetBreakglassEscalation(ctx context.Context, cluster string, userGroups []string, targetGroup string) ([]telekomv1alpha1.BreakglassEscalation, error) {
	em.getLogger().Debugw("Fetching cluster-group-target BreakglassEscalations", "cluster", cluster, "userGroups", userGroups, "targetGroup", targetGroup)
	metrics.APIEndpointRequests.WithLabelValues("GetClusterGroupTargetBreakglassEscalation").Inc()
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

	// Filter collected by cluster and allowed groups using shared helpers
	oidcPrefixes := em.getOIDCPrefixes()
	out := make([]telekomv1alpha1.BreakglassEscalation, 0)
	for _, be := range collected {
		if be.Spec.EscalatedGroup != targetGroup {
			continue
		}
		if !escalationMatchesCluster(be, cluster) {
			continue
		}
		if groupsMatch(userGroups, be.Spec.Allowed.Groups, oidcPrefixes) {
			out = append(out, be)
		}
	}
	return out, nil
}

func NewEscalationManager(contextName string, resolver GroupMemberResolver) (EscalationManager, error) {
	log := zap.S()
	log.Infow("Initializing EscalationManager", "context", contextName)
	cfg, err := config.GetConfigWithContext(contextName)
	if err != nil {
		log.Errorw("Failed to get config with context", "context", contextName, "error", err)
		return EscalationManager{}, errors.Wrapf(err, "failed to get config with context %q", contextName)
	}

	c, err := client.New(cfg, client.Options{
		Scheme: Scheme,
	})
	if err != nil {
		log.Errorw("Failed to create new client", "error", err)
		return EscalationManager{}, errors.Wrap(err, "failed to create new client")
	}

	log.Info("EscalationManager initialized successfully")
	return EscalationManager{Client: c, resolver: resolver, log: log}, nil
}

// NewEscalationManagerWithClient constructs an EscalationManager backed by the provided controller-runtime client.
// Use this when a shared manager client (with cache/indexes) should be reused instead of creating a new rest.Config.
// Optional variadic arguments:
//   - log *zap.SugaredLogger: custom logger (falls back to global zap.S() if not provided)
//   - configLoader *cfgpkg.CachedLoader: config loader (falls back to cfgpkg.Load() if not provided)
func NewEscalationManagerWithClient(c client.Client, resolver GroupMemberResolver, opts ...any) *EscalationManager {
	em := &EscalationManager{Client: c, resolver: resolver}
	for _, opt := range opts {
		switch v := opt.(type) {
		case *zap.SugaredLogger:
			em.log = v
		case *cfgpkg.CachedLoader:
			em.configLoader = v
		}
	}
	return em
}

// SetResolver updates the GroupMemberResolver used for resolving group members.
// This should be called when the IdentityProvider configuration changes to ensure
// the EscalationManager uses the latest Keycloak group sync configuration.
// Thread-safe: Uses mutex to protect concurrent access to the resolver field.
func (em *EscalationManager) SetResolver(resolver GroupMemberResolver) {
	em.resolverMu.Lock()
	defer em.resolverMu.Unlock()
	em.resolver = resolver
	em.getLogger().Infow("EscalationManager resolver updated")
}

// UpdateBreakglassEscalationStatus updates the given escalation resource status
func (em *EscalationManager) UpdateBreakglassEscalationStatus(ctx context.Context, esc telekomv1alpha1.BreakglassEscalation) error {
	log := em.getLogger()
	log.Infow("Updating BreakglassEscalation status", "name", esc.Name)
	if err := applyBreakglassEscalationStatus(ctx, em, &esc); err != nil {
		log.Errorw("Failed to update BreakglassEscalation status", "name", esc.Name, "error", err)
		return errors.Wrapf(err, "failed to update BreakglassEscalation status %s", esc.Name)
	}
	log.Infow("BreakglassEscalation status updated", "name", esc.Name)
	return nil
}
