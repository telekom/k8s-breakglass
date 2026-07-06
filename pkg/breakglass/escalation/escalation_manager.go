package escalation

import (
	"context"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"go.uber.org/zap"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/fields"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	breakglass "github.com/telekom/k8s-breakglass/pkg/breakglass"
	cfgpkg "github.com/telekom/k8s-breakglass/pkg/config"
	"github.com/telekom/k8s-breakglass/pkg/metrics"
	"github.com/telekom/k8s-breakglass/pkg/system"
)

// Compile-time assertion: EscalationManager must implement EscalationLookup.
var _ breakglass.EscalationLookup = (*EscalationManager)(nil)

type EscalationManager struct {
	client.Client
	resolver     breakglass.GroupMemberResolver // Protected by resolverMu - use GetResolver/SetResolver
	resolverMu   sync.RWMutex                   // Protects concurrent access to resolver field
	log          *zap.SugaredLogger             // Injected logger (falls back to global if nil)
	configLoader *cfgpkg.CachedLoader           // Cached config loader to avoid disk reads per request
}

// GetResolver returns the current GroupMemberResolver in a thread-safe manner.
func (em *EscalationManager) GetResolver() breakglass.GroupMemberResolver {
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
func (em *EscalationManager) GetAllBreakglassEscalations(ctx context.Context) ([]breakglassv1alpha1.BreakglassEscalation, error) {
	log := em.getLogger()
	log.Debug("Fetching all BreakglassEscalations")
	metrics.APIEndpointRequests.WithLabelValues("GetAllBreakglassEscalations").Inc()
	escal := breakglassv1alpha1.BreakglassEscalationList{}
	if err := em.List(ctx, &escal); err != nil {
		log.Errorw("Failed to get BreakglassEscalationList", "error", err)
		return nil, fmt.Errorf("failed to get BreakglassEscalationList: %w", err)
	}
	log.Infow("Fetched BreakglassEscalations", "count", len(escal.Items))
	return escal.Items, nil
}

func (em *EscalationManager) GetBreakglassEscalationsWithFilter(ctx context.Context,
	filter func(breakglassv1alpha1.BreakglassEscalation) bool,
) ([]breakglassv1alpha1.BreakglassEscalation, error) {
	log := em.getLogger()
	log.Debug("Fetching BreakglassEscalations with filter")
	metrics.APIEndpointRequests.WithLabelValues("GetBreakglassEscalationsWithFilter").Inc()
	ess := breakglassv1alpha1.BreakglassEscalationList{}

	if err := em.List(ctx, &ess); err != nil {
		log.Errorw("Failed to list BreakglassEscalation for filtered get", "error", err)
		return nil, fmt.Errorf("failed to list BreakglassEscalation for filtered get: %w", err)
	}
	log.Debugw("Retrieved escalations for filtering", "totalCount", len(ess.Items))

	output := make([]breakglassv1alpha1.BreakglassEscalation, 0, len(ess.Items))
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
) ([]breakglassv1alpha1.BreakglassEscalation, error) {
	log := em.getLogger()
	log.Debugw("Fetching BreakglassEscalations with selector", "selector", fs.String())
	metrics.APIEndpointRequests.WithLabelValues("GetBreakglassEscalationsWithSelector").Inc()
	ess := breakglassv1alpha1.BreakglassEscalationList{}

	if err := em.List(ctx, &ess, &client.ListOptions{FieldSelector: fs}); err != nil {
		log.Errorw("Failed to list BreakglassEscalation with selector", "selector", fs.String(), "error", err)
		return nil, fmt.Errorf("failed to list BreakglassEscalation with selector: %w", err)
	}

	log.Infow("Fetched BreakglassEscalations with selector", "count", len(ess.Items), "selector", fs.String())
	return ess.Items, nil
}

func escalationGroupIndexLookupValues(groups, oidcPrefixes []string) []string {
	seen := make(map[string]struct{}, len(groups)*(len(oidcPrefixes)+1))
	values := make([]string, 0, len(groups)*(len(oidcPrefixes)+1))
	add := func(value string) {
		if value == "" {
			return
		}
		if _, exists := seen[value]; exists {
			return
		}
		seen[value] = struct{}{}
		values = append(values, value)
	}

	for _, group := range groups {
		add(group)
		for _, prefix := range oidcPrefixes {
			if prefix == "" {
				continue
			}
			if strings.HasPrefix(group, prefix) {
				add(strings.TrimPrefix(group, prefix))
				continue
			}
			add(prefix + group)
		}
	}
	return values
}

func (em *EscalationManager) collectEscalationsByFieldIndex(ctx context.Context, field string, values []string) ([]breakglassv1alpha1.BreakglassEscalation, bool, error) {
	if len(values) == 0 {
		return nil, true, nil
	}

	collected := make([]breakglassv1alpha1.BreakglassEscalation, 0)
	seen := make(map[string]struct{})
	for _, value := range values {
		list := breakglassv1alpha1.BreakglassEscalationList{}
		if err := em.List(ctx, &list, client.MatchingFields{field: value}); err != nil {
			if breakglass.IsFieldIndexError(err) {
				return nil, false, nil
			}
			return nil, false, fmt.Errorf("failed to list BreakglassEscalation by %s: %w", field, err)
		}
		for _, item := range list.Items {
			key := item.Namespace + "/" + item.Name
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			collected = append(collected, item)
		}
	}
	return collected, true, nil
}

// GetBreakglassEscalation retrieves a single BreakglassEscalation by namespace/name using the cached controller-runtime client.
// Prefer this over filter-based scans when the owner reference is known to minimize cache iterations.
func (em *EscalationManager) GetBreakglassEscalation(ctx context.Context, namespace, name string) (*breakglassv1alpha1.BreakglassEscalation, error) {
	log := em.getLogger()
	log.Debugw("Fetching BreakglassEscalation by name", "namespace", namespace, "name", name)
	metrics.APIEndpointRequests.WithLabelValues("GetBreakglassEscalation").Inc()
	got := &breakglassv1alpha1.BreakglassEscalation{}
	if err := em.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, got); err != nil {
		status := "500"
		if apierrors.IsNotFound(err) {
			status = "404"
		}
		metrics.APIEndpointErrors.WithLabelValues("GetBreakglassEscalation", status).Inc()
		return nil, fmt.Errorf("failed to get BreakglassEscalation %s/%s: %w", namespace, name, err)
	}
	return got, nil
}

// GetGroupBreakglassEscalations returns escalations available to users in the specified groups
func (em *EscalationManager) GetGroupBreakglassEscalations(ctx context.Context,
	groups []string,
) ([]breakglassv1alpha1.BreakglassEscalation, error) {
	log := em.getLogger()
	log.Debugw("Fetching group BreakglassEscalations", "groupCount", len(groups))
	metrics.APIEndpointRequests.WithLabelValues("GetGroupBreakglassEscalations").Inc()

	oidcPrefixes := em.getOIDCPrefixes()
	collected, indexed, err := em.collectEscalationsByFieldIndex(ctx, "spec.allowed.group", escalationGroupIndexLookupValues(groups, oidcPrefixes))
	if err != nil {
		return nil, err
	}
	if indexed {
		output := make([]breakglassv1alpha1.BreakglassEscalation, 0, len(collected))
		for _, item := range collected {
			if groupsMatch(groups, item.Spec.Allowed.Groups, oidcPrefixes) {
				output = append(output, item)
			}
		}
		log.Debugw("Fetched group escalation candidates with group index", "candidateCount", len(collected), "matched", len(output))
		return output, nil
	}

	// Fallback to full filter if the group index is unavailable or unsupported.
	return em.GetBreakglassEscalationsWithFilter(ctx, func(be breakglassv1alpha1.BreakglassEscalation) bool {
		allowedGroups := be.Spec.Allowed.Groups
		if len(oidcPrefixes) > 0 {
			allowedGroups = breakglass.StripOIDCPrefixes(allowedGroups, oidcPrefixes)
		}
		for _, group := range groups {
			if slices.Contains(allowedGroups, group) {
				log.Debugw("Escalation matches user group", append(system.NamespacedFields(be.Name, ""), "allowedGroupCount", len(be.Spec.Allowed.Groups))...)
				return true
			}
		}
		log.Debugw("Escalation does not match any user groups", append(system.NamespacedFields(be.Name, ""), "userGroupCount", len(groups), "allowedGroupCount", len(be.Spec.Allowed.Groups))...)
		return false
	})
}

// GetClusterBreakglassEscalations returns escalations that apply to a specific cluster.
// Supports glob patterns in both Allowed.Clusters and ClusterConfigRefs fields.
func (em *EscalationManager) GetClusterBreakglassEscalations(ctx context.Context, cluster string) ([]breakglassv1alpha1.BreakglassEscalation, error) {
	em.getLogger().Debugw("Fetching cluster BreakglassEscalations", "cluster", cluster)
	metrics.APIEndpointRequests.WithLabelValues("GetClusterBreakglassEscalations").Inc()

	return em.GetBreakglassEscalationsWithFilter(ctx, func(be breakglassv1alpha1.BreakglassEscalation) bool {
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
func escalationMatchesCluster(be breakglassv1alpha1.BreakglassEscalation, cluster string) bool {
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
		normalized = breakglass.StripOIDCPrefixes(allowedGroups, oidcPrefixes)
	}
	for _, g := range userGroups {
		if slices.Contains(normalized, g) {
			return true
		}
	}
	return false
}

// GetClusterGroupBreakglassEscalations returns escalations for specific cluster and user groups
func (em *EscalationManager) GetClusterGroupBreakglassEscalations(ctx context.Context, cluster string, groups []string) ([]breakglassv1alpha1.BreakglassEscalation, error) {
	log := em.getLogger()
	log.Debugw("Fetching cluster-group BreakglassEscalations", "cluster", cluster, "groupCount", len(groups))
	metrics.APIEndpointRequests.WithLabelValues("GetClusterGroupBreakglassEscalations").Inc()

	oidcPrefixes := em.getOIDCPrefixes()
	collected, indexed, err := em.collectEscalationsByFieldIndex(ctx, "spec.allowed.group", escalationGroupIndexLookupValues(groups, oidcPrefixes))
	if err != nil {
		return nil, err
	}
	if !indexed {
		all, err := em.GetAllBreakglassEscalations(ctx)
		if err != nil {
			return nil, err
		}
		collected = all
		log.Debugw("Fell back to full escalation scan", "cluster", cluster, "totalEscalations", len(collected))
	} else {
		log.Debugw("Fetched escalation candidates with group index", "cluster", cluster, "candidateCount", len(collected))
	}

	// Filter collected by cluster matching and groups using shared helpers
	out := make([]breakglassv1alpha1.BreakglassEscalation, 0)
	for _, be := range collected {
		if !escalationMatchesCluster(be, cluster) {
			log.Debugw("Escalation skipped: cluster mismatch",
				"escalation", be.Name,
				"allowedClusters", be.Spec.Allowed.Clusters,
				"clusterConfigRefs", be.Spec.ClusterConfigRefs,
				"requestedCluster", cluster)
			continue
		}
		if groupsMatch(groups, be.Spec.Allowed.Groups, oidcPrefixes) {
			out = append(out, be)
		} else {
			log.Debugw("Escalation skipped: group mismatch",
				"escalation", be.Name,
				"allowedGroups", be.Spec.Allowed.Groups,
				"userGroupCount", len(groups))
		}
	}
	log.Debugw("Cluster-group escalation lookup complete", "cluster", cluster, "matched", len(out), "evaluated", len(collected))
	return out, nil
}

// GetClusterGroupTargetBreakglassEscalation returns escalations for specific cluster, user groups, and target group
func (em *EscalationManager) GetClusterGroupTargetBreakglassEscalation(ctx context.Context, cluster string, userGroups []string, targetGroup string) ([]breakglassv1alpha1.BreakglassEscalation, error) {
	log := em.getLogger()
	log.Debugw("Fetching cluster-group-target BreakglassEscalations", "cluster", cluster, "userGroupCount", len(userGroups), "targetGroupHint", system.RedactGroupName(targetGroup))
	metrics.APIEndpointRequests.WithLabelValues("GetClusterGroupTargetBreakglassEscalation").Inc()

	var collected []breakglassv1alpha1.BreakglassEscalation
	indexed := false
	if targetGroup != "" {
		var err error
		collected, indexed, err = em.collectEscalationsByFieldIndex(ctx, "spec.escalatedGroup", []string{targetGroup})
		if err != nil {
			return nil, err
		}
	}
	if !indexed {
		all, err := em.GetAllBreakglassEscalations(ctx)
		if err != nil {
			return nil, err
		}
		collected = all
		log.Debugw("Fell back to full target escalation scan", "cluster", cluster, "targetGroupHint", system.RedactGroupName(targetGroup), "totalEscalations", len(collected))
	} else {
		log.Debugw("Fetched escalation candidates with target-group index", "cluster", cluster, "targetGroupHint", system.RedactGroupName(targetGroup), "candidateCount", len(collected))
	}

	// Filter collected by cluster and allowed groups using shared helpers
	oidcPrefixes := em.getOIDCPrefixes()
	out := make([]breakglassv1alpha1.BreakglassEscalation, 0)
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

func NewEscalationManager(contextName string, resolver breakglass.GroupMemberResolver) (EscalationManager, error) {
	log := zap.S()
	log.Infow("Initializing EscalationManager", "context", contextName)
	cfg, err := config.GetConfigWithContext(contextName)
	if err != nil {
		log.Errorw("Failed to get config with context", "context", contextName, "error", err)
		return EscalationManager{}, fmt.Errorf("failed to get config with context %q: %w", contextName, err)
	}

	c, err := client.New(cfg, client.Options{
		Scheme: breakglass.Scheme,
	})
	if err != nil {
		log.Errorw("Failed to create new client", "error", err)
		return EscalationManager{}, fmt.Errorf("failed to create new client: %w", err)
	}

	log.Info("EscalationManager initialized successfully")
	return EscalationManager{Client: c, resolver: resolver, log: log}, nil
}

// EscalationManagerOption configures an EscalationManager during construction.
type EscalationManagerOption func(*EscalationManager)

// WithLogger sets a custom logger for the EscalationManager.
// If not provided, the global zap.S() logger is used as fallback.
// Passing nil is a no-op (the existing logger is retained).
func WithLogger(log *zap.SugaredLogger) EscalationManagerOption {
	return func(em *EscalationManager) {
		if log != nil {
			em.log = log
		}
	}
}

// WithConfigLoader sets a cached config loader for the EscalationManager.
// If not provided, the manager falls back to cfgpkg.Load() for each config read.
// Passing nil is a no-op (the existing loader is retained).
func WithConfigLoader(loader *cfgpkg.CachedLoader) EscalationManagerOption {
	return func(em *EscalationManager) {
		if loader != nil {
			em.configLoader = loader
		}
	}
}

// NewEscalationManagerWithClient constructs an EscalationManager backed by the provided controller-runtime client.
// Use this when a shared manager client (with cache/indexes) should be reused instead of creating a new rest.Config.
// Configuration is applied via functional options (WithLogger, WithConfigLoader).
func NewEscalationManagerWithClient(c client.Client, resolver breakglass.GroupMemberResolver, opts ...EscalationManagerOption) *EscalationManager {
	em := &EscalationManager{Client: c, resolver: resolver}
	for _, opt := range opts {
		if opt != nil {
			opt(em)
		}
	}
	return em
}

// SetResolver updates the GroupMemberResolver used for resolving group members.
// This should be called when the IdentityProvider configuration changes to ensure
// the EscalationManager uses the latest Keycloak group sync configuration.
// Thread-safe: Uses mutex to protect concurrent access to the resolver field.
func (em *EscalationManager) SetResolver(resolver breakglass.GroupMemberResolver) {
	em.resolverMu.Lock()
	defer em.resolverMu.Unlock()
	em.resolver = resolver
	em.getLogger().Infow("EscalationManager resolver updated")
}

// UpdateBreakglassEscalationStatus updates the given escalation resource status
func (em *EscalationManager) UpdateBreakglassEscalationStatus(ctx context.Context, esc breakglassv1alpha1.BreakglassEscalation) error {
	log := em.getLogger()
	log.Infow("Updating BreakglassEscalation status", "name", esc.Name)
	if err := breakglass.ApplyBreakglassEscalationStatus(ctx, em, &esc); err != nil {
		log.Errorw("Failed to update BreakglassEscalation status", "name", esc.Name, "error", err)
		return fmt.Errorf("failed to update BreakglassEscalation status %s: %w", esc.Name, err)
	}
	log.Infow("BreakglassEscalation status updated", "name", esc.Name)
	return nil
}
