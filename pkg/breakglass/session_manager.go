package breakglass

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"time"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/metrics"
	"github.com/telekom/k8s-breakglass/pkg/system"
	"github.com/telekom/k8s-breakglass/pkg/utils"
	"go.uber.org/zap"
	"golang.org/x/sync/singleflight"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
)

// SessionManager is kubernetes client based object for managing CRUD operation on BreakglassSession custom resource.
type SessionManager struct {
	client.Client
	reader              client.Reader
	liveReader          client.Reader
	liveFallbackMu      sync.Mutex
	liveFallbackAt      map[string]time.Time
	liveFallbackSweepAt time.Time
	liveFallbackFlight  singleflight.Group
	log                 *zap.SugaredLogger
	logFallbackOnce     sync.Once
}

const liveReaderNegativeCacheTTL = time.Second

// getLogger returns the injected logger or falls back to the global logger.
// Callers should prefer passing a logger via WithSessionLogger to avoid
// hidden global state dependencies.
func (c *SessionManager) getLogger() *zap.SugaredLogger {
	if c.log != nil {
		return c.log
	}
	c.logFallbackOnce.Do(func() {
		zap.S().Warn("SessionManager using global logger — use WithSessionLogger() in production")
	})
	return zap.S()
}

// SessionManagerOption configures a SessionManager during construction.
type SessionManagerOption func(*SessionManager)

// WithSessionLogger sets a custom logger for the SessionManager.
// If not provided, the global zap.S() logger is used as fallback.
// Passing nil is a no-op (the existing logger is retained).
func WithSessionLogger(log *zap.SugaredLogger) SessionManagerOption {
	return func(sm *SessionManager) {
		if log != nil {
			sm.log = log
		}
	}
}

// Deprecated: NewSessionManager creates an uncached client that reads directly from the
// API server. Prefer NewSessionManagerWithClient or NewSessionManagerWithClientAndReader
// with a cached manager client for consistent caching behavior.
func NewSessionManager(contextName string) (*SessionManager, error) {
	cfg, err := config.GetConfigWithContext(contextName)
	if err != nil {
		zap.S().Errorw("Failed to get config with context", "context", contextName, "error", err)
		return nil, fmt.Errorf("failed to get config with context %q: %w", contextName, err)
	}

	c, err := client.New(cfg, client.Options{
		Scheme: Scheme,
	})
	if err != nil {
		zap.S().Errorw("Failed to create new client", "error", err)
		return nil, fmt.Errorf("failed to create new client: %w", err)
	}

	log := zap.S().Named("session-manager")
	log.Infow("SessionManager initialized", "context", contextName)
	return &SessionManager{Client: c, reader: c, log: log}, nil
}

// NewSessionManagerWithClient allows embedding an existing controller-runtime client (e.g., from a shared manager)
// to avoid creating redundant rest.Config instances or duplicate caches. The provided client must already be
// configured with the Breakglass scheme.
// Configuration is applied via functional options (WithSessionLogger).
func NewSessionManagerWithClient(c client.Client, opts ...SessionManagerOption) *SessionManager {
	return NewSessionManagerWithClientAndReader(c, nil, opts...)
}

// NewSessionManagerWithClientAndReader allows using a cached client for writes and an optional reader
// (e.g., APIReader) for consistent reads when required.
// Configuration is applied via functional options (WithSessionLogger).
func NewSessionManagerWithClientAndReader(c client.Client, reader client.Reader, opts ...SessionManagerOption) *SessionManager {
	sm := &SessionManager{Client: c, reader: reader}
	if reader == nil {
		sm.reader = c
	} else {
		sm.liveReader = reader
	}
	for _, opt := range opts {
		if opt != nil {
			opt(sm)
		}
	}
	return sm
}

// Reader returns the underlying client.Reader used for consistent reads.
// This is typically the uncached APIReader when the SessionManager was constructed
// via NewSessionManagerWithClientAndReader. Other components (e.g., ActivityTracker)
// can use this to bypass the informer cache for up-to-date reads.
func (c *SessionManager) Reader() client.Reader {
	if c.reader != nil {
		return c.reader
	}
	return c.Client
}

func (c *SessionManager) list(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	if c.reader != nil {
		return c.reader.List(ctx, list, opts...)
	}
	return c.Client.List(ctx, list, opts...)
}

// IsFieldIndexError returns true if the error indicates a missing field index
// or unsupported field selector—i.e. it is safe to fall back to a full list +
// client-side filter.  All other errors (RBAC, network, etcd) are real failures.
//
// NOTE: controller-runtime does not expose typed errors for index-not-found
// conditions (as of v0.23.x). This function relies on substring matching
// against known error messages. If controller-runtime changes wording in a
// future release, the regression tests in session_manager_test.go
// (TestIsFieldIndexError*) will catch the change.
func IsFieldIndexError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	// controller-runtime cache: "no index with name <field> has been registered"
	// controller-runtime cache: "Index with name <field> does not exist"
	// generic phrasing: "field index", "no indexer"
	// apiserver field selectors: "field label not supported"
	return strings.Contains(msg, "field index") ||
		strings.Contains(msg, "no indexer") ||
		strings.Contains(msg, "no index with name") ||
		strings.Contains(msg, "field label not supported") ||
		strings.Contains(msg, "Index with name")
}

func SessionSelector(name, username, cluster, group string) string {
	selectors := []string{}

	if name != "" {
		return fmt.Sprintf("metadata.name=%s", name)
	}

	if username != "" {
		selectors = append(selectors, fmt.Sprintf("spec.user=%s", username))
	}
	if cluster != "" {
		selectors = append(selectors, fmt.Sprintf("spec.cluster=%s", cluster))
	}
	if group != "" {
		selectors = append(selectors, fmt.Sprintf("spec.grantedGroup=%s", group))
	}

	return strings.Join(selectors, ",")
}

// Get all stored GetClusterGroupAccess
func (c *SessionManager) GetAllBreakglassSessions(ctx context.Context) ([]breakglassv1alpha1.BreakglassSession, error) {
	log := c.getLogger()
	log.Debug("Fetching all BreakglassSessions")
	cgal := breakglassv1alpha1.BreakglassSessionList{}
	if err := c.list(ctx, &cgal); err != nil {
		log.Errorw("Failed to get BreakglassSessionList", "error", err)
		return nil, fmt.Errorf("failed to get BreakglassSessionList: %w", err)
	}
	log.Infow("Fetched BreakglassSessions", "count", len(cgal.Items))
	return cgal.Items, nil
}

// GetSessionsByState returns all sessions in the specified state.
// Uses the status.state field index for efficient lookup when available.
// Falls back to listing all and filtering if index is not registered.
func (c *SessionManager) GetSessionsByState(ctx context.Context,
	state breakglassv1alpha1.BreakglassSessionState,
) ([]breakglassv1alpha1.BreakglassSession, error) {
	return c.GetSessionsByStates(ctx, []breakglassv1alpha1.BreakglassSessionState{state})
}

// GetSessionsByStates returns all sessions matching any of the specified states.
// It uses the status.state field index for efficient lookup when available. If
// the index is missing, it falls back to a single full list plus client-side
// filtering instead of issuing one full-list fallback per requested state.
func (c *SessionManager) GetSessionsByStates(ctx context.Context,
	states []breakglassv1alpha1.BreakglassSessionState,
) ([]breakglassv1alpha1.BreakglassSession, error) {
	log := c.getLogger()

	stateSet := make(map[breakglassv1alpha1.BreakglassSessionState]struct{}, len(states))
	uniqueStates := make([]breakglassv1alpha1.BreakglassSessionState, 0, len(states))
	for _, state := range states {
		if _, exists := stateSet[state]; exists {
			continue
		}
		stateSet[state] = struct{}{}
		uniqueStates = append(uniqueStates, state)
	}
	if len(uniqueStates) == 0 {
		return nil, nil
	}

	log.Debugw("Fetching BreakglassSessions by states (using field index)", "states", uniqueStates)
	sessions := make([]breakglassv1alpha1.BreakglassSession, 0)
	seen := make(map[string]struct{})
	for _, state := range uniqueStates {
		bsl := breakglassv1alpha1.BreakglassSessionList{}
		// Use the cached client (c.Client.List) for indexed queries.
		// Field indexes are only available in the cache, not via APIReader.
		if err := c.Client.List(ctx, &bsl, client.MatchingFields{"status.state": string(state)}); err != nil {
			if !IsFieldIndexError(err) {
				// Real error (RBAC, network, etc.) — return it directly.
				log.Errorw("Failed to list BreakglassSessions by state", "state", state, "error", err)
				return nil, fmt.Errorf("failed to list BreakglassSessions by state: %w", err)
			}
			// Field index not available — fall back to one full list and filter
			// all requested states in-memory.
			log.Debugw("Field index not available; falling back to client-side filtering", "states", uniqueStates, "error", err)
			all, err := c.GetAllBreakglassSessions(ctx)
			if err != nil {
				return nil, err
			}
			filtered := make([]breakglassv1alpha1.BreakglassSession, 0, len(all))
			for _, s := range all {
				if _, ok := stateSet[s.Status.State]; ok {
					filtered = append(filtered, s)
				}
			}
			return filtered, nil
		}
		for _, session := range bsl.Items {
			key := session.Namespace + "/" + session.Name
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			sessions = append(sessions, session)
		}
	}
	log.Infow("Fetched BreakglassSessions by states (indexed)", "count", len(sessions), "states", uniqueStates)
	return sessions, nil
}

// Get all stored GetClusterGroupAccess
func (c *SessionManager) GetBreakglassSessionByName(ctx context.Context, name string) (breakglassv1alpha1.BreakglassSession, error) {
	log := c.getLogger()
	// Try direct GET first (works when object namespace is part of the object stored locally)
	log.Debugw("Fetching BreakglassSession by name (direct GET)", system.NamespacedFields(name, "")...)
	bs := breakglassv1alpha1.BreakglassSession{}

	// controller-runtime client requires a namespace when a name is provided in ObjectKey.
	// If the object was created with a namespace, a direct Get with empty namespace will fail.
	// In that case, fall back to listing sessions across all namespaces using a field selector on metadata.name.
	if err := c.Get(ctx, client.ObjectKey{Name: name}, &bs); err == nil {
		log.Infow("Fetched BreakglassSession by name (direct GET)", system.NamespacedFields(name, bs.Namespace)...)
		return bs, nil
	} else {
		log.Debugw("Direct GET failed; falling back to list across namespaces", "name", name, "error", err)
	}

	// Try cache-backed field index before falling back to selector-based listing
	indexed := breakglassv1alpha1.BreakglassSessionList{}
	if err := c.List(ctx, &indexed, client.MatchingFields{"metadata.name": name}); err == nil {
		switch len(indexed.Items) {
		case 0:
			log.Debugw("Field index lookup returned no sessions; falling back to selector", "name", name)
		case 1:
			found := indexed.Items[0]
			log.Infow("Fetched BreakglassSession by name (field index)", system.NamespacedFields(found.Name, found.Namespace)...)
			return found, nil
		default:
			namespaces := make([]string, 0, len(indexed.Items))
			for _, it := range indexed.Items {
				namespaces = append(namespaces, it.Namespace)
			}
			msg := fmt.Sprintf("multiple BreakglassSessions with name %q found in namespaces: %s", name, strings.Join(namespaces, ","))
			log.Errorw("Ambiguous BreakglassSession name across namespaces (field index)", "name", name, "namespaces", namespaces)
			return bs, fmt.Errorf("%s", msg)
		}
	} else {
		log.Debugw("Field index lookup failed; falling back to selector", "name", name, "error", err)
	}

	// Fallback: list across namespaces using a metadata.name field selector
	selector := fmt.Sprintf("metadata.name=%s", name)
	fs, ferr := fields.ParseSelector(selector)
	if ferr != nil {
		log.Errorw("Failed to parse field selector for fallback lookup", "selector", selector, "error", ferr)
		return bs, fmt.Errorf("failed to create field selector %q: %w", selector, ferr)
	}

	bsl := breakglassv1alpha1.BreakglassSessionList{}
	if err := c.list(ctx, &bsl, &client.ListOptions{FieldSelector: fs}); err != nil {
		log.Errorw("Failed to list BreakglassSessionList for fallback lookup", "selector", selector, "error", err)
		return bs, fmt.Errorf("failed to list BreakglassSessionList for fallback lookup: %w", err)
	}

	if len(bsl.Items) == 0 {
		log.Debugw("BreakglassSession not found by name across namespaces", "name", name)
		return bs, apierrors.NewNotFound(schema.GroupResource{Group: breakglassv1alpha1.GroupVersion.Group, Resource: "breakglasssessions"}, name)
	}

	if len(bsl.Items) > 1 {
		// Ambiguous: multiple sessions with same name exist in different namespaces.
		namespaces := make([]string, 0, len(bsl.Items))
		for _, it := range bsl.Items {
			namespaces = append(namespaces, it.Namespace)
		}
		msg := fmt.Sprintf("multiple BreakglassSessions with name %q found in namespaces: %s", name, strings.Join(namespaces, ","))
		log.Errorw("Ambiguous BreakglassSession name across namespaces", "name", name, "namespaces", namespaces)
		return bs, fmt.Errorf("%s", msg)
	}

	// Single match: return it
	found := bsl.Items[0]
	log.Infow("Fetched BreakglassSession by name (fallback list)", system.NamespacedFields(found.Name, found.Namespace)...)
	return found, nil
}

// GetUserBreakglassSessions returns all sessions for a user across all clusters.
// Uses the spec.user field index for efficient lookup when available.
// Falls back to listing all and filtering if index is not registered.
func (c *SessionManager) GetUserBreakglassSessions(ctx context.Context,
	user string,
) ([]breakglassv1alpha1.BreakglassSession, error) {
	log := c.getLogger()
	log.Debugw("Fetching BreakglassSessions for user (using field index)", "user", user)
	bsl := breakglassv1alpha1.BreakglassSessionList{}
	// Use the cached client (c.Client.List) for indexed queries.
	// Field indexes are only available in the cache, not via APIReader.
	if err := c.Client.List(ctx, &bsl, client.MatchingFields{"spec.user": user}); err != nil {
		if !IsFieldIndexError(err) {
			log.Errorw("Failed to list BreakglassSessions for user", "user", user, "error", err)
			return nil, fmt.Errorf("failed to list BreakglassSessions for user: %w", err)
		}
		// Field index not available — fall back to client-side filtering.
		log.Debugw("Field index not available; falling back to client-side filtering", "user", user, "error", err)
		all, err := c.GetAllBreakglassSessions(ctx)
		if err != nil {
			return nil, err
		}
		filtered := make([]breakglassv1alpha1.BreakglassSession, 0, len(all))
		for _, s := range all {
			if s.Spec.User == user {
				filtered = append(filtered, s)
			}
		}
		return filtered, nil
	}
	log.Infow("Fetched BreakglassSessions for user (indexed)", "count", len(bsl.Items), "user", user)
	return bsl.Items, nil
}

// Get GetClusterGroupAccess by cluster name.
// Uses the spec.cluster and spec.user field indexes for efficient lookup when available.
// Falls back to listing all and filtering if indexes are not registered.
func (c *SessionManager) GetClusterUserBreakglassSessions(ctx context.Context,
	cluster string,
	user string,
) ([]breakglassv1alpha1.BreakglassSession, error) {
	log := c.getLogger()
	log.Debugw("Fetching BreakglassSessions for cluster and user (using field index)", "cluster", cluster, "user", user)
	bsl := breakglassv1alpha1.BreakglassSessionList{}
	// Use the cached client (c.Client.List) for indexed queries.
	// Field indexes are only available in the cache, not via APIReader.
	if err := c.Client.List(ctx, &bsl, client.MatchingFields{"spec.cluster": cluster, "spec.user": user}); err != nil {
		if !IsFieldIndexError(err) {
			log.Errorw("Failed to list BreakglassSessions for cluster/user", "cluster", cluster, "user", user, "error", err)
			return nil, fmt.Errorf("failed to list BreakglassSessions for cluster/user: %w", err)
		}
		// Field index not available — fall back to client-side filtering.
		log.Debugw("Field index not available; falling back to client-side filtering", "cluster", cluster, "user", user, "error", err)
		all, err := c.GetAllBreakglassSessions(ctx)
		if err != nil {
			return nil, err
		}
		filtered := make([]breakglassv1alpha1.BreakglassSession, 0, len(all))
		for _, s := range all {
			if s.Spec.Cluster == cluster && s.Spec.User == user {
				filtered = append(filtered, s)
			}
		}
		return filtered, nil
	}
	if c.liveReader != nil && !hasAuthorizationEligibleSession(bsl.Items, time.Now()) {
		fallbackKey := cluster + "\x00" + user
		fallback, refreshed := c.fetchLiveClusterUserBreakglassSessions(ctx, cluster, user, fallbackKey, log)
		if !refreshed || len(fallback) == 0 {
			return bsl.Items, nil
		}
		result := mergeSessionResults(bsl.Items, fallback)
		log.Infow("Fetched BreakglassSessions from live reader after cache lookup found no eligible session",
			"count", len(result), "cluster", cluster, "user", user)
		return result, nil
	}
	log.Infow("Fetched BreakglassSessions (indexed)", "count", len(bsl.Items), "cluster", cluster, "user", user)
	return bsl.Items, nil
}

// RefreshClusterUserBreakglassSessions refreshes a cached cluster/user lookup
// after the cached sessions failed to authorize a specific request.
func (c *SessionManager) RefreshClusterUserBreakglassSessions(ctx context.Context,
	cluster string,
	user string,
) ([]breakglassv1alpha1.BreakglassSession, bool, error) {
	cached, err := c.GetClusterUserBreakglassSessions(ctx, cluster, user)
	if err != nil || c.liveReader == nil {
		return cached, false, err
	}
	fallbackKey := cluster + "\x00" + user
	live, refreshed := c.fetchLiveClusterUserBreakglassSessions(ctx, cluster, user, fallbackKey, c.getLogger())
	if !refreshed || len(live) == 0 {
		return cached, refreshed, nil
	}
	if sessionResultsEqual(cached, live) {
		c.recordLiveReaderFallback(fallbackKey, time.Now())
	}
	return mergeSessionResults(cached, live), true, nil
}

func (c *SessionManager) fetchLiveClusterUserBreakglassSessions(ctx context.Context,
	cluster string,
	user string,
	fallbackKey string,
	log *zap.SugaredLogger,
) ([]breakglassv1alpha1.BreakglassSession, bool) {
	if c.liveReaderFallbackSuppressed(fallbackKey, time.Now()) {
		return nil, false
	}
	value, _, _ := c.liveFallbackFlight.Do(fallbackKey, func() (interface{}, error) {
		var liveList breakglassv1alpha1.BreakglassSessionList
		err := c.liveReader.List(ctx, &liveList, client.MatchingFields{
			"spec.cluster": cluster,
			"spec.user":    user,
		})
		if err != nil && IsFieldIndexError(err) {
			err = c.liveReader.List(ctx, &liveList)
		}
		if err != nil {
			log.Warnw("Failed to refresh BreakglassSessions from live reader after cache lookup found no eligible session",
				"cluster", cluster, "user", user, "error", err)
			return liveFallbackResult{}, nil
		}
		filtered := make([]breakglassv1alpha1.BreakglassSession, 0, len(liveList.Items))
		for _, s := range liveList.Items {
			if s.Spec.Cluster == cluster && s.Spec.User == user {
				filtered = append(filtered, s)
			}
		}
		if hasAuthorizationEligibleSession(filtered, time.Now()) {
			return liveFallbackResult{sessions: filtered, success: true}, nil
		}
		c.recordLiveReaderFallback(fallbackKey, time.Now())
		return liveFallbackResult{sessions: filtered, success: true}, nil
	})
	fallback, ok := value.(liveFallbackResult)
	if !ok || !fallback.success {
		return nil, false
	}
	return fallback.sessions, true
}

type liveFallbackResult struct {
	sessions []breakglassv1alpha1.BreakglassSession
	success  bool
}

func hasAuthorizationEligibleSession(sessions []breakglassv1alpha1.BreakglassSession, now time.Time) bool {
	for _, session := range sessions {
		if IsSessionAuthorizationEligible(session, now) {
			return true
		}
	}
	return false
}

func mergeSessionResults(cached, live []breakglassv1alpha1.BreakglassSession) []breakglassv1alpha1.BreakglassSession {
	result := append([]breakglassv1alpha1.BreakglassSession(nil), cached...)
	positions := make(map[string]int, len(result))
	for _, session := range result {
		positions[session.Namespace+"/"+session.Name] = len(positions)
	}
	for _, session := range live {
		key := session.Namespace + "/" + session.Name
		if position, exists := positions[key]; exists {
			result[position] = session
			continue
		}
		positions[key] = len(result)
		result = append(result, session)
	}
	return result
}

func sessionResultsEqual(left, right []breakglassv1alpha1.BreakglassSession) bool {
	if len(left) != len(right) {
		return false
	}
	rightByKey := make(map[string]breakglassv1alpha1.BreakglassSession, len(right))
	for _, session := range right {
		rightByKey[session.Namespace+"/"+session.Name] = session
	}
	for _, session := range left {
		other, ok := rightByKey[session.Namespace+"/"+session.Name]
		if !ok ||
			!reflect.DeepEqual(session.Spec, other.Spec) ||
			!reflect.DeepEqual(session.Status, other.Status) {
			return false
		}
	}
	return true
}

func (c *SessionManager) liveReaderFallbackSuppressed(key string, now time.Time) bool {
	c.liveFallbackMu.Lock()
	defer c.liveFallbackMu.Unlock()

	if c.liveFallbackSweepAt.IsZero() || now.Sub(c.liveFallbackSweepAt) >= liveReaderNegativeCacheTTL {
		for cachedKey, last := range c.liveFallbackAt {
			if now.Sub(last) >= liveReaderNegativeCacheTTL {
				delete(c.liveFallbackAt, cachedKey)
			}
		}
		c.liveFallbackSweepAt = now
	}
	if last, ok := c.liveFallbackAt[key]; ok && now.Sub(last) < liveReaderNegativeCacheTTL {
		return true
	}
	return false
}

func (c *SessionManager) recordLiveReaderFallback(key string, now time.Time) {
	c.liveFallbackMu.Lock()
	defer c.liveFallbackMu.Unlock()
	if c.liveFallbackAt == nil {
		c.liveFallbackAt = make(map[string]time.Time)
	}
	c.liveFallbackAt[key] = now
}

func (c *SessionManager) clearLiveReaderFallback(key string) {
	c.liveFallbackMu.Lock()
	defer c.liveFallbackMu.Unlock()
	delete(c.liveFallbackAt, key)
}

// GetBreakglassSessions with custom field selector string.
func (c *SessionManager) GetBreakglassSessionsWithSelectorString(ctx context.Context,
	selectorString string,
) ([]breakglassv1alpha1.BreakglassSession, error) {
	log := c.getLogger()
	log.Debugw("Fetching BreakglassSessions with selector string", "selector", selectorString)
	bsl := breakglassv1alpha1.BreakglassSessionList{}

	fs, err := fields.ParseSelector(selectorString)
	if err != nil {
		log.Errorw("Failed to create field selector", "selector", selectorString, "error", err)
		return nil, fmt.Errorf("failed to create field selector %q : %w", selectorString, err)
	}

	if err := c.list(ctx, &bsl, &client.ListOptions{FieldSelector: fs}); err != nil {
		log.Errorw("Failed to list BreakglassSessionList with string selector", "selector", selectorString, "error", err)
		return nil, fmt.Errorf("failed to list BreakglassSessionList with string selector: %w", err)
	}
	log.Infow("Fetched BreakglassSessions with selector string", "count", len(bsl.Items), "selector", selectorString)
	return bsl.Items, nil
}

// GetBreakglassSessions with custom field selector.
func (c *SessionManager) GetBreakglassSessionsWithSelector(ctx context.Context,
	fs fields.Selector,
) ([]breakglassv1alpha1.BreakglassSession, error) {
	log := c.getLogger()
	log.Debugw("Fetching BreakglassSessions with selector", "selector", fs.String())
	bsl := breakglassv1alpha1.BreakglassSessionList{}

	if err := c.list(ctx, &bsl, &client.ListOptions{FieldSelector: fs}); err != nil {
		log.Errorw("Failed to list BreakglassSessionList with selector", "selector", fs.String(), "error", err)
		return nil, fmt.Errorf("failed to list BreakglassSessionList with selector: %w", err)
	}
	log.Infow("Fetched BreakglassSessions with selector", "count", len(bsl.Items), "selector", fs.String())
	return bsl.Items, nil
}

// Add new breakglass session.
// Note: Uses Create instead of SSA because GenerateName requires Create semantics.
// For updates, use UpdateBreakglassSession which uses SSA.
func (c *SessionManager) AddBreakglassSession(ctx context.Context, bs *breakglassv1alpha1.BreakglassSession) error {
	log := c.getLogger()
	log.Infow("Adding new BreakglassSession", append(system.NamespacedFields(bs.Name, bs.Namespace), "user", bs.Spec.User, "cluster", bs.Spec.Cluster)...)
	if err := c.Create(ctx, bs); err != nil {
		log.Errorw("Failed to create new BreakglassSession", append(system.NamespacedFields(bs.Name, bs.Namespace), "error", err)...)
		return fmt.Errorf("failed to create new BreakglassSession: %w", err)
	}
	log.Infow("BreakglassSession created successfully", system.NamespacedFields(bs.Name, bs.Namespace)...)
	// Emit metric for created session (cluster may be in spec)
	metrics.SessionCreated.WithLabelValues(bs.Spec.Cluster).Inc()

	// Track session creation with IDP if specified
	if bs.Spec.IdentityProviderName != "" {
		metrics.SessionCreatedWithIDP.WithLabelValues(bs.Spec.IdentityProviderName).Inc()
	}

	return nil
}

// Update breakglass session.
func (c *SessionManager) UpdateBreakglassSession(ctx context.Context, bs breakglassv1alpha1.BreakglassSession) error {
	log := c.getLogger()
	log.Infow("Updating BreakglassSession", system.NamespacedFields(bs.Name, bs.Namespace)...)
	if bs.TypeMeta.APIVersion == "" || bs.TypeMeta.Kind == "" {
		bs.TypeMeta = metav1.TypeMeta{
			APIVersion: breakglassv1alpha1.GroupVersion.String(),
			Kind:       "BreakglassSession",
		}
	}
	if err := utils.ApplyObject(ctx, c.Client, &bs); err != nil {
		log.Errorw("Failed to update BreakglassSession", append(system.NamespacedFields(bs.Name, bs.Namespace), "error", err)...)
		return fmt.Errorf("failed to update BreakglassSession %s/%s: %w", bs.Namespace, bs.Name, err)
	}
	log.Infow("BreakglassSession updated successfully", system.NamespacedFields(bs.Name, bs.Namespace)...)
	metrics.SessionUpdated.WithLabelValues(bs.Spec.Cluster).Inc()
	return nil
}

func (c *SessionManager) UpdateBreakglassSessionStatus(ctx context.Context, bs breakglassv1alpha1.BreakglassSession) error {
	log := c.getLogger()
	log.Infow("Updating BreakglassSession status", system.NamespacedFields(bs.Name, bs.Namespace)...)

	// Always fetch current state once to get Namespace, ResourceVersion, and Generation
	// This avoids duplicate API calls while ensuring kstatus compliance
	current, err := c.GetBreakglassSessionByName(ctx, bs.Name)
	if err != nil {
		log.Errorw("Failed to resolve BreakglassSession before status update", append(system.NamespacedFields(bs.Name, bs.Namespace), "error", err)...)
		return fmt.Errorf("failed to resolve BreakglassSession %s before status update: %w", bs.Name, err)
	}

	// Populate missing fields from current state
	if bs.Namespace == "" {
		bs.Namespace = current.Namespace
	}
	if bs.ResourceVersion == "" {
		bs.ResourceVersion = current.ResourceVersion
	}
	// Set observedGeneration for kstatus compliance
	bs.Status.ObservedGeneration = current.Generation
	if err := applyBreakglassSessionStatus(ctx, c, &bs); err != nil {
		log.Errorw("Failed to update BreakglassSession status", append(system.NamespacedFields(bs.Name, bs.Namespace), "error", err)...)
		return fmt.Errorf("failed to update BreakglassSession status %s/%s: %w", bs.Namespace, bs.Name, err)
	}
	log.Infow("BreakglassSession status updated successfully", system.NamespacedFields(bs.Name, bs.Namespace)...)
	return nil
}

// DeleteBreakglassSession deletes the given BreakglassSession and emits a metric when successful.
func (c *SessionManager) DeleteBreakglassSession(ctx context.Context, bs *breakglassv1alpha1.BreakglassSession) error {
	log := c.getLogger()
	if err := c.Delete(ctx, bs); err != nil {
		log.Errorw("Failed to delete BreakglassSession", append(system.NamespacedFields(bs.Name, bs.Namespace), "error", err)...)
		return fmt.Errorf("failed to delete breakglass session: %w", err)
	}
	log.Infow("BreakglassSession deleted successfully", system.NamespacedFields(bs.Name, bs.Namespace)...)
	metrics.SessionDeleted.WithLabelValues(bs.Spec.Cluster).Inc()
	return nil
}
