package breakglass

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/metrics"
	"github.com/telekom/k8s-breakglass/pkg/system"
	"go.uber.org/zap"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
)

// SessionManager is kubernetes client based object for managing CRUD operation on BreakglassSession custom resource.
type SessionManager struct {
	client.Client
	reader client.Reader
}

var ErrAccessNotFound = errors.New("access not found")

func NewSessionManager(contextName string) (SessionManager, error) {
	cfg, err := config.GetConfigWithContext(contextName)
	if err != nil {
		zap.S().Errorw("Failed to get config with context", "context", contextName, "error", err.Error())
		return SessionManager{}, fmt.Errorf("failed to get config with context %q: %w", contextName, err)
	}

	c, err := client.New(cfg, client.Options{
		Scheme: Scheme,
	})
	if err != nil {
		zap.S().Errorw("Failed to create new client", "error", err.Error())
		return SessionManager{}, fmt.Errorf("failed to create new client: %w", err)
	}

	zap.S().Infow("SessionManager initialized", "context", contextName)
	return SessionManager{Client: c, reader: c}, nil
}

// NewSessionManagerWithClient allows embedding an existing controller-runtime client (e.g., from a shared manager)
// to avoid creating redundant rest.Config instances or duplicate caches. The provided client must already be
// configured with the Breakglass scheme.
func NewSessionManagerWithClient(c client.Client) SessionManager {
	return NewSessionManagerWithClientAndReader(c, c)
}

// NewSessionManagerWithClientAndReader allows using a cached client for writes and an optional reader
// (e.g., APIReader) for consistent reads when required.
func NewSessionManagerWithClientAndReader(c client.Client, reader client.Reader) SessionManager {
	if reader == nil {
		reader = c
	}
	return SessionManager{Client: c, reader: reader}
}

func (c SessionManager) list(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	if c.reader != nil {
		return c.reader.List(ctx, list, opts...)
	}
	return c.Client.List(ctx, list, opts...)
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
func (c SessionManager) GetAllBreakglassSessions(ctx context.Context) ([]v1alpha1.BreakglassSession, error) {
	zap.S().Debug("Fetching all BreakglassSessions")
	cgal := v1alpha1.BreakglassSessionList{}
	if err := c.list(ctx, &cgal); err != nil {
		zap.S().Errorw("Failed to get BreakglassSessionList", "error", err.Error())
		return nil, fmt.Errorf("failed to get BreakglassSessionList: %w", err)
	}
	zap.S().Infow("Fetched BreakglassSessions", "count", len(cgal.Items))
	return cgal.Items, nil
}

// Get all stored GetClusterGroupAccess
func (c SessionManager) GetBreakglassSessionByName(ctx context.Context, name string) (v1alpha1.BreakglassSession, error) {
	// Try direct GET first (works when object namespace is part of the object stored locally)
	zap.S().Debugw("Fetching BreakglassSession by name (direct GET)", system.NamespacedFields(name, "")...)
	bs := v1alpha1.BreakglassSession{}

	// controller-runtime client requires a namespace when a name is provided in ObjectKey.
	// If the object was created with a namespace, a direct Get with empty namespace will fail.
	// In that case, fall back to listing sessions across all namespaces using a field selector on metadata.name.
	if err := c.Get(ctx, client.ObjectKey{Name: name}, &bs); err == nil {
		zap.S().Infow("Fetched BreakglassSession by name (direct GET)", system.NamespacedFields(name, bs.Namespace)...)
		return bs, nil
	} else {
		zap.S().Debugw("Direct GET failed; falling back to list across namespaces", "name", name, "error", err.Error())
	}

	// Try cache-backed field index before falling back to selector-based listing
	indexed := v1alpha1.BreakglassSessionList{}
	if err := c.List(ctx, &indexed, client.MatchingFields{"metadata.name": name}); err == nil {
		switch len(indexed.Items) {
		case 0:
			zap.S().Debugw("Field index lookup returned no sessions; falling back to selector", "name", name)
		case 1:
			found := indexed.Items[0]
			zap.S().Infow("Fetched BreakglassSession by name (field index)", system.NamespacedFields(found.Name, found.Namespace)...)
			return found, nil
		default:
			namespaces := make([]string, 0, len(indexed.Items))
			for _, it := range indexed.Items {
				namespaces = append(namespaces, it.Namespace)
			}
			msg := fmt.Sprintf("multiple BreakglassSessions with name %q found in namespaces: %s", name, strings.Join(namespaces, ","))
			zap.S().Errorw("Ambiguous BreakglassSession name across namespaces (field index)", "name", name, "namespaces", namespaces)
			return bs, fmt.Errorf("%s", msg)
		}
	} else {
		zap.S().Debugw("Field index lookup failed; falling back to selector", "name", name, "error", err.Error())
	}

	// Fallback: list across namespaces using a metadata.name field selector
	selector := fmt.Sprintf("metadata.name=%s", name)
	fs, ferr := fields.ParseSelector(selector)
	if ferr != nil {
		zap.S().Errorw("Failed to parse field selector for fallback lookup", "selector", selector, "error", ferr.Error())
		return bs, fmt.Errorf("failed to create field selector %q: %w", selector, ferr)
	}

	bsl := v1alpha1.BreakglassSessionList{}
	if err := c.list(ctx, &bsl, &client.ListOptions{FieldSelector: fs}); err != nil {
		zap.S().Errorw("Failed to list BreakglassSessionList for fallback lookup", "selector", selector, "error", err.Error())
		return bs, fmt.Errorf("failed to list BreakglassSessionList for fallback lookup: %w", err)
	}

	if len(bsl.Items) == 0 {
		zap.S().Debugw("BreakglassSession not found by name across namespaces", "name", name)
		return bs, apierrors.NewNotFound(schema.GroupResource{Group: v1alpha1.GroupVersion.Group, Resource: "breakglasssessions"}, name)
	}

	if len(bsl.Items) > 1 {
		// Ambiguous: multiple sessions with same name exist in different namespaces.
		namespaces := make([]string, 0, len(bsl.Items))
		for _, it := range bsl.Items {
			namespaces = append(namespaces, it.Namespace)
		}
		msg := fmt.Sprintf("multiple BreakglassSessions with name %q found in namespaces: %s", name, strings.Join(namespaces, ","))
		zap.S().Errorw("Ambiguous BreakglassSession name across namespaces", "name", name, "namespaces", namespaces)
		return bs, fmt.Errorf("%s", msg)
	}

	// Single match: return it
	found := bsl.Items[0]
	zap.S().Infow("Fetched BreakglassSession by name (fallback list)", system.NamespacedFields(found.Name, found.Namespace)...)
	return found, nil
}

// Get GetClusterGroupAccess by cluster name.
func (c SessionManager) GetClusterUserBreakglassSessions(ctx context.Context,
	cluster string,
	user string,
) ([]v1alpha1.BreakglassSession, error) {
	zap.S().Debugw("Fetching BreakglassSessions for cluster and user (using field index)", "cluster", cluster, "user", user)
	bsl := v1alpha1.BreakglassSessionList{}
	// Use MatchingFields to leverage field indexers registered by the manager
	if err := c.List(ctx, &bsl, client.MatchingFields{"spec.cluster": cluster, "spec.user": user}); err != nil {
		zap.S().Debugw("Field-index based list failed; falling back to selector string", "error", err)
		selector := fmt.Sprintf("spec.cluster=%s,spec.user=%s",
			cluster,
			user)
		return c.GetBreakglassSessionsWithSelectorString(ctx, selector)
	}
	zap.S().Infow("Fetched BreakglassSessions (indexed)", "count", len(bsl.Items), "cluster", cluster, "user", user)
	return bsl.Items, nil
}

// GetBreakglassSessions with custom field selector string.
func (c SessionManager) GetBreakglassSessionsWithSelectorString(ctx context.Context,
	selectorString string,
) ([]v1alpha1.BreakglassSession, error) {
	zap.S().Debugw("Fetching BreakglassSessions with selector string", "selector", selectorString)
	bsl := v1alpha1.BreakglassSessionList{}

	fs, err := fields.ParseSelector(selectorString)
	if err != nil {
		zap.S().Errorw("Failed to create field selector", "selector", selectorString, "error", err)
		return nil, fmt.Errorf("failed to create field selector %q : %w", selectorString, err)
	}

	if err := c.list(ctx, &bsl, &client.ListOptions{FieldSelector: fs}); err != nil {
		zap.S().Errorw("Failed to list BreakglassSessionList with string selector", "selector", selectorString, "error", err.Error())
		return nil, fmt.Errorf("failed to list BreakglassSessionList with string selector: %w", err)
	}
	zap.S().Infow("Fetched BreakglassSessions with selector string", "count", len(bsl.Items), "selector", selectorString)
	return bsl.Items, nil
}

// GetBreakglassSessions with custom field selector.
func (c SessionManager) GetBreakglassSessionsWithSelector(ctx context.Context,
	fs fields.Selector,
) ([]v1alpha1.BreakglassSession, error) {
	zap.S().Debugw("Fetching BreakglassSessions with selector", "selector", fs.String())
	bsl := v1alpha1.BreakglassSessionList{}

	if err := c.list(ctx, &bsl, &client.ListOptions{FieldSelector: fs}); err != nil {
		zap.S().Errorw("Failed to list BreakglassSessionList with selector", "selector", fs.String(), "error", err.Error())
		return nil, fmt.Errorf("failed to list BreakglassSessionList with selector: %w", err)
	}
	zap.S().Infow("Fetched BreakglassSessions with selector", "count", len(bsl.Items), "selector", fs.String())
	return bsl.Items, nil
}

// Add new breakglass session.
func (c SessionManager) AddBreakglassSession(ctx context.Context, bs *v1alpha1.BreakglassSession) error {
	zap.S().Infow("Adding new BreakglassSession", append(system.NamespacedFields(bs.Name, bs.Namespace), "user", bs.Spec.User, "cluster", bs.Spec.Cluster)...)
	if err := c.Create(ctx, bs); err != nil {
		zap.S().Errorw("Failed to create new BreakglassSession", append(system.NamespacedFields(bs.Name, bs.Namespace), "error", err.Error())...)
		return fmt.Errorf("failed to create new BreakglassSession: %w", err)
	}
	zap.S().Infow("BreakglassSession created successfully", system.NamespacedFields(bs.Name, bs.Namespace)...)
	// Emit metric for created session (cluster may be in spec)
	metrics.SessionCreated.WithLabelValues(bs.Spec.Cluster).Inc()

	// Track session creation with IDP if specified
	if bs.Spec.IdentityProviderName != "" {
		metrics.SessionCreatedWithIDP.WithLabelValues(bs.Spec.IdentityProviderName).Inc()
	}

	return nil
}

// Update breakglass session.
func (c SessionManager) UpdateBreakglassSession(ctx context.Context, bs v1alpha1.BreakglassSession) error {
	zap.S().Infow("Updating BreakglassSession", system.NamespacedFields(bs.Name, bs.Namespace)...)
	if err := c.Update(ctx, &bs); err != nil {
		zap.S().Errorw("Failed to update BreakglassSession", append(system.NamespacedFields(bs.Name, bs.Namespace), "error", err.Error())...)
		return fmt.Errorf("failed to update BreakglassSession %s/%s: %w", bs.Namespace, bs.Name, err)
	}
	zap.S().Infow("BreakglassSession updated successfully", system.NamespacedFields(bs.Name, bs.Namespace)...)
	metrics.SessionUpdated.WithLabelValues(bs.Spec.Cluster).Inc()
	return nil
}

func (c SessionManager) UpdateBreakglassSessionStatus(ctx context.Context, bs v1alpha1.BreakglassSession) error {
	zap.S().Infow("Updating BreakglassSession status", system.NamespacedFields(bs.Name, bs.Namespace)...)

	// Always fetch current state once to get Namespace, ResourceVersion, and Generation
	// This avoids duplicate API calls while ensuring kstatus compliance
	current, err := c.GetBreakglassSessionByName(ctx, bs.Name)
	if err != nil {
		zap.S().Errorw("Failed to resolve BreakglassSession before status update", append(system.NamespacedFields(bs.Name, bs.Namespace), "error", err.Error())...)
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
		zap.S().Errorw("Failed to update BreakglassSession status", append(system.NamespacedFields(bs.Name, bs.Namespace), "error", err.Error())...)
		return fmt.Errorf("failed to update BreakglassSession status %s/%s: %w", bs.Namespace, bs.Name, err)
	}
	zap.S().Infow("BreakglassSession status updated successfully", system.NamespacedFields(bs.Name, bs.Namespace)...)
	return nil
}

// DeleteBreakglassSession deletes the given BreakglassSession and emits a metric when successful.
func (c SessionManager) DeleteBreakglassSession(ctx context.Context, bs *v1alpha1.BreakglassSession) error {
	if err := c.Delete(ctx, bs); err != nil {
		zap.S().Errorw("Failed to delete BreakglassSession", append(system.NamespacedFields(bs.Name, bs.Namespace), "error", err.Error())...)
		return fmt.Errorf("failed to delete breakglass session: %w", err)
	}
	zap.S().Infow("BreakglassSession deleted successfully", system.NamespacedFields(bs.Name, bs.Namespace)...)
	metrics.SessionDeleted.WithLabelValues(bs.Spec.Cluster).Inc()
	return nil
}
