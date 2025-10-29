package breakglass

import (
	"context"
	"fmt"
	"strings"

	"github.com/pkg/errors"
	"gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/api/v1alpha1"
	"gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/pkg/system"
	"go.uber.org/zap"
	"k8s.io/apimachinery/pkg/fields"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
)

// SessionManager is kubernetes client based object for managing CRUD operation on BreakglassSession custom resource.
type SessionManager struct {
	client.Client
}

var ErrAccessNotFound = errors.New("access not found")

func NewSessionManager(contextName string) (SessionManager, error) {
	cfg, err := config.GetConfigWithContext(contextName)
	if err != nil {
		zap.S().Errorw("Failed to get config with context", "context", contextName, "error", err.Error())
		return SessionManager{}, errors.Wrap(err, fmt.Sprintf("failed to get config with context %q", contextName))
	}

	c, err := client.New(cfg, client.Options{
		Scheme: Scheme,
	})
	if err != nil {
		zap.S().Errorw("Failed to create new client", "error", err.Error())
		return SessionManager{}, errors.Wrap(err, "failed to create new client")
	}

	zap.S().Infow("SessionManager initialized", "context", contextName)
	return SessionManager{c}, nil
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
	if err := c.List(ctx, &cgal); err != nil {
		zap.S().Errorw("Failed to get BreakglassSessionList", "error", err.Error())
		return nil, errors.Wrap(err, "failed to get BreakglassSessionList")
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

	// Fallback: list across namespaces using a metadata.name field selector
	selector := fmt.Sprintf("metadata.name=%s", name)
	fs, ferr := fields.ParseSelector(selector)
	if ferr != nil {
		zap.S().Errorw("Failed to parse field selector for fallback lookup", "selector", selector, "error", ferr.Error())
		return bs, errors.Wrapf(ferr, "failed to create field selector %q", selector)
	}

	bsl := v1alpha1.BreakglassSessionList{}
	if err := c.List(ctx, &bsl, &client.ListOptions{FieldSelector: fs}); err != nil {
		zap.S().Errorw("Failed to list BreakglassSessionList for fallback lookup", "selector", selector, "error", err.Error())
		return bs, errors.Wrap(err, "failed to list BreakglassSessionList for fallback lookup")
	}

	if len(bsl.Items) == 0 {
		zap.S().Errorw("BreakglassSession not found by name across namespaces", "name", name)
		return bs, errors.Wrapf(errors.New("not found"), "failed to get BreakglassSession by name: %s", name)
	}

	if len(bsl.Items) > 1 {
		// Ambiguous: multiple sessions with same name exist in different namespaces.
		namespaces := make([]string, 0, len(bsl.Items))
		for _, it := range bsl.Items {
			namespaces = append(namespaces, it.Namespace)
		}
		msg := fmt.Sprintf("multiple BreakglassSessions with name %q found in namespaces: %s", name, strings.Join(namespaces, ","))
		zap.S().Errorw("Ambiguous BreakglassSession name across namespaces", "name", name, "namespaces", namespaces)
		return bs, errors.Errorf(msg)
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
	selector := fmt.Sprintf("spec.cluster=%s,spec.user=%s",
		cluster,
		user)
	zap.S().Debugw("Fetching BreakglassSessions for cluster and user", "cluster", cluster, "user", user)
	return c.GetBreakglassSessionsWithSelectorString(ctx, selector)
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

	if err := c.List(ctx, &bsl, &client.ListOptions{FieldSelector: fs}); err != nil {
		zap.S().Errorw("Failed to list BreakglassSessionList with string selector", "selector", selectorString, "error", err.Error())
		return nil, errors.Wrapf(err, "failed to list BreakglassSessionList with string selector")
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

	if err := c.List(ctx, &bsl, &client.ListOptions{FieldSelector: fs}); err != nil {
		zap.S().Errorw("Failed to list BreakglassSessionList with selector", "selector", fs.String(), "error", err.Error())
		return nil, errors.Wrapf(err, "failed to list BreakglassSessionList with selector")
	}
	zap.S().Infow("Fetched BreakglassSessions with selector", "count", len(bsl.Items), "selector", fs.String())
	return bsl.Items, nil
}

// Add new breakglass session.
func (c SessionManager) AddBreakglassSession(ctx context.Context, bs v1alpha1.BreakglassSession) error {
	zap.S().Infow("Adding new BreakglassSession", append(system.NamespacedFields(bs.Name, bs.Namespace), "user", bs.Spec.User, "cluster", bs.Spec.Cluster)...)
	if err := c.Create(ctx, &bs); err != nil {
		zap.S().Errorw("Failed to create new BreakglassSession", append(system.NamespacedFields(bs.Name, bs.Namespace), "error", err.Error())...)
		return errors.Wrap(err, "failed to create new BreakglassSession")
	}
	zap.S().Infow("BreakglassSession created successfully", system.NamespacedFields(bs.Name, bs.Namespace)...)
	return nil
}

// Update breakglass session.
func (c SessionManager) UpdateBreakglassSession(ctx context.Context, bs v1alpha1.BreakglassSession) error {
	zap.S().Infow("Updating BreakglassSession", system.NamespacedFields(bs.Name, bs.Namespace)...)
	if err := c.Update(ctx, &bs); err != nil {
		zap.S().Errorw("Failed to update BreakglassSession", append(system.NamespacedFields(bs.Name, bs.Namespace), "error", err.Error())...)
		return errors.Wrapf(err, "failed to update new BreakglassSession")
	}
	zap.S().Infow("BreakglassSession updated successfully", system.NamespacedFields(bs.Name, bs.Namespace)...)
	return nil
}

func (c SessionManager) UpdateBreakglassSessionStatus(ctx context.Context, bs v1alpha1.BreakglassSession) error {
	zap.S().Infow("Updating BreakglassSession status", system.NamespacedFields(bs.Name, bs.Namespace)...)
	if err := c.Status().Update(ctx, &bs); err != nil {
		zap.S().Errorw("Failed to update BreakglassSession status", append(system.NamespacedFields(bs.Name, bs.Namespace), "error", err.Error())...)
		return errors.Wrapf(err, "failed to update new BreakglassSession")
	}
	zap.S().Infow("BreakglassSession status updated successfully", system.NamespacedFields(bs.Name, bs.Namespace)...)
	return nil
}
