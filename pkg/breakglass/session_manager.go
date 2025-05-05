package breakglass

import (
	"context"
	"fmt"
	"strings"

	"github.com/pkg/errors"
	"gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/api/v1alpha1"
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
		return SessionManager{}, errors.Wrap(err, fmt.Sprintf("failed to get config with context %q", contextName))
	}

	c, err := client.New(cfg, client.Options{
		Scheme: Scheme,
	})
	if err != nil {
		return SessionManager{}, errors.Wrap(err, "failed to create new client")
	}

	return SessionManager{c}, nil
}

func SessionSelector(uname, username, cluster, group string) string {
	selectors := []string{}

	if uname != "" {
		return fmt.Sprintf("metadata.name=%s", uname)
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
	cgal := v1alpha1.BreakglassSessionList{}
	if err := c.List(ctx, &cgal); err != nil {
		return nil, errors.Wrap(err, "failed to get BreakglassSessionList")
	}

	return cgal.Items, nil
}

// Get all stored GetClusterGroupAccess
func (c SessionManager) GetBreakglassSessionByName(ctx context.Context, name string) (v1alpha1.BreakglassSession, error) {
	bs := v1alpha1.BreakglassSession{}
	if err := c.Get(ctx, client.ObjectKey{Name: name}, &bs); err != nil {
		return bs, errors.Wrap(err, "failed to get BreakglassSession by name")
	}

	return bs, nil
}

// Get GetClusterGroupAccess by cluster name.
func (c SessionManager) GetClusterUserBreakglassSessions(ctx context.Context,
	cluster string,
	user string,
) ([]v1alpha1.BreakglassSession, error) {
	selector := fmt.Sprintf("spec.cluster=%s,spec.user=%s",
		cluster,
		user)
	return c.GetBreakglassSessionsWithSelectorString(ctx, selector)
}

// GetBreakglassSessions with custom field selector string.
func (c SessionManager) GetBreakglassSessionsWithSelectorString(ctx context.Context,
	selectorString string,
) ([]v1alpha1.BreakglassSession, error) {
	bsl := v1alpha1.BreakglassSessionList{}

	fs, err := fields.ParseSelector(selectorString)
	if err != nil {
		return nil, fmt.Errorf("failed to create field selector %q : %w", selectorString, err)
	}

	if err := c.List(ctx, &bsl, &client.ListOptions{FieldSelector: fs}); err != nil {
		return nil, errors.Wrapf(err, "failed to list BreakglassSessionList with string selector")
	}

	return bsl.Items, nil
}

// GetBreakglassSessions with custom field selector.
func (c SessionManager) GetBreakglassSessionsWithSelector(ctx context.Context,
	fs fields.Selector,
) ([]v1alpha1.BreakglassSession, error) {
	bsl := v1alpha1.BreakglassSessionList{}

	if err := c.List(ctx, &bsl, &client.ListOptions{FieldSelector: fs}); err != nil {
		return nil, errors.Wrapf(err, "failed to list BreakglassSessionList with selector")
	}

	return bsl.Items, nil
}

// Add new breakglass session.
func (c SessionManager) AddBreakglassSession(ctx context.Context, bs v1alpha1.BreakglassSession) error {
	if err := c.Create(ctx, &bs); err != nil {
		return errors.Wrap(err, "failed to create new BreakglassSession")
	}

	return nil
}

// Update breakglass session.
func (c SessionManager) UpdateBreakglassSession(ctx context.Context, bs v1alpha1.BreakglassSession) error {
	if err := c.Update(ctx, &bs); err != nil {
		return errors.Wrapf(err, "failed to update new BreakglassSession")
	}

	return nil
}

func (c SessionManager) UpdateBreakglassSessionStatus(ctx context.Context, bs v1alpha1.BreakglassSession) error {
	if err := c.Status().Update(ctx, &bs); err != nil {
		return errors.Wrapf(err, "failed to update new BreakglassSession")
	}

	return nil
}
