package breakglass

import (
	"context"
	"fmt"

	"github.com/pkg/errors"
	"gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/api/v1alpha1"
	telekomv1alpha1 "gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/api/v1alpha1"
	"k8s.io/apimachinery/pkg/fields"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
)

type EscalationManager struct {
	client.Client
}

// Get all stored GetClusterGroupAccess
func (em EscalationManager) GetAllBreakglassEscalations(ctx context.Context) ([]telekomv1alpha1.BreakglassEscalation, error) {
	escal := v1alpha1.BreakglassEscalationList{}
	if err := em.List(ctx, &escal); err != nil {
		return nil, errors.Wrap(err, "failed to get BreakglassEscalationList")
	}

	return escal.Items, nil
}

// GetBreakglassEscalationsWithSelector with custom field selector.
func (em EscalationManager) GetBreakglassEscalationsWithSelector(ctx context.Context,
	fs fields.Selector,
) ([]telekomv1alpha1.BreakglassEscalation, error) {
	ess := v1alpha1.BreakglassEscalationList{}

	if err := em.List(ctx, &ess, &client.ListOptions{FieldSelector: fs}); err != nil {
		return nil, errors.Wrapf(err, "failed to list BreakglassEscalation with selector")
	}

	return ess.Items, nil
}

func (em EscalationManager) GetUserBreakglassEscalations(ctx context.Context,
	username string,
) ([]telekomv1alpha1.BreakglassEscalation, error) {
	return em.GetBreakglassEscalationsWithSelector(ctx, fields.SelectorFromSet(fields.Set{
		"spec.username": username,
	}))
}

func (em EscalationManager) GetClusterBreakglassEscalations(ctx context.Context,
	cluster string,
) ([]telekomv1alpha1.BreakglassEscalation, error) {
	return em.GetBreakglassEscalationsWithSelector(ctx, fields.SelectorFromSet(fields.Set{
		"spec.cluster": cluster,
	}))
}

func (em EscalationManager) GetClusterUserBreakglassEscalations(ctx context.Context,
	cug ClusterUserGroup,
) ([]telekomv1alpha1.BreakglassEscalation, error) {
	return em.GetBreakglassEscalationsWithSelector(ctx, fields.SelectorFromSet(fields.Set{
		"spec.cluster":  cug.Clustername,
		"spec.username": cug.Username,
	}))
}

func (em EscalationManager) GetClusterUserGroupBreakglassEscalation(ctx context.Context,
	cug ClusterUserGroup,
) ([]telekomv1alpha1.BreakglassEscalation, error) {
	return em.GetBreakglassEscalationsWithSelector(ctx, fields.SelectorFromSet(fields.Set{
		"spec.cluster":        cug.Clustername,
		"spec.username":       cug.Username,
		"spec.escalatedGroup": cug.Groupname,
	}))
}

func NewEscalationManager(contextName string) (EscalationManager, error) {
	cfg, err := config.GetConfigWithContext(contextName)
	if err != nil {
		return EscalationManager{}, errors.Wrap(err, fmt.Sprintf("failed to get config with context %q", contextName))
	}

	c, err := client.New(cfg, client.Options{
		Scheme: scheme,
	})
	if err != nil {
		return EscalationManager{}, errors.Wrap(err, "failed to create new client")
	}

	return EscalationManager{c}, nil
}
