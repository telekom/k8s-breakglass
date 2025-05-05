package breakglass

import (
	"context"
	"fmt"
	"slices"

	"github.com/pkg/errors"
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
	escal := telekomv1alpha1.BreakglassEscalationList{}
	if err := em.List(ctx, &escal); err != nil {
		return nil, errors.Wrap(err, "failed to get BreakglassEscalationList")
	}

	return escal.Items, nil
}

func (em EscalationManager) GetBreakglassEscalationsWithFilter(ctx context.Context,
	filter func(telekomv1alpha1.BreakglassEscalation) bool,
) ([]telekomv1alpha1.BreakglassEscalation, error) {
	ess := telekomv1alpha1.BreakglassEscalationList{}

	if err := em.List(ctx, &ess); err != nil {
		return nil, errors.Wrapf(err, "failed to list BreakglassEscalation for filtered get")
	}

	output := make([]telekomv1alpha1.BreakglassEscalation, 0, len(ess.Items))
	for _, it := range ess.Items {
		if filter(it) {
			output = append(output, it)
		}
	}

	return output, nil
}

// GetBreakglassEscalationsWithSelector with custom field selector.
func (em EscalationManager) GetBreakglassEscalationsWithSelector(ctx context.Context,
	fs fields.Selector,
) ([]telekomv1alpha1.BreakglassEscalation, error) {
	ess := telekomv1alpha1.BreakglassEscalationList{}

	if err := em.List(ctx, &ess, &client.ListOptions{FieldSelector: fs}); err != nil {
		return nil, errors.Wrapf(err, "failed to list BreakglassEscalation with selector")
	}

	return ess.Items, nil
}

func (em EscalationManager) GetUserBreakglassEscalations(ctx context.Context,
	username string,
) ([]telekomv1alpha1.BreakglassEscalation, error) {
	return em.GetBreakglassEscalationsWithFilter(ctx, func(be telekomv1alpha1.BreakglassEscalation) bool {
		return slices.Contains(be.Spec.Allowed.Users, username)
	})
}

func (em EscalationManager) GetClusterBreakglassEscalations(ctx context.Context,
	cluster string,
) ([]telekomv1alpha1.BreakglassEscalation, error) {
	return em.GetBreakglassEscalationsWithFilter(ctx, func(be telekomv1alpha1.BreakglassEscalation) bool {
		return slices.Contains(be.Spec.Allowed.Clusters, cluster)
	})
}

func (em EscalationManager) GetClusterUserBreakglassEscalations(ctx context.Context,
	cug ClusterUserGroup,
) ([]telekomv1alpha1.BreakglassEscalation, error) {
	return em.GetBreakglassEscalationsWithFilter(ctx, func(be telekomv1alpha1.BreakglassEscalation) bool {
		return slices.Contains(be.Spec.Allowed.Clusters, cug.Clustername) && slices.Contains(be.Spec.Allowed.Users, cug.Username)
	})
}

func (em EscalationManager) GetClusterUserGroupBreakglassEscalation(ctx context.Context,
	cug ClusterUserGroup,
) ([]telekomv1alpha1.BreakglassEscalation, error) {
	return em.GetBreakglassEscalationsWithFilter(ctx, func(be telekomv1alpha1.BreakglassEscalation) bool {
		return be.Spec.EscalatedGroup == cug.Groupname &&
			slices.Contains(be.Spec.Allowed.Clusters, cug.Clustername) &&
			slices.Contains(be.Spec.Allowed.Users, cug.Username)
	})
}

func NewEscalationManager(contextName string) (EscalationManager, error) {
	cfg, err := config.GetConfigWithContext(contextName)
	if err != nil {
		return EscalationManager{}, errors.Wrap(err, fmt.Sprintf("failed to get config with context %q", contextName))
	}

	c, err := client.New(cfg, client.Options{
		Scheme: Scheme,
	})
	if err != nil {
		return EscalationManager{}, errors.Wrap(err, "failed to create new client")
	}

	return EscalationManager{c}, nil
}
