package client

import (
	"context"
	"fmt"
	"net/http"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
)

type EscalationService struct {
	client *Client
}

func (c *Client) Escalations() *EscalationService {
	return &EscalationService{client: c}
}

func (e *EscalationService) List(ctx context.Context) ([]breakglassv1alpha1.BreakglassEscalation, error) {
	endpoint := "api/breakglassEscalations"
	var escs []breakglassv1alpha1.BreakglassEscalation
	if err := e.client.do(ctx, http.MethodGet, endpoint, nil, &escs); err != nil {
		return nil, err
	}
	return escs, nil
}

func (e *EscalationService) Get(ctx context.Context, name string) (*breakglassv1alpha1.BreakglassEscalation, error) {
	escs, err := e.List(ctx)
	if err != nil {
		return nil, err
	}
	for i := range escs {
		if escs[i].Name == name {
			return &escs[i], nil
		}
	}
	return nil, fmt.Errorf("escalation not found: %s", name)
}

// ListClusters returns unique cluster names from all escalation policies.
func (e *EscalationService) ListClusters(ctx context.Context) ([]string, error) {
	escs, err := e.List(ctx)
	if err != nil {
		return nil, err
	}
	clusterSet := make(map[string]struct{})
	for _, esc := range escs {
		for _, cluster := range esc.Spec.Allowed.Clusters {
			clusterSet[cluster] = struct{}{}
		}
	}
	clusters := make([]string, 0, len(clusterSet))
	for c := range clusterSet {
		clusters = append(clusters, c)
	}
	return clusters, nil
}
