package client

import (
	"context"
	"fmt"
	"net/http"

	"github.com/telekom/k8s-breakglass/api/v1alpha1"
)

type EscalationService struct {
	client *Client
}

func (c *Client) Escalations() *EscalationService {
	return &EscalationService{client: c}
}

func (e *EscalationService) List(ctx context.Context) ([]v1alpha1.BreakglassEscalation, error) {
	endpoint := "api/breakglassEscalations"
	var escs []v1alpha1.BreakglassEscalation
	if err := e.client.do(ctx, http.MethodGet, endpoint, nil, &escs); err != nil {
		return nil, err
	}
	return escs, nil
}

func (e *EscalationService) Get(ctx context.Context, name string) (*v1alpha1.BreakglassEscalation, error) {
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
