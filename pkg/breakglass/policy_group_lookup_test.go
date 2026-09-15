// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package breakglass

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/telekom/k8s-breakglass/pkg/config"
	"go.uber.org/zap"
	"k8s.io/client-go/rest"
)

type policyRESTProvider struct{ err error }

func (p policyRESTProvider) GetRESTConfig(context.Context, string) (*rest.Config, error) {
	return nil, p.err
}

func TestGroupLookupConfiguredProviderDoesNotFallBack(t *testing.T) {
	unavailable := errors.New("spoke unavailable")
	for _, providerErr := range []error{unavailable, nil} {
		controller := NewBreakglassSessionController(zap.NewNop().Sugar(), config.Config{}, nil, nil, nil, "must-not-use-local-config", policyRESTProvider{err: providerErr}, nil, true)
		_, err := controller.getUserGroupsFn(context.Background(), ClusterUserGroup{Clustername: "spoke", Username: "approver"})
		if err == nil || !strings.Contains(err.Error(), "get spoke rest config") {
			t.Fatalf("expected provider failure, got %v", err)
		}
		if providerErr != nil && !errors.Is(err, providerErr) {
			t.Fatalf("lost provider cause: %v", err)
		}
	}
}

func TestGroupLookupNilProviderRetainsExplicitLegacyConfig(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "missing-legacy-config")
	t.Setenv("KUBECONFIG", filepath.Join(t.TempDir(), "missing-kubeconfig"))
	controller := NewBreakglassSessionController(zap.NewNop().Sugar(), config.Config{}, nil, nil, nil, configPath, nil, nil, true)
	_, err := controller.getUserGroupsFn(context.Background(), ClusterUserGroup{Clustername: "spoke", Username: "approver"})
	if err == nil || !strings.Contains(err.Error(), "failed to get config") {
		t.Fatalf("expected selected legacy config error, got %v", err)
	}
}
