// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"context"
	"fmt"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

func (c *DebugSessionController) syncTrackedJobDeadlines(ctx context.Context, session *breakglassv1alpha1.DebugSession) error {
	if !hasTrackedDebugJob(session) || session.Status.ExpiresAt == nil {
		return nil
	}
	var targetClient ctrlclient.Client
	if c.targetClients != nil {
		var err error
		targetClient, err = c.targetClients.GetClient(ctx, session.Spec.Cluster)
		if err != nil {
			return fmt.Errorf("get target client for debug session %q: %w", session.Name, err)
		}
	} else {
		if c.ccProvider == nil {
			return fmt.Errorf("target client for debug session %q is unavailable", session.Name)
		}
		restCfg, err := c.ccProvider.GetRESTConfig(ctx, session.Spec.Cluster)
		if err != nil {
			return fmt.Errorf("get target REST config for debug session %q: %w", session.Name, err)
		}
		targetClient, err = ctrlclient.New(restCfg, ctrlclient.Options{})
		if err != nil {
			return fmt.Errorf("create target client for debug session %q: %w", session.Name, err)
		}
	}
	return syncTrackedDebugJobDeadlines(ctx, targetClient, session, *session.Status.ExpiresAt)
}
