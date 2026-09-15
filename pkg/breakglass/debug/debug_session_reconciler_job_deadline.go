// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"context"
	"fmt"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

func (c *DebugSessionController) syncTrackedJobDeadlines(ctx context.Context, session *breakglassv1alpha1.DebugSession) error {
	if !hasTrackedDebugJob(session) || session.Status.ExpiresAt == nil {
		return nil
	}
	var (
		targetClient ctrlclient.Client
		configured   *breakglassv1alpha1.ClusterConfig
		provider     ClientProviderInterface
	)
	if c.targetClients != nil {
		provider = c.targetClients
		var err error
		targetClient, configured, err = provider.GetClientForPrivilegedOperation(ctx, session.Spec.Cluster)
		if err != nil {
			return fmt.Errorf("get target client for debug session %q: %w", session.Name, err)
		}
	} else {
		if c.ccProvider == nil {
			return fmt.Errorf("target client for debug session %q is unavailable", session.Name)
		}
		provider = &clusterClientAdapter{ccProvider: c.ccProvider}
		var err error
		var restCfg *rest.Config
		restCfg, configured, err = c.ccProvider.GetRESTConfigForPrivilegedOperation(ctx, session.Spec.Cluster)
		if err != nil {
			return fmt.Errorf("get target REST config for debug session %q: %w", session.Name, err)
		}
		if c.targetClientFactory != nil {
			targetClient, err = c.targetClientFactory(restCfg)
		} else {
			targetClient, err = ctrlclient.New(restCfg, ctrlclient.Options{})
		}
		if err != nil {
			c.ccProvider.ReleasePrivilegedOperationClusterConfig(configured)
			return fmt.Errorf("create target client for debug session %q: %w", session.Name, err)
		}
	}
	defer releasePrivilegedOperationSnapshot(provider, configured)
	return syncTrackedDebugJobDeadlines(ctx, targetClient, session, *session.Status.ExpiresAt, func(fenceCtx context.Context, requested metav1.Time) (metav1.Time, error) {
		if err := provider.ValidatePrivilegedOperationClusterConfig(fenceCtx, configured); err != nil {
			return requested, fmt.Errorf("privileged target configuration changed: %w", err)
		}
		reader := c.reader
		if reader == nil {
			reader = c.client
		}
		return liveDebugSessionDeadline(fenceCtx, reader, session, requested)
	})
}
