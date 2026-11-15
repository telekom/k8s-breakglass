/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package debug

import (
	"context"
	"slices"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/breakglass"
	"github.com/telekom/k8s-breakglass/pkg/utils"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

func (c *DebugSessionController) patchDebugSessionAllowedPods(
	ctx context.Context,
	ds *breakglassv1alpha1.DebugSession,
	allowedPods []breakglassv1alpha1.AllowedPodRef,
) error {
	reader := c.reader
	if reader == nil {
		reader = c.client
	}
	return breakglass.PatchDebugSessionStatusWithReader(ctx, c.client, reader, ds, func(status *breakglassv1alpha1.DebugSessionStatus) {
		status.AllowedPods = allowedPods
	})
}

func (c *DebugSessionController) patchDebugSessionAllowedPodsAndAuxiliaryStatuses(
	ctx context.Context,
	ds *breakglassv1alpha1.DebugSession,
	allowedPods []breakglassv1alpha1.AllowedPodRef,
	auxiliaryResourceStatuses []breakglassv1alpha1.AuxiliaryResourceStatus,
) error {
	reader := c.reader
	if reader == nil {
		reader = c.client
	}
	return breakglass.PatchDebugSessionStatusWithReader(ctx, c.client, reader, ds, func(status *breakglassv1alpha1.DebugSessionStatus) {
		status.AllowedPods = allowedPods
		status.AuxiliaryResourceStatuses = auxiliaryResourceStatuses
	})
}

// recordSessionIntermediates records the ReplicaSets and Jobs between the
// session's workloads and their Pods while the session is active. If a
// workload is deleted before cleanup, the garbage collector removes them, and
// a Pod evicted with a long grace period would otherwise lose its lineage.
func (c *DebugSessionController) recordSessionIntermediates(ctx context.Context, target ctrlclient.Client, ds *breakglassv1alpha1.DebugSession) error {
	found, err := discoverSessionPods(ctx, target, append(slices.Clone(ds.Status.DeployedResources), specializedCleanupRefs(ds)...),
		func(ref breakglassv1alpha1.DeployedResourceRef) bool {
			return utils.DebugSessionResourceIntentionallyRetained(ds, ref)
		})
	if err != nil {
		return err
	}
	var missing []breakglassv1alpha1.DeployedResourceRef
	for _, ref := range found.intermediates {
		if !slices.ContainsFunc(ds.Status.DeployedResources, func(r breakglassv1alpha1.DeployedResourceRef) bool { return sameResource(r, ref) }) {
			missing = append(missing, ref)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	reader := c.reader
	if reader == nil {
		reader = c.client
	}
	return breakglass.PatchDebugSessionStatusWithReader(ctx, c.client, reader, ds, func(status *breakglassv1alpha1.DebugSessionStatus) {
		for _, ref := range missing {
			status.DeployedResources = appendDeployedRef(status.DeployedResources, ref)
		}
	})
}
