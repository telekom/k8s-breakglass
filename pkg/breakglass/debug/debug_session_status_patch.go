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
	"encoding/json"
	"fmt"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

func (c *DebugSessionController) patchDebugSessionAllowedPods(
	ctx context.Context,
	ds *breakglassv1alpha1.DebugSession,
	allowedPods []breakglassv1alpha1.AllowedPodRef,
) error {
	patch := struct {
		Status struct {
			AllowedPods []breakglassv1alpha1.AllowedPodRef `json:"allowedPods"`
		} `json:"status"`
	}{}
	patch.Status.AllowedPods = allowedPods

	patchBytes, err := json.Marshal(patch)
	if err != nil {
		return fmt.Errorf("marshal DebugSession allowed pods status patch: %w", err)
	}

	target := &breakglassv1alpha1.DebugSession{
		TypeMeta: metav1.TypeMeta{
			APIVersion: breakglassv1alpha1.GroupVersion.String(),
			Kind:       "DebugSession",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ds.Name,
			Namespace: ds.Namespace,
		},
	}

	if err := c.client.Status().Patch(ctx, target, ctrlclient.RawPatch(types.MergePatchType, patchBytes)); err != nil {
		return fmt.Errorf("patch DebugSession allowed pods status: %w", err)
	}
	return nil
}

func (c *DebugSessionController) patchDebugSessionAllowedPodsAndAuxiliaryStatuses(
	ctx context.Context,
	ds *breakglassv1alpha1.DebugSession,
	allowedPods []breakglassv1alpha1.AllowedPodRef,
	auxiliaryResourceStatuses []breakglassv1alpha1.AuxiliaryResourceStatus,
) error {
	patch := struct {
		Status struct {
			AllowedPods               []breakglassv1alpha1.AllowedPodRef           `json:"allowedPods"`
			AuxiliaryResourceStatuses []breakglassv1alpha1.AuxiliaryResourceStatus `json:"auxiliaryResourceStatuses"`
		} `json:"status"`
	}{}
	patch.Status.AllowedPods = allowedPods
	patch.Status.AuxiliaryResourceStatuses = auxiliaryResourceStatuses

	patchBytes, err := json.Marshal(patch)
	if err != nil {
		return fmt.Errorf("marshal DebugSession allowed pods and auxiliary statuses patch: %w", err)
	}

	target := &breakglassv1alpha1.DebugSession{
		TypeMeta: metav1.TypeMeta{
			APIVersion: breakglassv1alpha1.GroupVersion.String(),
			Kind:       "DebugSession",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ds.Name,
			Namespace: ds.Namespace,
		},
	}

	if err := c.client.Status().Patch(ctx, target, ctrlclient.RawPatch(types.MergePatchType, patchBytes)); err != nil {
		return fmt.Errorf("patch DebugSession allowed pods and auxiliary statuses: %w", err)
	}
	return nil
}
