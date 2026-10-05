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

package utils

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/cli-utils/pkg/kstatus/status"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ResourceReadiness represents the readiness state of a Kubernetes resource.
type ResourceReadiness struct {
	// Ready indicates whether the resource has reached its desired state.
	Ready bool

	// Status is the kstatus status of the resource.
	Status status.Status

	// Message provides additional information about the resource's state.
	Message string

	// Error holds any error encountered while checking readiness.
	Error error
}

// IsReady returns true if the resource is in a ready/current state.
func (r ResourceReadiness) IsReady() bool {
	return r.Ready && r.Status == status.CurrentStatus
}

// IsFailed returns true if the resource is in a failed state.
func (r ResourceReadiness) IsFailed() bool {
	return r.Status == status.FailedStatus
}

// IsInProgress returns true if the resource is still progressing.
func (r ResourceReadiness) IsInProgress() bool {
	return r.Status == status.InProgressStatus
}

// IsTerminating returns true if the resource is being deleted.
func (r ResourceReadiness) IsTerminating() bool {
	return r.Status == status.TerminatingStatus
}

// ReadinessChecker provides methods for checking resource readiness using kstatus.
type ReadinessChecker struct {
	log *zap.SugaredLogger
}

// NewReadinessChecker creates a new ReadinessChecker instance.
func NewReadinessChecker(log *zap.SugaredLogger) *ReadinessChecker {
	return &ReadinessChecker{
		log: log.Named("readiness-checker"),
	}
}

// CheckReadiness checks the readiness of an unstructured resource using kstatus.
// Returns ResourceReadiness with the current status.
func (r *ReadinessChecker) CheckReadiness(obj *unstructured.Unstructured) ResourceReadiness {
	result, err := status.Compute(obj)
	if err != nil {
		return ResourceReadiness{
			Ready:   false,
			Status:  status.UnknownStatus,
			Message: fmt.Sprintf("failed to compute status: %v", err),
			Error:   err,
		}
	}

	return ResourceReadiness{
		Ready:   result.Status == status.CurrentStatus,
		Status:  result.Status,
		Message: result.Message,
	}
}

// CheckResourceReadiness fetches a resource by name and checks its readiness.
func (r *ReadinessChecker) CheckResourceReadiness(
	ctx context.Context,
	c client.Client,
	gvk schema.GroupVersionKind,
	name, namespace string,
) ResourceReadiness {
	obj := &unstructured.Unstructured{}
	obj.SetGroupVersionKind(gvk)

	key := types.NamespacedName{Name: name, Namespace: namespace}
	if err := c.Get(ctx, key, obj); err != nil {
		if apierrors.IsNotFound(err) {
			return ResourceReadiness{
				Ready:   false,
				Status:  status.NotFoundStatus,
				Message: "resource not found",
				Error:   err,
			}
		}
		return ResourceReadiness{
			Ready:   false,
			Status:  status.UnknownStatus,
			Message: fmt.Sprintf("failed to get resource: %v", err),
			Error:   err,
		}
	}

	return r.CheckReadiness(obj)
}

// WaitForReadiness waits for a resource to become ready with a timeout.
// Returns the final readiness state.
func (r *ReadinessChecker) WaitForReadiness(
	ctx context.Context,
	c client.Client,
	gvk schema.GroupVersionKind,
	name, namespace string,
	timeout time.Duration,
	pollInterval time.Duration,
) ResourceReadiness {
	deadline := time.Now().Add(timeout)

	for {
		readiness := r.CheckResourceReadiness(ctx, c, gvk, name, namespace)

		// Return immediately if ready, failed, or terminating
		if readiness.IsReady() || readiness.IsFailed() || readiness.IsTerminating() {
			return readiness
		}

		// Check timeout
		if time.Now().After(deadline) {
			return ResourceReadiness{
				Ready:   false,
				Status:  readiness.Status,
				Message: fmt.Sprintf("timeout waiting for readiness after %v: %s", timeout, readiness.Message),
				Error:   fmt.Errorf("timeout waiting for readiness"),
			}
		}

		// Wait before next poll
		select {
		case <-ctx.Done():
			return ResourceReadiness{
				Ready:   false,
				Status:  status.UnknownStatus,
				Message: "context cancelled",
				Error:   ctx.Err(),
			}
		case <-time.After(pollInterval):
			// Continue polling
		}
	}
}

// CheckMultipleResourceReadiness checks readiness for multiple resources.
// Returns a map of resource key to readiness state.
func (r *ReadinessChecker) CheckMultipleResourceReadiness(
	ctx context.Context,
	c client.Client,
	resources []ResourceRef,
) map[string]ResourceReadiness {
	results := make(map[string]ResourceReadiness, len(resources))

	for _, ref := range resources {
		key := ref.Key()
		results[key] = r.CheckResourceReadiness(ctx, c, ref.GVK, ref.Name, ref.Namespace)
	}

	return results
}

// AllReady returns true if all resources in the readiness map are ready.
func AllReady(readinessMap map[string]ResourceReadiness) bool {
	for _, r := range readinessMap {
		if !r.IsReady() {
			return false
		}
	}
	return true
}

// AnyFailed returns true if any resource in the readiness map is in failed state.
func AnyFailed(readinessMap map[string]ResourceReadiness) bool {
	for _, r := range readinessMap {
		if r.IsFailed() {
			return true
		}
	}
	return false
}

// ResourceRef holds information needed to identify a resource.
type ResourceRef struct {
	GVK       schema.GroupVersionKind
	Name      string
	Namespace string
}

// Key returns a unique string key for the resource reference.
func (r ResourceRef) Key() string {
	if r.Namespace == "" {
		return fmt.Sprintf("%s/%s", r.GVK.Kind, r.Name)
	}
	return fmt.Sprintf("%s/%s/%s", r.GVK.Kind, r.Namespace, r.Name)
}

// ResourceRefFromUnstructured creates a ResourceRef from an unstructured object.
func ResourceRefFromUnstructured(obj *unstructured.Unstructured) ResourceRef {
	return ResourceRef{
		GVK:       obj.GroupVersionKind(),
		Name:      obj.GetName(),
		Namespace: obj.GetNamespace(),
	}
}

// SummarizeReadiness provides a human-readable summary of multiple readiness states.
func SummarizeReadiness(readinessMap map[string]ResourceReadiness) string {
	total := len(readinessMap)
	ready := 0
	failed := 0
	inProgress := 0

	for _, r := range readinessMap {
		switch {
		case r.IsReady():
			ready++
		case r.IsFailed():
			failed++
		case r.IsInProgress():
			inProgress++
		}
	}

	return fmt.Sprintf("%d/%d ready, %d failed, %d in-progress", ready, total, failed, inProgress)
}
