// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"context"
	"fmt"
	"time"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	batchv1 "k8s.io/api/batch/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

// syncTrackedDebugJobDeadlines makes every tracked workload Job at least as
// long-lived as the committed session expiry. It is deliberately monotonic:
// retries never shorten a deadline, and the recorded UID and optimistic
// resource-version patch prevent changing a same-name replacement.
func syncTrackedDebugJobDeadlines(
	ctx context.Context,
	targetClient ctrlclient.Client,
	session *breakglassv1alpha1.DebugSession,
	newExpiry metav1.Time,
) error {
	if session == nil {
		return nil
	}
	seen := make(map[ctrlclient.ObjectKey]struct{})
	for _, ref := range session.Status.DeployedResources {
		if ref.APIVersion != "batch/v1" || ref.Kind != "Job" || ref.Source != "debug-pod" || ref.Name == "" {
			continue
		}
		key := ctrlclient.ObjectKey{Name: ref.Name, Namespace: ref.Namespace}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		if targetClient == nil {
			return fmt.Errorf("target client is unavailable for tracked Job %s/%s", ref.Namespace, ref.Name)
		}

		job := &batchv1.Job{}
		if err := targetClient.Get(ctx, key, job); err != nil {
			return fmt.Errorf("get tracked Job %s/%s: %w", ref.Namespace, ref.Name, err)
		}
		if ref.UID == "" || string(job.UID) != ref.UID {
			return fmt.Errorf("tracked Job %s/%s identity changed", ref.Namespace, ref.Name)
		}
		if job.Spec.ActiveDeadlineSeconds == nil || *job.Spec.ActiveDeadlineSeconds < 1 {
			return fmt.Errorf("tracked Job %s/%s has no positive active deadline", ref.Namespace, ref.Name)
		}
		if job.Status.StartTime == nil {
			return fmt.Errorf("tracked Job %s/%s has no start time", ref.Namespace, ref.Name)
		}

		remaining := newExpiry.Sub(job.Status.StartTime.Time)
		desiredSeconds := int64(remaining / time.Second)
		if remaining%time.Second != 0 {
			desiredSeconds++
		}
		if desiredSeconds < 1 {
			return fmt.Errorf("tracked Job %s/%s renewed expiry precedes its start time", ref.Namespace, ref.Name)
		}
		if *job.Spec.ActiveDeadlineSeconds >= desiredSeconds {
			continue
		}

		updated := job.DeepCopy()
		deadline := desiredSeconds
		updated.Spec.ActiveDeadlineSeconds = &deadline
		if err := targetClient.Patch(ctx, updated, ctrlclient.MergeFromWithOptions(job, ctrlclient.MergeFromWithOptimisticLock{})); err != nil {
			return fmt.Errorf("extend tracked Job %s/%s deadline: %w", ref.Namespace, ref.Name, err)
		}
	}
	return nil
}

func hasTrackedDebugJob(session *breakglassv1alpha1.DebugSession) bool {
	if session == nil {
		return false
	}
	for _, ref := range session.Status.DeployedResources {
		if ref.APIVersion == "batch/v1" && ref.Kind == "Job" && ref.Source == "debug-pod" && ref.Name != "" {
			return true
		}
	}
	return false
}
