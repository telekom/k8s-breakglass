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

type debugJobDeadlineFence func(context.Context, metav1.Time) (metav1.Time, error)

// syncTrackedDebugJobDeadlines keeps every tracked workload Job aligned with
// the committed session expiry. The recorded UID and optimistic
// resource-version patch prevent changing a same-name replacement.
func syncTrackedDebugJobDeadlines(
	ctx context.Context,
	targetClient ctrlclient.Client,
	session *breakglassv1alpha1.DebugSession,
	newExpiry metav1.Time,
	fence debugJobDeadlineFence,
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
			// A pending Job has no deadline origin yet; normal reconciliation retries.
			continue
		}

		effectiveExpiry := newExpiry
		if fence != nil {
			var err error
			effectiveExpiry, err = fence(ctx, newExpiry)
			if err != nil {
				return fmt.Errorf("fence tracked Job %s/%s deadline: %w", ref.Namespace, ref.Name, err)
			}
		}
		remaining := effectiveExpiry.Sub(job.Status.StartTime.Time)
		desiredSeconds := int64(remaining / time.Second)
		if desiredSeconds < 1 {
			return fmt.Errorf("tracked Job %s/%s renewed expiry precedes its start time", ref.Namespace, ref.Name)
		}
		if *job.Spec.ActiveDeadlineSeconds == desiredSeconds {
			continue
		}

		updated := job.DeepCopy()
		deadline := desiredSeconds
		updated.Spec.ActiveDeadlineSeconds = &deadline
		if err := targetClient.Patch(ctx, updated, ctrlclient.MergeFromWithOptions(job, ctrlclient.MergeFromWithOptimisticLock{})); err != nil {
			return fmt.Errorf("synchronize tracked Job %s/%s deadline: %w", ref.Namespace, ref.Name, err)
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

func liveDebugSessionDeadline(
	ctx context.Context,
	reader ctrlclient.Reader,
	session *breakglassv1alpha1.DebugSession,
	requested metav1.Time,
) (metav1.Time, error) {
	if reader == nil {
		return requested, fmt.Errorf("live debug session reader is unavailable")
	}
	if session == nil || session.UID == "" {
		return requested, fmt.Errorf("debug session identity is incomplete")
	}
	live := &breakglassv1alpha1.DebugSession{}
	if err := reader.Get(ctx, ctrlclient.ObjectKeyFromObject(session), live); err != nil {
		return requested, fmt.Errorf("read live debug session: %w", err)
	}
	if live.UID == "" || live.UID != session.UID {
		return requested, fmt.Errorf("debug session identity changed")
	}
	if !live.DeletionTimestamp.IsZero() || live.Status.State != breakglassv1alpha1.DebugSessionStateActive ||
		live.Status.ExpiresAt == nil || isDebugSessionExpired(live, time.Now().UTC()) {
		return requested, fmt.Errorf("debug session is no longer active")
	}
	// The live status is the committed source of truth. Returning the caller's
	// requested value when it is older would let a stale renewal shorten a Job
	// after a newer renewal has already committed.
	return *live.Status.ExpiresAt, nil
}
