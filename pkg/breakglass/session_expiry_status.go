// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package breakglass

import (
	"context"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type sessionExpiryMutator func(*breakglassv1alpha1.BreakglassSession)
type sessionExpiryPredicate func(breakglassv1alpha1.BreakglassSession) bool

func (wc *BreakglassSessionController) updateSessionStatusIfCurrent(
	ctx context.Context,
	session breakglassv1alpha1.BreakglassSession,
	expectedState breakglassv1alpha1.BreakglassSessionState,
	shouldUpdate sessionExpiryPredicate,
	mutate sessionExpiryMutator,
) (breakglassv1alpha1.BreakglassSession, bool, error) {
	var updated breakglassv1alpha1.BreakglassSession
	var applied bool

	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var current breakglassv1alpha1.BreakglassSession
		key := client.ObjectKeyFromObject(&session)
		if err := wc.sessionManager.Reader().Get(ctx, key, &current); err != nil {
			if key.Namespace != "" {
				return err
			}
			fallback, fallbackErr := wc.sessionManager.GetBreakglassSessionByName(ctx, key.Name)
			if fallbackErr != nil {
				return fallbackErr
			}
			current = fallback
		}
		updated = current

		if current.Status.State != expectedState || !shouldUpdate(current) {
			applied = false
			return nil
		}

		base := current.DeepCopy()
		mutate(&current)
		if current.Generation > 0 {
			current.Status.ObservedGeneration = current.Generation
		}

		patch := client.MergeFromWithOptions(base, client.MergeFromWithOptimisticLock{})
		if err := wc.sessionManager.Client.Status().Patch(ctx, &current, patch); err != nil {
			return err
		}

		updated = current
		applied = true
		return nil
	})
	return updated, applied, err
}
