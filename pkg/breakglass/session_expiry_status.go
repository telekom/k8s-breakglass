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
	sessionName string,
	expectedState breakglassv1alpha1.BreakglassSessionState,
	shouldUpdate sessionExpiryPredicate,
	mutate sessionExpiryMutator,
) (breakglassv1alpha1.BreakglassSession, bool, error) {
	var updated breakglassv1alpha1.BreakglassSession
	var applied bool

	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		current, err := wc.sessionManager.GetBreakglassSessionByName(ctx, sessionName)
		if err != nil {
			return err
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
