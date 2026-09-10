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
	"fmt"
	"time"

	"github.com/gin-gonic/gin"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	apiresponses "github.com/telekom/k8s-breakglass/pkg/apiresponses"
	breakglass "github.com/telekom/k8s-breakglass/pkg/breakglass"
	"go.uber.org/zap"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

func (c *DebugSessionAPIController) patchDebugSessionStatusWithOptimisticLock(
	ctx context.Context,
	session *breakglassv1alpha1.DebugSession,
	mutate func(*breakglassv1alpha1.DebugSessionStatus),
) error {
	if err := breakglass.PatchDebugSessionStatusWithReader(ctx, c.client, c.reader(), session, mutate); err != nil {
		return fmt.Errorf("patch DebugSession API status with optimistic lock: %w", err)
	}
	return nil
}

func (c *DebugSessionAPIController) recordDebugSessionActivity(ctx context.Context, session *breakglassv1alpha1.DebugSession) {
	if session == nil || session.UID == "" {
		return
	}
	// A completed target operation still needs bounded bookkeeping after request cancellation.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	// Target mutation status writes advance the resource version. Re-read the
	// same session UID instead of treating the API's pre-operation object as current.
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var live breakglassv1alpha1.DebugSession
		if err := c.reader().Get(ctx, ctrlclient.ObjectKeyFromObject(session), &live); err != nil {
			return fmt.Errorf("read session activity: %w", err)
		}
		if live.UID != session.UID || !live.DeletionTimestamp.IsZero() {
			return nil
		}
		return c.patchDebugSessionStatusWithOptimisticLock(ctx, &live, func(status *breakglassv1alpha1.DebugSessionStatus) {
			now := metav1.Now()
			candidate := live.DeepCopy()
			candidate.Status = *status
			if status.State != breakglassv1alpha1.DebugSessionStateActive || isDebugSessionExpired(candidate, now.Time) {
				return
			}
			if status.LastActivity == nil || status.LastActivity.Time.Before(now.Time) {
				status.LastActivity = &now
			}
			status.ActivityCount++
		})
	})
	if err != nil {
		c.log.Warnw("successful debug operation was not recorded as activity", "session", session.Name, "error", err)
	}
}

func respondDebugSessionStatusPatchError(ctx *gin.Context, reqLog *zap.SugaredLogger, action, responseMessage, sessionName string, err error) {
	if apierrors.IsConflict(err) {
		reqLog.Warnw("Debug session status update conflict", "action", action, "session", sessionName, "error", err)
		apiresponses.RespondConflict(ctx, "debug session was updated concurrently; refresh the session before retrying")
		return
	}

	reqLog.Errorw("Failed to "+action, "session", sessionName, "error", err)
	apiresponses.RespondInternalErrorSimple(ctx, responseMessage)
}
