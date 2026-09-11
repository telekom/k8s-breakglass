// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"context"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"go.uber.org/zap"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

// shouldEmitDebugSessionAudit preserves captured policy and suppresses events when
// an uncaptured policy is unavailable, so lookup failures cannot bypass opt-out.
func shouldEmitDebugSessionAudit(ctx context.Context, reader ctrlclient.Reader, log *zap.SugaredLogger, session *breakglassv1alpha1.DebugSession) bool {
	policy := session.Status.ResolvedTemplate
	if policy == nil {
		if session.Spec.TemplateRef == "" {
			return true
		}
		template := &breakglassv1alpha1.DebugSessionTemplate{}
		if err := reader.Get(ctx, ctrlclient.ObjectKey{Name: session.Spec.TemplateRef}, template); err != nil {
			log.Warnw("Skipping debug session audit event: template audit policy unavailable", "session", session.Name, "template", session.Spec.TemplateRef, "error", err)
			return false
		}
		policy = &template.Spec
	}
	return policy.Audit == nil || policy.Audit.Enabled
}
