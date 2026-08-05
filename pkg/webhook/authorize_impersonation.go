// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package webhook

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/audit"
	"github.com/telekom/k8s-breakglass/pkg/impersonation"
	"github.com/telekom/k8s-breakglass/pkg/metrics"
	"github.com/telekom/k8s-breakglass/pkg/policy"
)

// evaluateImpersonation handles SubjectAccessReviews that concern impersonation.
//
// This closes a live security gap. Since Kubernetes 1.36 the ConstrainedImpersonation
// feature gate (KEP-5284) is beta and on by default, and the API server authorizes
// impersonation by asking the authorizer chain about verbs named
// `impersonate:<mode>` and `impersonate-on:<mode>:<verb>`. Those verbs did not
// exist when this webhook was written, so every one of them fell through to the
// generic path — and a webhook authorizer that allows verbs it does not recognise
// silently grants constrained impersonation.
//
// Returns handled=true when a decision has been written to the response.
//
// Backwards compatibility: on any spoke where the gate is off or the release
// predates the feature, the constrained verbs simply never arrive, so this
// function only ever sees the legacy `impersonate` verb — which it passes through
// to the existing RBAC and session logic exactly as before. Nothing here changes
// behaviour on an older spoke.
func (wc *WebhookController) evaluateImpersonation(c *gin.Context, s *authorizeState) bool {
	req, isImpersonation := impersonation.ClassifySAR(&s.sar)
	if !isImpersonation {
		return false
	}

	s.impersonation = &req

	cfg := wc.constrainedImpersonationConfig(s)

	s.reqLog.Infow("SubjectAccessReview concerns impersonation",
		"verb", req.Verb.Raw,
		"verbKind", req.Verb.Kind.String(),
		"mode", string(req.Verb.Mode),
		"identityResource", req.Target.Resource,
		"identityName", req.Target.Name,
		"identityNamespace", req.Target.Namespace,
		"extraKey", req.Target.Subresource,
		"requestor", req.Requestor.User,
		"requestorUID", req.Requestor.UID,
		"cluster", s.clusterName)

	metrics.ImpersonationSARRequests.WithLabelValues(
		s.clusterName, string(req.Verb.Mode), req.Verb.Kind.String()).Inc()

	// 1. Malformed / unrecognised impersonation verbs fail closed.
	//
	// This is the crux of the gap. If a future API server introduces a fifth mode,
	// this build cannot parse its verb — and returning "no opinion" would let the
	// API server treat the impersonation as vetted. A loud denial is the only safe
	// answer, and it is scoped to impersonation verbs alone so it cannot affect any
	// ordinary request.
	if req.Verb.Kind == impersonation.VerbKindMalformed {
		if !cfg.ShouldDenyUnrecognisedVerbs() {
			s.reqLog.Warnw(
				"Unrecognised impersonation verb allowed to proceed because denyUnrecognisedVerbs is "+
					"disabled on this ClusterConfig; constrained impersonation may be granted without "+
					"breakglass evaluation",
				"verb", req.Verb.Raw, "cluster", s.clusterName)
			metrics.ImpersonationUnrecognisedVerbs.WithLabelValues(s.clusterName, "allowed").Inc()
			return false
		}
		decision := impersonation.DenyUnrecognisedVerb(req.Verb)
		metrics.ImpersonationUnrecognisedVerbs.WithLabelValues(s.clusterName, "denied").Inc()
		wc.writeImpersonationDenial(c, s, decision.Reason, decision.Source)
		return true
	}

	// 2. Guardrail: system:masters is never impersonable through breakglass.
	//
	// The API server hard-denies it in constrained mode but deliberately does NOT
	// for legacy impersonation, so without this check a blanket legacy grant plus a
	// system:masters target is a complete cluster-admin bypass.
	if req.Target.Resource == impersonation.ResourceGroups &&
		req.Target.Name == impersonation.GroupSystemMasters {
		wc.writeImpersonationDenial(c, s,
			"Denied: impersonating the system:masters group is never permitted through breakglass.",
			"system-masters")
		return true
	}

	// 3. Legacy-fallback policy.
	if req.Verb.Kind == impersonation.VerbKindLegacyImpersonate {
		if handled := wc.evaluateLegacyImpersonationFallback(c, s, cfg); handled {
			return true
		}
	}

	// 4. DenyPolicy impersonation rules.
	if handled := wc.evaluateImpersonationDenyPolicies(c, s, req); handled {
		return true
	}

	// Not denied here. Fall through to the normal RBAC and session-based
	// authorization path, which decides whether an actual grant exists. Returning
	// false rather than allowing is deliberate: this function's job is to make
	// impersonation decisions explicit and deniable, not to invent grants.
	return false
}

// constrainedImpersonationConfig returns the effective constrained-impersonation
// settings for the target spoke. A nil ClusterConfig or an absent block yields the
// safe defaults via the nil-receiver accessors, so clusters onboarded before this
// field existed are protected without any operator action.
func (wc *WebhookController) constrainedImpersonationConfig(
	s *authorizeState,
) *breakglassv1alpha1.ConstrainedImpersonationConfig {
	if s.clusterCfg == nil {
		return nil
	}
	return s.clusterCfg.Spec.ConstrainedImpersonation
}

// evaluateLegacyImpersonationFallback applies the spoke's legacyFallback policy to
// a classic `impersonate` check.
func (wc *WebhookController) evaluateLegacyImpersonationFallback(
	c *gin.Context,
	s *authorizeState,
	cfg *breakglassv1alpha1.ConstrainedImpersonationConfig,
) bool {
	switch cfg.EffectiveLegacyFallback() {
	case breakglassv1alpha1.LegacyImpersonationFallbackForbidden:
		metrics.ImpersonationLegacyFallback.WithLabelValues(s.clusterName, "denied").Inc()
		wc.writeImpersonationDenial(c, s,
			"Denied: legacy (unconstrained) impersonation is forbidden on this cluster. "+
				"A blanket `impersonate` grant wins by fallback and would silently defeat the "+
				"constrained impersonation rules configured here. Use a constrained mode instead.",
			"legacy-fallback-forbidden")
		return true

	case breakglassv1alpha1.LegacyImpersonationFallbackWarn:
		metrics.ImpersonationLegacyFallback.WithLabelValues(s.clusterName, "warned").Inc()
		s.impersonationWarnedLegacy = true
		s.reqLog.Warnw(
			"Legacy (unconstrained) impersonation in use; the API server does not apply the "+
				"constrained restrictions to this path and any blanket `impersonate` grant defeats "+
				"configured constraints",
			"cluster", s.clusterName,
			"requestor", s.sar.Spec.User,
			"identityResource", s.sar.Spec.ResourceAttributes.Resource,
			"identityName", s.sar.Spec.ResourceAttributes.Name)
		return false

	case breakglassv1alpha1.LegacyImpersonationFallbackAllow:
		metrics.ImpersonationLegacyFallback.WithLabelValues(s.clusterName, "allowed").Inc()
		return false

	default:
		metrics.ImpersonationLegacyFallback.WithLabelValues(s.clusterName, "allowed").Inc()
		return false
	}
}

// evaluateImpersonationDenyPolicies runs DenyPolicy impersonationRules, globally
// and per active session.
func (wc *WebhookController) evaluateImpersonationDenyPolicies(
	c *gin.Context,
	s *authorizeState,
	req impersonation.Request,
) bool {
	if wc.denyEval == nil {
		return false
	}

	act := policy.ImpersonationAction{
		Verb:              req.Verb,
		IdentityResource:  req.Target.Resource,
		Identity:          req.Target.Name,
		IdentityNamespace: req.Target.Namespace,
		ExtraKey:          req.Target.Subresource,
		ClusterID:         s.clusterName,
		Tenant:            s.tenant,
	}

	// Action checks carry the target request's own attributes rather than the
	// impersonation target's, so they populate different fields.
	if req.Verb.Kind == impersonation.VerbKindAction && s.sar.Spec.ResourceAttributes != nil {
		act.TargetResource = s.sar.Spec.ResourceAttributes.Resource
		act.TargetAPIGroup = s.sar.Spec.ResourceAttributes.Group
	}

	// serviceaccounts is the only namespaced identity kind, so it is the only case
	// where namespace labels can matter.
	if act.IdentityNamespace != "" &&
		act.IdentityResource == impersonation.ResourceServiceAccounts {
		if labels, err := wc.fetchNamespaceLabels(s.ctx, s.clusterName, act.IdentityNamespace); err != nil {
			s.reqLog.Debugw("Failed to fetch namespace labels for impersonation DenyPolicy evaluation",
				"error", err.Error(), "namespace", act.IdentityNamespace)
		} else {
			act.NamespaceLabels = labels
		}
	}

	scopes := []struct {
		session string
		label   string
	}{{session: "", label: "global"}}
	for _, sess := range s.sessions {
		scopes = append(scopes, struct {
			session string
			label   string
		}{session: sess.Name, label: "session:" + sess.Name})
	}

	for _, scope := range scopes {
		act.Session = scope.session
		denied, polName, reason, err := wc.denyEval.MatchImpersonation(s.ctx, act)
		if err != nil {
			// Fail closed, consistent with the resource DenyPolicy path: an
			// impersonation grant we could not evaluate must not be allowed.
			s.reqLog.Errorw("Impersonation DenyPolicy evaluation failed; denying fail-closed",
				"error", err.Error(), "scope", scope.label, "cluster", s.clusterName)
			metrics.ImpersonationDenyPolicyErrors.WithLabelValues(s.clusterName).Inc()
			wc.writeImpersonationDenial(c, s,
				"Impersonation DenyPolicy evaluation failed; request denied fail-closed",
				"impersonation-policy-error")
			return true
		}
		if denied {
			wc.emitPolicyDenialAudit(s.ctx, s.sar.Spec.User, s.groups, s.clusterName,
				&s.sar, polName, "impersonation:"+scope.label)
			wc.writeImpersonationDenial(c, s, reason, "impersonation-policy")
			return true
		}
	}

	return false
}

// writeImpersonationDenial emits metrics, an audit event and the deny response for
// an impersonation decision.
func (wc *WebhookController) writeImpersonationDenial(
	c *gin.Context,
	s *authorizeState,
	reason, source string,
) {
	metrics.WebhookSARDenied.WithLabelValues(s.clusterName).Inc()
	metrics.WebhookSARDecisions.WithLabelValues(s.clusterName, "denied", source).Inc()
	metrics.WebhookSARDuration.WithLabelValues(s.clusterName, "denied").
		Observe(time.Since(s.startTime).Seconds())

	mode := ""
	verbKind := ""
	constraint := ""
	if s.impersonation != nil {
		mode = string(s.impersonation.Verb.Mode)
		verbKind = s.impersonation.Verb.Kind.String()
		if s.impersonation.Verb.IsConstrained() {
			constraint = impersonation.IdentityVerb(s.impersonation.Verb.Mode)
		}
	}
	metrics.ImpersonationSARDecisions.WithLabelValues(s.clusterName, mode, "denied", source).Inc()

	wc.emitImpersonationAudit(s, false, reason, source, constraint)

	s.reqLog.Infow("Impersonation DENIED",
		"cluster", s.clusterName,
		"requestor", s.sar.Spec.User,
		"requestorUID", s.sar.Spec.UID,
		"verb", verbKindOrRaw(s),
		"verbKind", verbKind,
		"mode", mode,
		"source", source,
		"reason", reason)

	s.phases.EndPhase(PhaseImpersonation)
	s.phases.LogSummary()

	c.JSON(http.StatusOK, &SubjectAccessReviewResponse{
		ApiVersion: s.sar.APIVersion,
		Kind:       s.sar.Kind,
		Status: SubjectAccessReviewResponseStatus{
			Allowed: false,
			Reason:  wc.finalizeReason(reason, false, s.clusterName),
		},
	})
}

func verbKindOrRaw(s *authorizeState) string {
	if s.impersonation != nil {
		return s.impersonation.Verb.Raw
	}
	if s.sar.Spec.ResourceAttributes != nil {
		return s.sar.Spec.ResourceAttributes.Verb
	}
	return ""
}

// emitImpersonationAudit records an impersonation authorization decision.
//
// constraint mirrors the API server's own audit field
// authenticationMetadata.impersonationConstraint: it holds the identity verb for
// constrained impersonation and is empty for legacy, exactly as the API server
// omits the field there. Recording it on both sides lets an auditor join the
// breakglass decision to the API server's audit event for the same request.
func (wc *WebhookController) emitImpersonationAudit(
	s *authorizeState,
	allowed bool,
	reason, source, constraint string,
) {
	if wc.auditService == nil || s.impersonation == nil {
		return
	}

	req := s.impersonation
	severity := audit.SeverityWarning
	if allowed {
		severity = audit.SeverityInfo
	}

	details := map[string]interface{}{
		"allowed":                 allowed,
		"impersonationVerb":       req.Verb.Raw,
		"impersonationVerbKind":   req.Verb.Kind.String(),
		"impersonationMode":       string(req.Verb.Mode),
		"impersonationConstraint": constraint,
		"identityResource":        req.Target.Resource,
		"identityName":            req.Target.Name,
		"identityNamespace":       req.Target.Namespace,
		"source":                  source,
		"requestorUID":            req.Requestor.UID,
	}
	if req.Target.Subresource != "" {
		details["extraKey"] = req.Target.Subresource
	}
	if req.Verb.UnderlyingVerb != "" {
		details["underlyingVerb"] = req.Verb.UnderlyingVerb
	}
	if reason != "" {
		details["reason"] = reason
	}
	if s.impersonationWarnedLegacy {
		details["legacyFallbackWarned"] = true
	}

	wc.auditService.Emit(s.ctx, &audit.Event{
		Type:     audit.EventResourceImpersonate,
		Severity: severity,
		Actor: audit.Actor{
			User:   req.Requestor.User,
			Groups: req.Requestor.Groups,
		},
		Target: audit.Target{
			Cluster:   s.clusterName,
			Kind:      req.Target.Resource,
			Name:      req.Target.Name,
			Namespace: req.Target.Namespace,
		},
		Details: details,
	})
}

// noteImpersonationOutcome records the final decision for an impersonation SAR
// that was not short-circuited by evaluateImpersonation, so that allows reached via
// RBAC or a session are audited and counted too.
func (wc *WebhookController) noteImpersonationOutcome(s *authorizeState) {
	if s.impersonation == nil {
		return
	}

	decision := "denied"
	if s.allowed {
		decision = "allowed"
	}

	constraint := ""
	if s.impersonation.Verb.IsConstrained() {
		constraint = impersonation.IdentityVerb(s.impersonation.Verb.Mode)
	}

	metrics.ImpersonationSARDecisions.WithLabelValues(
		s.clusterName, string(s.impersonation.Verb.Mode), decision,
		orDefault(s.allowSource, "final")).Inc()

	wc.emitImpersonationAudit(s, s.allowed, s.reason,
		orDefault(s.allowSource, "final"), constraint)

	s.reqLog.Infow(fmt.Sprintf("Impersonation %s", decision),
		"cluster", s.clusterName,
		"requestor", s.impersonation.Requestor.User,
		"requestorUID", s.impersonation.Requestor.UID,
		"verb", s.impersonation.Verb.Raw,
		"mode", string(s.impersonation.Verb.Mode),
		"impersonationConstraint", constraint,
		"source", s.allowSource)
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
