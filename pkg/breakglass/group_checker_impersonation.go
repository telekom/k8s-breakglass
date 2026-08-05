// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package breakglass

import (
	"context"
	"errors"
	"fmt"

	"go.uber.org/zap"
	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/impersonation"
	"github.com/telekom/k8s-breakglass/pkg/metrics"
)

// AuthCheckerUsername is the synthetic identity the RBAC probe impersonates. It is
// not a real user and never has RBAC of its own: the probe impersonates it
// together with a session's granted groups purely to ask the spoke "what could
// these groups do?".
const AuthCheckerUsername = "system:auth-checker"

// probeCapabilities caches per-spoke constrained-impersonation capability for the
// RBAC probe. It is package-level state because CanGroupsDo is a free function
// invoked per SubjectAccessReview and has no object to hang a cache off.
var probeCapabilities = impersonation.NewCapabilityCache(impersonation.DefaultCapabilityTTL)

// ProbeCapabilityCache exposes the cache so that callers can invalidate a spoke
// when its ClusterConfig changes, and so tests can control it.
func ProbeCapabilityCache() *impersonation.CapabilityCache {
	return probeCapabilities
}

// CanGroupsDoConstrained is CanGroupsDo with constrained-impersonation support.
//
// It impersonates AuthCheckerUsername plus the supplied groups and issues a
// SelfSubjectAccessReview on the spoke, exactly as CanGroupsDo always has. What is
// new is that on a spoke which supports constrained impersonation it does so under
// the `impersonate:user-info` constraint rather than a blanket `impersonate` grant.
//
// Backwards compatibility is the governing requirement here, because this function
// is what decides whether breakglass authorizes anyone at all:
//
//   - Capability is resolved PER SPOKE and cached, never inferred from the hub's
//     own Kubernetes version. Two spokes on different releases both work inside one
//     controller.
//   - Unknown capability attempts the constrained path first and falls back to
//     legacy on denial, then records what happened. A wrong first guess costs one
//     extra denied SelfSubjectAccessReview, not an outage.
//   - A spoke recorded as unsupported goes straight to legacy, so a pre-1.35
//     cluster pays no per-request penalty and behaves byte-identically to before
//     this feature existed.
//   - The fallback triggers on an impersonation denial only. A network error or an
//     unrelated 500 is returned to the caller rather than being recorded as
//     "constrained impersonation unsupported", so a transient blip cannot pin a
//     spoke to the legacy path.
func CanGroupsDoConstrained(
	ctx context.Context,
	rc *rest.Config,
	groups []string,
	sar authorizationv1.SubjectAccessReview,
	clustername string,
	cc *breakglassv1alpha1.ClusterConfig,
) (bool, error) {
	if rc == nil {
		return false, errors.New("rest config is nil")
	}

	ssarSpec, err := selfSubjectAccessReviewSpec(sar)
	if err != nil {
		return false, err
	}

	impCfg := clusterConstrainedImpersonation(cc)
	capability := resolveProbeCapability(clustername, impCfg)
	probeMode := probeModeFor(impCfg)

	identity := impersonation.Identity{
		UserName: AuthCheckerUsername,
		Groups:   groups,
	}

	// Try the constrained path when the spoke may support it.
	if capability.UsesConstrained() && probeMode.IsConstrained() {
		allowed, attemptErr := runProbe(ctx, rc, identity, probeMode, capability, ssarSpec)
		switch {
		case attemptErr == nil:
			probeCapabilities.RecordProbe(clustername, probeMode, true, capability.ServerVersion)
			setCapabilityMetric(clustername, impersonation.SupportYes)
			return allowed, nil

		case impersonation.IsConstrainedImpersonationDenial(attemptErr):
			// The spoke refused the constrained impersonation. This is exactly what a
			// pre-1.35 cluster does, and also what a 1.36 cluster with the gate off or
			// without the constrained RBAC grants does. All three want the same
			// remedy, so record unsupported and fall through to legacy.
			probeCapabilities.RecordProbe(clustername, probeMode, false, capability.ServerVersion)
			setCapabilityMetric(clustername, impersonation.SupportNo)
			metrics.ImpersonationDowngrades.WithLabelValues(clustername, string(probeMode)).Inc()
			zap.S().Infow(
				"Constrained impersonation refused by spoke; falling back to legacy impersonation "+
					"for the RBAC probe. This is expected on Kubernetes below 1.35, with the "+
					"ConstrainedImpersonation gate disabled, or before the constrained RBAC is applied.",
				"cluster", clustername, "mode", string(probeMode), "error", attemptErr.Error())

		default:
			// Not an impersonation denial: propagate rather than mislabelling the
			// spoke as lacking the feature.
			return false, attemptErr
		}
	}

	// Legacy path: the blanket impersonation breakglass has always used.
	allowed, err := runProbe(ctx, rc, identity, impersonation.ModeLegacy, capability, ssarSpec)
	if err != nil {
		return false, err
	}
	if capability.Support == impersonation.SupportNo {
		setCapabilityMetric(clustername, impersonation.SupportNo)
	}
	return allowed, nil
}

// runProbe performs one impersonated SelfSubjectAccessReview attempt.
func runProbe(
	ctx context.Context,
	rc *rest.Config,
	identity impersonation.Identity,
	mode impersonation.Mode,
	capability impersonation.Capability,
	ssarSpec authorizationv1.SelfSubjectAccessReviewSpec,
) (bool, error) {
	// Build with a capability that permits the requested mode; the caller has
	// already decided which mode to attempt.
	buildCapability := capability
	if mode.IsConstrained() {
		buildCapability.Support = impersonation.SupportYes
	}

	built, err := impersonation.Build(identity, mode, buildCapability)
	if err != nil {
		return false, fmt.Errorf("failed to build impersonation config for mode %q: %w", mode, err)
	}

	cfg := rest.CopyConfig(rc)
	cfg.Impersonate = built.Config

	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return false, fmt.Errorf("failed to create client: %w", err)
	}

	resp, err := client.AuthorizationV1().SelfSubjectAccessReviews().Create(
		ctx, &authorizationv1.SelfSubjectAccessReview{Spec: ssarSpec}, metav1.CreateOptions{})
	if err != nil {
		return false, err
	}

	zap.S().Debugw("Impersonated SelfSubjectAccessReview result",
		"allowed", resp.Status.Allowed,
		"mode", string(built.Mode),
		"impersonationConstraint", built.Constraint)

	return resp.Status.Allowed, nil
}

// resolveProbeCapability determines the capability to use for a spoke, letting an
// explicit ClusterConfig setting override detection.
func resolveProbeCapability(
	clustername string,
	impCfg *breakglassv1alpha1.ConstrainedImpersonationConfig,
) impersonation.Capability {
	switch impCfg.EffectiveSupport() {
	case breakglassv1alpha1.ConstrainedImpersonationEnabled:
		return impersonation.Capability{
			Support:     impersonation.SupportYes,
			DetectedVia: "configured",
		}
	case breakglassv1alpha1.ConstrainedImpersonationDisabled:
		return impersonation.Capability{
			Support:     impersonation.SupportNo,
			DetectedVia: "configured",
		}
	case breakglassv1alpha1.ConstrainedImpersonationAuto:
		return probeCapabilities.Get(clustername)
	default:
		return probeCapabilities.Get(clustername)
	}
}

// probeModeFor returns the constrained mode to use for the probe. user-info is the
// only mode that can carry groups, and carrying groups is the entire point of the
// probe, so anything else is silently corrected to user-info.
func probeModeFor(impCfg *breakglassv1alpha1.ConstrainedImpersonationConfig) impersonation.Mode {
	configured := impCfg.EffectiveProbeMode()
	if configured == breakglassv1alpha1.ImpersonationModeLegacy {
		return impersonation.ModeLegacy
	}
	if configured != breakglassv1alpha1.ImpersonationModeUserInfo {
		zap.S().Warnw(
			"constrainedImpersonation.probeMode must be user-info or legacy: the RBAC probe "+
				"impersonates groups, and user-info is the only mode that can carry them. "+
				"Using user-info.",
			"configured", string(configured))
	}
	return impersonation.ModeUserInfo
}

func clusterConstrainedImpersonation(
	cc *breakglassv1alpha1.ClusterConfig,
) *breakglassv1alpha1.ConstrainedImpersonationConfig {
	if cc == nil {
		return nil
	}
	return cc.Spec.ConstrainedImpersonation
}

func setCapabilityMetric(clustername string, support impersonation.Support) {
	for _, s := range []impersonation.Support{
		impersonation.SupportYes, impersonation.SupportNo, impersonation.SupportUnknown,
	} {
		value := 0.0
		if s == support {
			value = 1.0
		}
		metrics.ImpersonationCapability.WithLabelValues(clustername, s.String()).Set(value)
	}
}

// selfSubjectAccessReviewSpec converts an incoming SubjectAccessReview into the
// SelfSubjectAccessReview spec used by the probe.
func selfSubjectAccessReviewSpec(
	sar authorizationv1.SubjectAccessReview,
) (authorizationv1.SelfSubjectAccessReviewSpec, error) {
	var spec authorizationv1.SelfSubjectAccessReviewSpec

	switch {
	case sar.Spec.ResourceAttributes != nil:
		spec.ResourceAttributes = &authorizationv1.ResourceAttributes{
			Namespace:   sar.Spec.ResourceAttributes.Namespace,
			Verb:        sar.Spec.ResourceAttributes.Verb,
			Group:       sar.Spec.ResourceAttributes.Group,
			Resource:    sar.Spec.ResourceAttributes.Resource,
			Subresource: sar.Spec.ResourceAttributes.Subresource,
			Name:        sar.Spec.ResourceAttributes.Name,
		}
	case sar.Spec.NonResourceAttributes != nil:
		spec.NonResourceAttributes = &authorizationv1.NonResourceAttributes{
			Path: sar.Spec.NonResourceAttributes.Path,
			Verb: sar.Spec.NonResourceAttributes.Verb,
		}
	default:
		return spec, errors.New("sar spec must have either resourceAttributes or nonResourceAttributes")
	}

	return spec, nil
}
