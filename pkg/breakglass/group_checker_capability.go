// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package breakglass

import (
	"context"
	"fmt"

	"go.uber.org/zap"
	authorizationv1 "k8s.io/api/authorization/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/telekom/k8s-breakglass/pkg/impersonation"
)

// AuthCheckerProbeUID is the synthetic UID the capability-detection probe
// impersonates alongside AuthCheckerUsername.
//
// It is not a real UID and grants nothing by itself. It exists solely to make the
// detection probe DISCRIMINATING, which is the whole reason capability detection
// works at all — see detectProbeCapability for the argument.
//
// config/rbac/impersonate_constrained_role.yaml pins this exact string in
// resourceNames, so changing it here disables constrained-impersonation detection
// on every spoke until the RBAC is updated too.
const AuthCheckerProbeUID = "breakglass-capability-probe"

// capabilityDetectionSpec is the SelfSubjectAccessReview the detection probe
// issues. Its content is deliberately irrelevant: constrained impersonation
// authorizes the IMPERSONATION, and an impersonator never needs the impersonated
// permission itself. Only whether the impersonation was authorized is read.
func capabilityDetectionSpec() authorizationv1.SelfSubjectAccessReviewSpec {
	return authorizationv1.SelfSubjectAccessReviewSpec{
		ResourceAttributes: &authorizationv1.ResourceAttributes{
			Verb:     "get",
			Resource: "namespaces",
		},
	}
}

// detectProbeCapability determines, and caches, whether a spoke can really do
// constrained impersonation.
//
// # Why the obvious probe does not work
//
// KEP-5284 adds NO new headers: client-side semantics are deliberately unchanged,
// and the mode is derived server-side from the shape of the impersonated identity.
// An ordinary impersonated request therefore looks IDENTICAL on the wire whether or
// not the spoke supports constrained impersonation. Worse, the apiserver falls back
// to legacy impersonation whenever every constrained mode denies, so the retained
// blanket `impersonate` grant authorizes the request either way. Concluding
// "supported" from such a request's success is therefore not detection at all: it
// reports every legacy-granted spoke as supported, at any Kubernetes version, with
// the feature gate in any state.
//
// That mislabelling is not cosmetic. The retire-the-legacy-grant procedure keys off
// this verdict, so a false "supported" walks an operator into stripping the only
// grant that actually works on that spoke — a total outage presented as a
// successful rollout.
//
// # What actually discriminates
//
// Two independent signals are combined, and BOTH must be positive before support is
// claimed:
//
//  1. A version floor. Constrained impersonation cannot exist before 1.35, so a
//     spoke below it is settled without any probe. This is the only place a version
//     is compared, and an unreadable version never yields "supported".
//
//  2. A UID-bearing impersonation probe. This is the load-bearing part. The probe
//     impersonates AuthCheckerUsername *plus* AuthCheckerProbeUID, which forces the
//     apiserver to authorize the `uids` identity resource in the
//     authentication.k8s.io API group. The retained legacy grant covers only
//     `users` and `groups` in the CORE group, so it CANNOT satisfy a uids check.
//     The legacy fallback therefore cannot rescue this probe, and success is
//     positive proof that a constrained mode genuinely ran and was authorized.
//
// The result is that the ambiguous cases all resolve to "unsupported", which keeps
// the spoke on the legacy path it already works on:
//
//   - below 1.35                      → unsupported (version floor)
//   - 1.35+, gate off                 → unsupported (constrained verbs never issued,
//     and legacy cannot authorize uids)
//   - 1.35+, gate on, RBAC not applied → unsupported (nothing grants the uids verb)
//   - 1.35+, gate on, RBAC applied     → SUPPORTED, and provably so
//
// Note the third case in particular: constrained RBAC applied to a spoke that
// cannot use it is "accepted but inert", and this probe correctly refuses to be
// fooled by it, because an inert grant cannot authorize anything.
//
// Known limitation, documented rather than hidden: the discriminator assumes the
// spoke's legacy grant does not itself cover `authentication.k8s.io` `uids`. A
// deployment that binds breakglass to cluster-admin (or to any role broad enough to
// include that resource) can produce a false "supported". Such a spoke still WORKS —
// constrained is attempted, legacy fallback covers it — but its capability gauge
// cannot be trusted on its own. This is precisely why the documented procedure for
// retiring a legacy grant requires an explicit manual verification and an operator
// assertion, and never keys off the gauge alone.
//
// A transient failure is never allowed to pin a spoke: an unreadable version or an
// error that is not a clean authorization denial yields an UNCACHED
// SupportUnknown, so the next request tries again. Unknown still attempts the
// constrained path and falls back, i.e. exactly today's behaviour.
func detectProbeCapability(
	ctx context.Context,
	rc *rest.Config,
	clustername string,
) impersonation.Capability {
	serverVersion, hint := probeVersionHint(rc)

	// Signal 1: a spoke whose release predates the feature is settled without a
	// probe. An unparseable or unreadable version deliberately lands here too, via
	// VersionHint's own "assume unsupported" contract.
	if hint == impersonation.SupportNo {
		entry := impersonation.Capability{
			Support:       impersonation.SupportNo,
			Mode:          impersonation.ModeLegacy,
			DetectedVia:   "version-floor",
			ServerVersion: serverVersion,
		}
		probeCapabilities.Set(clustername, entry)
		zap.S().Infow(
			"Spoke cannot support constrained impersonation; using legacy impersonation. "+
				"This is expected below Kubernetes 1.35 and whenever the spoke's version cannot be read.",
			"cluster", clustername, "serverVersion", serverVersion)
		return entry
	}

	// Signal 2: the discriminating probe. Only a genuinely functioning constrained
	// mode can authorize this, because the legacy grant cannot cover uids.
	allowed, err := runCapabilityProbe(ctx, rc)
	switch {
	case err == nil && allowed:
		entry := impersonation.Capability{
			Support:       impersonation.SupportYes,
			Mode:          impersonation.ModeUserInfo,
			DetectedVia:   "capability-probe",
			ServerVersion: serverVersion,
		}
		probeCapabilities.Set(clustername, entry)
		zap.S().Infow("Constrained impersonation confirmed on spoke",
			"cluster", clustername, "serverVersion", serverVersion)
		return entry

	case err == nil && !allowed:
		// The impersonation itself was authorized, but the SelfSubjectAccessReview
		// answered "no" about its (irrelevant) subject query. That still proves the
		// impersonation was accepted, so treat it as confirmation.
		entry := impersonation.Capability{
			Support:       impersonation.SupportYes,
			Mode:          impersonation.ModeUserInfo,
			DetectedVia:   "capability-probe",
			ServerVersion: serverVersion,
		}
		probeCapabilities.Set(clustername, entry)
		return entry

	case isAuthorizationDenial(err):
		entry := impersonation.Capability{
			Support:       impersonation.SupportNo,
			Mode:          impersonation.ModeLegacy,
			DetectedVia:   "capability-probe-denied",
			ServerVersion: serverVersion,
		}
		probeCapabilities.Set(clustername, entry)
		zap.S().Infow(
			"Constrained impersonation is not usable on this spoke; using legacy impersonation. "+
				"Expected when the ConstrainedImpersonation feature gate is disabled, or before "+
				"config/rbac/impersonate_constrained_role.yaml has been applied to the spoke.",
			"cluster", clustername, "serverVersion", serverVersion, "error", err.Error())
		return entry

	default:
		// Not a clean denial: a network blip, a 500, a timeout. Deliberately NOT
		// cached, so this cannot pin the spoke on the strength of a transient error.
		zap.S().Warnw(
			"Could not determine constrained-impersonation capability for spoke; "+
				"leaving it undetermined and retrying on the next request",
			"cluster", clustername, "serverVersion", serverVersion, "error", errString(err))
		return impersonation.Capability{
			Support:       impersonation.SupportUnknown,
			DetectedVia:   "detection-inconclusive",
			ServerVersion: serverVersion,
		}
	}
}

// runCapabilityProbe issues the UID-bearing impersonated SelfSubjectAccessReview
// that only a working constrained mode can authorize.
func runCapabilityProbe(ctx context.Context, rc *rest.Config) (bool, error) {
	cfg := rest.CopyConfig(rc)
	cfg.Impersonate = rest.ImpersonationConfig{
		UserName: AuthCheckerUsername,
		UID:      AuthCheckerProbeUID,
	}

	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return false, fmt.Errorf("failed to create capability probe client: %w", err)
	}

	resp, err := client.AuthorizationV1().SelfSubjectAccessReviews().Create(
		ctx,
		&authorizationv1.SelfSubjectAccessReview{Spec: capabilityDetectionSpec()},
		metav1.CreateOptions{})
	if err != nil {
		return false, err
	}
	return resp.Status.Allowed, nil
}

// probeVersionHint reads the spoke's reported version and converts it to a support
// hint. A version that cannot be read yields SupportNo, matching VersionHint's
// documented "assume unsupported" contract: the spoke then keeps the legacy
// behaviour it already has.
func probeVersionHint(rc *rest.Config) (string, impersonation.Support) {
	dc, err := discovery.NewDiscoveryClientForConfig(rc)
	if err != nil {
		return "", impersonation.SupportNo
	}
	version, err := dc.ServerVersion()
	if err != nil || version == nil {
		return "", impersonation.SupportNo
	}
	return version.GitVersion, impersonation.VersionHint(version.Major, version.Minor)
}

// isAuthorizationDenial reports whether err is a clean authorization refusal, as
// opposed to a transport or server failure.
//
// Detection uses a dedicated probe that the legacy grant provably cannot authorize,
// so within detection a Forbidden or Unauthorized answer unambiguously means
// "constrained impersonation is not usable here". That is a stronger statement than
// the message-sniffing IsConstrainedImpersonationDenial has to do on the functional
// path, which is why detection does not reuse it.
func isAuthorizationDenial(err error) bool {
	if err == nil {
		return false
	}
	return k8serrors.IsForbidden(err) || k8serrors.IsUnauthorized(err) ||
		impersonation.IsConstrainedImpersonationDenial(err)
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
