// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package breakglass

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	authenticationv1 "k8s.io/api/authentication/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	"k8s.io/client-go/rest"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/impersonation"
)

// fakeSpoke is a minimal stand-in for a spoke API server, good enough to exercise
// capability detection end to end.
//
// It models the two things that actually decide the verdict: the version it reports
// at /version, and which impersonation identity resources its RBAC would authorize.
// Requests are answered by inspecting the Impersonate-* headers, exactly as a real
// apiserver's authorization would.
type fakeSpoke struct {
	// major/minor are reported at /version.
	major, minor string

	// allowUIDImpersonation models a spoke that both supports constrained
	// impersonation AND has the constrained RBAC applied, i.e. one that can
	// authorize a `uids` identity check in authentication.k8s.io.
	//
	// A spoke with only the legacy grant leaves this false: the legacy blanket
	// `impersonate` grant covers `users` and `groups` in the CORE group and provably
	// cannot authorize a uids check.
	allowUIDImpersonation bool

	// sawUIDHeader records whether any request carried Impersonate-Uid, so tests can
	// assert the probe is actually discriminating rather than accidentally passing.
	sawUIDHeader bool

	server *httptest.Server
}

func newFakeSpoke(t *testing.T, s *fakeSpoke) *rest.Config {
	t.Helper()

	mux := http.NewServeMux()

	mux.HandleFunc("/version", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]string{
			"major": s.major, "minor": s.minor,
			"gitVersion": "v" + s.major + "." + s.minor + ".0",
		})
	})

	// SelfSubjectAccessReview: the impersonation is authorized (or not) before the
	// SSAR is ever evaluated, which is what this handler models.
	mux.HandleFunc("/apis/authorization.k8s.io/v1/selfsubjectaccessreviews",
		func(w http.ResponseWriter, r *http.Request) {
			uid := r.Header.Get(authenticationv1.ImpersonateUIDHeader)
			if uid != "" {
				s.sawUIDHeader = true
				if !s.allowUIDImpersonation {
					// What a real spoke does when nothing grants the uids identity
					// check: on a pre-1.35 release the constrained verbs are never
					// consulted, and the legacy fallback cannot cover uids either.
					writeForbidden(w,
						`uids.authentication.k8s.io "`+uid+`" is forbidden: `+
							`User "system:serviceaccount:breakglass:manager" cannot impersonate `+
							`resource "uids" in API group "authentication.k8s.io" at the cluster scope`)
					return
				}
			}
			// Legacy grant authorizes username+groups impersonation, so the
			// functional probe succeeds regardless of constrained support.
			writeJSON(w, &authorizationv1.SelfSubjectAccessReview{
				Status: authorizationv1.SubjectAccessReviewStatus{Allowed: true},
			})
		})

	s.server = httptest.NewServer(mux)
	t.Cleanup(s.server.Close)

	return &rest.Config{Host: s.server.URL}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func writeForbidden(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"kind": "Status", "apiVersion": "v1", "status": "Failure",
		"message": msg, "reason": "Forbidden", "code": 403,
	})
}

func probeSAR() authorizationv1.SubjectAccessReview {
	return authorizationv1.SubjectAccessReview{
		Spec: authorizationv1.SubjectAccessReviewSpec{
			ResourceAttributes: &authorizationv1.ResourceAttributes{
				Verb: "get", Resource: "pods", Namespace: "default",
			},
		},
	}
}

// TestCapabilityDetection_LegacyOnlySpokeIsNotReportedSupported is THE regression
// test for the detection defect, and the test whose absence allowed it.
//
// The defect: capability was concluded from the success of an ordinary impersonated
// SelfSubjectAccessReview. But KEP-5284 adds no headers, so that request is
// byte-identical whether or not the spoke supports constrained impersonation, and
// the deliberately-retained blanket `impersonate` grant authorizes it either way.
// Every legacy-granted spoke was therefore recorded "supported" at ANY Kubernetes
// version with the gate in ANY state.
//
// Why that is severe rather than cosmetic: the documented procedure for retiring the
// legacy ClusterRole keys off this verdict. A false "supported" tells an operator to
// strip the only grant that works on that spoke, and breakglass then stops
// authorizing anyone — a total outage presented as a successful rollout.
//
// The invariant asserted here is the one that matters: SupportYes must NEVER be
// reported on evidence a legacy grant alone can produce. Under-claiming is safe,
// because it keeps the legacy grant in place.
func TestCapabilityDetection_LegacyOnlySpokeIsNotReportedSupported(t *testing.T) {
	// Every spoke shape on which constrained impersonation does NOT work, but where
	// the retained legacy grant makes an ordinary impersonated request succeed.
	spokes := []struct {
		name         string
		major, minor string
	}{
		{"pre-1.35, feature absent entirely", "1", "31"},
		{"1.34, feature absent entirely", "1", "34"},
		// 1.35+ with the gate off, or without the constrained RBAC applied. The
		// version permits the feature, so only the probe can settle it — and it
		// cannot be satisfied without a working constrained grant.
		{"1.35, gate off or RBAC not applied", "1", "35"},
		{"1.36, gate explicitly off", "1", "36"},
		// Real clusters report suffixed minors.
		{"1.36+ suffixed, gate off", "1", "36+"},
	}

	for _, sp := range spokes {
		t.Run(sp.name, func(t *testing.T) {
			cluster := "legacy-only-" + t.Name()
			t.Cleanup(func() { ForgetProbeCapability(cluster) })

			spoke := &fakeSpoke{
				major: sp.major, minor: sp.minor,
				allowUIDImpersonation: false, // legacy grant only
			}
			rc := newFakeSpoke(t, spoke)

			// The request must still be SERVED. Backwards compatibility is the
			// governing requirement: a spoke without constrained support keeps
			// working exactly as it does today, over legacy impersonation.
			allowed, err := CanGroupsDoConstrained(
				context.Background(), rc, []string{"sre", "oncall"},
				probeSAR(), cluster, nil)

			require.NoError(t, err,
				"a legacy-only spoke must keep working; this is the outage case")
			assert.True(t, allowed,
				"the legacy path must still answer the authorization question")

			// The verdict must not claim support.
			got := probeCapabilities.Get(cluster)
			assert.NotEqual(t, impersonation.SupportYes, got.Support,
				"a legacy-only spoke was reported SupportYes. The retire-the-legacy-grant "+
					"procedure keys off this verdict, so this walks an operator into stripping "+
					"the only grant that works on this spoke — a silent total outage.")
			assert.Equal(t, impersonation.SupportNo, got.Support,
				"detection should positively conclude unsupported, keeping the spoke on legacy")
		})
	}
}

// TestCapabilityDetection_SupportedSpokeIsDetected is the other half: detection must
// not be so conservative that it never reports support, or the migration this
// feature exists to enable could never complete.
func TestCapabilityDetection_SupportedSpokeIsDetected(t *testing.T) {
	for _, minor := range []string{"35", "36", "36+", "38"} {
		t.Run("1."+minor, func(t *testing.T) {
			cluster := "supported-" + t.Name()
			t.Cleanup(func() { ForgetProbeCapability(cluster) })

			spoke := &fakeSpoke{
				major: "1", minor: minor,
				allowUIDImpersonation: true, // gate on AND constrained RBAC applied
			}
			rc := newFakeSpoke(t, spoke)

			allowed, err := CanGroupsDoConstrained(
				context.Background(), rc, []string{"sre"}, probeSAR(), cluster, nil)

			require.NoError(t, err)
			assert.True(t, allowed)

			got := probeCapabilities.Get(cluster)
			assert.Equal(t, impersonation.SupportYes, got.Support,
				"a spoke that genuinely supports constrained impersonation was not detected")
			assert.Equal(t, "capability-probe", got.DetectedVia)

			assert.True(t, spoke.sawUIDHeader,
				"the detection probe did not send Impersonate-Uid, so it was not discriminating "+
					"and its success proves nothing")
		})
	}
}

// TestCapabilityDetection_VersionFloorSettlesWithoutProbing asserts a pre-1.35 spoke
// is decided on version alone. Constrained impersonation cannot exist there, so
// probing would be a guaranteed-denied round trip on every cache miss.
func TestCapabilityDetection_VersionFloorSettlesWithoutProbing(t *testing.T) {
	cluster := "floor-" + t.Name()
	t.Cleanup(func() { ForgetProbeCapability(cluster) })

	spoke := &fakeSpoke{major: "1", minor: "30"}
	rc := newFakeSpoke(t, spoke)

	got := detectProbeCapability(context.Background(), rc, cluster)

	assert.Equal(t, impersonation.SupportNo, got.Support)
	assert.Equal(t, "version-floor", got.DetectedVia)
	assert.False(t, spoke.sawUIDHeader,
		"a spoke below the version floor should be settled without an impersonation probe")
}

// TestCapabilityDetection_UnreadableVersionIsNotSupported covers the compat
// contract's rule that an unknown or unparseable version must be treated as "not
// supported", so such a spoke keeps the legacy behaviour it already has.
func TestCapabilityDetection_UnreadableVersionIsNotSupported(t *testing.T) {
	cluster := "noversion-" + t.Name()
	t.Cleanup(func() { ForgetProbeCapability(cluster) })

	// A server that fails /version outright.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	got := detectProbeCapability(context.Background(), &rest.Config{Host: srv.URL}, cluster)

	assert.NotEqual(t, impersonation.SupportYes, got.Support,
		"an unreadable version must never yield SupportYes")
	assert.Equal(t, impersonation.SupportNo, got.Support)
}

// TestCapabilityDetection_TransientFailureIsNotCached asserts a network-level
// failure during detection does not pin the spoke.
//
// This is the rule the original code got right and which must survive: only a clean
// authorization answer may write a verdict. A blip must leave the spoke
// undetermined so the next request retries.
func TestCapabilityDetection_TransientFailureIsNotCached(t *testing.T) {
	cluster := "transient-" + t.Name()
	t.Cleanup(func() { ForgetProbeCapability(cluster) })

	mux := http.NewServeMux()
	mux.HandleFunc("/version", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]string{"major": "1", "minor": "36", "gitVersion": "v1.36.0"})
	})
	// The probe itself fails with a server error, not a denial.
	mux.HandleFunc("/apis/authorization.k8s.io/v1/selfsubjectaccessreviews",
		func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"kind": "Status", "apiVersion": "v1", "status": "Failure",
				"message": "an error on the server has prevented the request from succeeding",
				"reason":  "InternalError", "code": 500,
			})
		})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	got := detectProbeCapability(context.Background(), &rest.Config{Host: srv.URL}, cluster)

	assert.Equal(t, impersonation.SupportUnknown, got.Support,
		"a transient failure must not settle capability")
	assert.Equal(t, impersonation.SupportUnknown, probeCapabilities.Get(cluster).Support,
		"a transient failure must not be CACHED, or a blip pins the spoke for the TTL")
}

// TestCapabilityDetection_ExplicitConfigSkipsDetection asserts an operator's
// explicit assertion wins and costs no probe. This is the escape hatch the docs
// point operators at when they need to retire a legacy grant deliberately.
func TestCapabilityDetection_ExplicitConfigSkipsDetection(t *testing.T) {
	tests := []struct {
		name    string
		support breakglassv1alpha1.ConstrainedImpersonationSupport
		want    impersonation.Support
	}{
		{"enabled", breakglassv1alpha1.ConstrainedImpersonationEnabled, impersonation.SupportYes},
		{"disabled", breakglassv1alpha1.ConstrainedImpersonationDisabled, impersonation.SupportNo},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cluster := "explicit-" + t.Name()
			t.Cleanup(func() { ForgetProbeCapability(cluster) })

			// A spoke that would detect the OPPOSITE of what is configured, proving
			// the configuration is what decided.
			spoke := &fakeSpoke{
				major: "1", minor: "31",
				allowUIDImpersonation: tc.support == breakglassv1alpha1.ConstrainedImpersonationDisabled,
			}
			rc := newFakeSpoke(t, spoke)

			cc := &breakglassv1alpha1.ClusterConfig{
				Spec: breakglassv1alpha1.ClusterConfigSpec{
					ConstrainedImpersonation: &breakglassv1alpha1.ConstrainedImpersonationConfig{
						Support: tc.support,
					},
				},
			}

			_, err := CanGroupsDoConstrained(
				context.Background(), rc, []string{"sre"}, probeSAR(), cluster, cc)
			require.NoError(t, err)

			assert.Equal(t, tc.want, probeCapabilities.Get(cluster).Support)
			assert.Equal(t, "configured", probeCapabilities.Get(cluster).DetectedVia,
				"an explicit setting must be recorded as configured, not as detected")
			assert.False(t, spoke.sawUIDHeader,
				"an explicit support setting must not pay for a detection probe")
		})
	}
}

// TestForgetProbeCapability_DropsTheRecord asserts the ClusterConfig-change hook
// really invalidates a spoke, so flipping support takes effect on the next request
// rather than after the cache TTL.
func TestForgetProbeCapability_DropsTheRecord(t *testing.T) {
	cluster := "forget-" + t.Name()
	t.Cleanup(func() { ForgetProbeCapability(cluster) })

	probeCapabilities.Set(cluster, impersonation.Capability{
		Support: impersonation.SupportYes, DetectedVia: "capability-probe",
	})
	require.Equal(t, impersonation.SupportYes, probeCapabilities.Get(cluster).Support)

	ForgetProbeCapability(cluster)

	assert.Equal(t, impersonation.SupportUnknown, probeCapabilities.Get(cluster).Support,
		"ForgetProbeCapability did not drop the record, so a ClusterConfig change would "+
			"not be honoured until the TTL expired")
}

// TestAuthCheckerProbeUIDMatchesRBAC pins the probe UID against the RBAC that must
// name it. Detection silently stops working if the two drift, and "silently stops
// detecting" degrades to "every spoke looks unsupported", which is safe but blocks
// the migration.
func TestAuthCheckerProbeUIDMatchesRBAC(t *testing.T) {
	assert.Equal(t, "breakglass-capability-probe", AuthCheckerProbeUID,
		"config/rbac/impersonate_constrained_role.yaml pins this value in resourceNames")
	assert.False(t, strings.HasPrefix(AuthCheckerProbeUID, "system:"),
		"the probe UID must not look like a real system principal")
}
