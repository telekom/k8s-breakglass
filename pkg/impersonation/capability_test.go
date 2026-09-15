// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package impersonation

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

// TestVersionHint covers the full per-spoke version matrix. This is the ONLY
// version comparison in the feature, and its result is advisory.
func TestVersionHint(t *testing.T) {
	tests := []struct {
		name         string
		major, minor string
		want         Support
	}{
		// Feature absent entirely.
		{"1.28", "1", "28", SupportNo},
		{"1.33", "1", "33", SupportNo},
		{"1.34", "1", "34", SupportNo},

		// 1.35: gate exists but off by default, so it must be opted into.
		// Unknown until probed.
		{"1.35 alpha opt-in", "1", "35", SupportUnknown},

		// 1.36+: gate on by default. Still only a hint — it can be disabled.
		{"1.36 beta default on", "1", "36", SupportYes},
		{"1.37", "1", "37", SupportYes},
		{"1.38 planned GA", "1", "38", SupportYes},
		{"1.40", "1", "40", SupportYes},

		// Real clusters report non-numeric suffixes.
		{"1.36+ suffix", "1", "36+", SupportYes},
		{"managed distro suffix", "1", "31.2-eks-1234", SupportNo},
		{"gke suffix", "1", "36.1-gke.100", SupportYes},

		// Unparseable or unexpected: assume not supported, so a spoke whose version
		// cannot be read keeps the legacy behaviour it has today.
		{"empty", "", "", SupportNo},
		{"empty minor", "1", "", SupportNo},
		{"non numeric minor", "1", "abc", SupportNo},
		{"non numeric major", "x", "36", SupportNo},
		{"major 2", "2", "0", SupportNo},
		{"major 0", "0", "36", SupportNo},
		{"whitespace", " ", " ", SupportNo},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := VersionHint(tc.major, tc.minor); got != tc.want {
				t.Errorf("VersionHint(%q, %q) = %v, want %v", tc.major, tc.minor, got, tc.want)
			}
		})
	}
}

// TestCapabilityUsesConstrained asserts the backwards-compatibility invariant:
// unknown capability must ATTEMPT the constrained path, never deny.
func TestCapabilityUsesConstrained(t *testing.T) {
	tests := []struct {
		name string
		cap  Capability
		want bool
	}{
		// Zero value = unknown = try constrained, let the fallback decide.
		{"zero value", Capability{}, true},
		{"unknown", Capability{Support: SupportUnknown}, true},
		{"supported", Capability{Support: SupportYes}, true},
		// Only a positively-detected lack of support skips the constrained path.
		{"unsupported", Capability{Support: SupportNo}, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.cap.UsesConstrained(); got != tc.want {
				t.Errorf("UsesConstrained() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestSupportString(t *testing.T) {
	tests := map[Support]string{
		SupportYes:     "supported",
		SupportNo:      "unsupported",
		SupportUnknown: "unknown",
		Support(99):    "unknown",
	}
	for s, want := range tests {
		if got := s.String(); got != want {
			t.Errorf("Support(%d).String() = %q, want %q", s, got, want)
		}
	}
}

// TestCapabilityCache_PerSpoke is the hub-and-spoke requirement: two spokes on
// different Kubernetes versions must both work inside one running controller.
func TestCapabilityCache_PerSpoke(t *testing.T) {
	c := NewCapabilityCache(time.Minute)

	c.RecordProbe("modern-spoke", ModeUserInfo, true, "v1.36.1")
	c.RecordProbe("legacy-spoke", ModeUserInfo, false, "v1.31.0")
	c.RecordProbe("alpha-spoke", ModeUserInfo, true, "v1.35.0")

	modern := c.Get("modern-spoke")
	if modern.Support != SupportYes {
		t.Errorf("modern-spoke Support = %v, want SupportYes", modern.Support)
	}
	if !modern.UsesConstrained() {
		t.Error("modern-spoke should use constrained impersonation")
	}
	if modern.DetectedVia != "probe-success" {
		t.Errorf("modern-spoke DetectedVia = %q", modern.DetectedVia)
	}

	legacy := c.Get("legacy-spoke")
	if legacy.Support != SupportNo {
		t.Errorf("legacy-spoke Support = %v, want SupportNo", legacy.Support)
	}
	if legacy.UsesConstrained() {
		t.Error("legacy-spoke must not use constrained impersonation")
	}
	if legacy.DetectedVia != "probe-denied" {
		t.Errorf("legacy-spoke DetectedVia = %q", legacy.DetectedVia)
	}

	if c.Get("alpha-spoke").Support != SupportYes {
		t.Error("alpha-spoke (1.35 with gate opted in) should be supported")
	}

	// An unknown spoke must not inherit any other spoke's verdict.
	unknown := c.Get("never-seen")
	if unknown.Support != SupportUnknown {
		t.Errorf("unseen spoke Support = %v, want SupportUnknown", unknown.Support)
	}
	if !unknown.UsesConstrained() {
		t.Error("unseen spoke should attempt constrained impersonation")
	}
}

func TestCapabilityCache_TTLExpiry(t *testing.T) {
	c := NewCapabilityCache(time.Minute)

	base := time.Now()
	current := base
	c.now = func() time.Time { return current }

	c.RecordProbe("spoke", ModeUserInfo, false, "v1.31.0")

	if got := c.Get("spoke"); got.Support != SupportNo {
		t.Fatalf("fresh entry Support = %v, want SupportNo", got.Support)
	}

	// Just inside the TTL: still trusted.
	current = base.Add(59 * time.Second)
	if got := c.Get("spoke"); got.Support != SupportNo {
		t.Errorf("entry at 59s Support = %v, want SupportNo", got.Support)
	}

	// Past the TTL: forgotten, so enabling the gate on a spoke takes effect without
	// restarting the controller.
	current = base.Add(2 * time.Minute)
	if got := c.Get("spoke"); got.Support != SupportUnknown {
		t.Errorf("expired entry Support = %v, want SupportUnknown", got.Support)
	}
}

func TestCapabilityCache_DefaultTTL(t *testing.T) {
	for _, ttl := range []time.Duration{0, -time.Second} {
		c := NewCapabilityCache(ttl)
		if c.ttl != DefaultCapabilityTTL {
			t.Errorf("NewCapabilityCache(%v).ttl = %v, want %v", ttl, c.ttl, DefaultCapabilityTTL)
		}
	}
}

func TestCapabilityCache_RecordConfigured(t *testing.T) {
	c := NewCapabilityCache(time.Minute)

	c.RecordConfigured("spoke", SupportNo, ModeLegacy)
	got := c.Get("spoke")

	if got.Support != SupportNo {
		t.Errorf("Support = %v, want SupportNo", got.Support)
	}
	if got.DetectedVia != "configured" {
		t.Errorf("DetectedVia = %q, want configured", got.DetectedVia)
	}
}

func TestCapabilityCache_ForgetAndLen(t *testing.T) {
	c := NewCapabilityCache(time.Minute)

	c.RecordProbe("a", ModeUserInfo, true, "")
	c.RecordProbe("b", ModeUserInfo, false, "")
	if got := c.Len(); got != 2 {
		t.Errorf("Len() = %d, want 2", got)
	}

	c.Forget("a")
	if got := c.Len(); got != 1 {
		t.Errorf("Len() after Forget = %d, want 1", got)
	}
	if got := c.Get("a"); got.Support != SupportUnknown {
		t.Errorf("forgotten spoke Support = %v", got.Support)
	}
}

func TestCapabilityCache_LenExcludesExpired(t *testing.T) {
	c := NewCapabilityCache(time.Minute)
	base := time.Now()
	current := base
	c.now = func() time.Time { return current }

	c.RecordProbe("a", ModeUserInfo, true, "")
	current = base.Add(2 * time.Minute)

	if got := c.Len(); got != 0 {
		t.Errorf("Len() with only expired entries = %d, want 0", got)
	}
}

func TestCapabilityCache_Concurrent(t *testing.T) {
	c := NewCapabilityCache(time.Minute)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(3)
		cluster := fmt.Sprintf("spoke-%d", i%5)
		go func() { defer wg.Done(); c.RecordProbe(cluster, ModeUserInfo, true, "v1.36.0") }()
		go func() { defer wg.Done(); _ = c.Get(cluster) }()
		go func() { defer wg.Done(); _ = c.Len() }()
	}
	wg.Wait()
}

// TestIsConstrainedImpersonationDenial guards the rule that a transient failure
// must never pin a spoke to legacy mode.
func TestIsConstrainedImpersonationDenial(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},

		// Genuine impersonation refusals, in the shapes real clusters produce.
		{
			"forbidden impersonate",
			errors.New(`selfsubjectaccessreviews.authorization.k8s.io is forbidden: User "system:serviceaccount:breakglass:manager" cannot impersonate resource "users" in API group "authentication.k8s.io"`),
			true,
		},
		{
			"cannot impersonate",
			errors.New(`User "manager" cannot impersonate resource "groups"`),
			true,
		},
		{
			"impersonation not allowed",
			errors.New("impersonating the system:masters group is not allowed"),
			true,
		},

		// NOT impersonation denials. Recording these as "unsupported" would pin a
		// spoke to the legacy path on the strength of a transient blip.
		{"network", errors.New("dial tcp 10.0.0.1:6443: i/o timeout"), false},
		{"server error", errors.New("an error on the server (\"Internal Server Error\") has prevented the request from succeeding"), false},
		{"context cancelled", errors.New("context deadline exceeded"), false},
		{"unrelated forbidden", errors.New(`pods is forbidden: User "x" cannot list resource "pods"`), false},
		{"tls", errors.New("x509: certificate signed by unknown authority"), false},
		{"not found", errors.New(`the server could not find the requested resource`), false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsConstrainedImpersonationDenial(tc.err); got != tc.want {
				t.Errorf("IsConstrainedImpersonationDenial(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestIsConstrainedImpersonationDenial_WrappedError(t *testing.T) {
	inner := errors.New(`User "manager" cannot impersonate resource "users"`)
	wrapped := fmt.Errorf("probe failed: %w", inner)

	if !IsConstrainedImpersonationDenial(wrapped) {
		t.Error("wrapped impersonation denial not detected")
	}
}

func TestParseVersionComponent(t *testing.T) {
	tests := []struct {
		in     string
		want   int
		wantOK bool
	}{
		{"36", 36, true},
		{"36+", 36, true},
		{"31.2-eks-1234", 31, true},
		{"1", 1, true},
		{"0", 0, true},
		{"", 0, false},
		{"abc", 0, false},
		{"+36", 0, false},
		{" 36", 36, true},
	}

	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			got, ok := parseVersionComponent(tc.in)
			if ok != tc.wantOK || (ok && got != tc.want) {
				t.Errorf("parseVersionComponent(%q) = (%d, %v), want (%d, %v)",
					tc.in, got, ok, tc.want, tc.wantOK)
			}
		})
	}
}
