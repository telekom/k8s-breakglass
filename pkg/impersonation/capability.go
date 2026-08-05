// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package impersonation

import (
	"strconv"
	"strings"
	"sync"
	"time"
)

// Support is a spoke's detected constrained-impersonation capability.
type Support int

const (
	// SupportUnknown means capability has not been determined yet. Callers MUST
	// treat this as "try constrained, fall back to legacy" — never as a denial.
	SupportUnknown Support = iota

	// SupportYes means a constrained impersonation attempt against this spoke
	// has actually succeeded.
	SupportYes

	// SupportNo means constrained impersonation does not work against this spoke:
	// the release predates the feature, or the gate is off, or no RBAC grants the
	// constrained verbs. In every one of those cases the correct behaviour is the
	// same — use legacy impersonation — so they deliberately are not distinguished.
	SupportNo
)

// String renders the support level for logs, metrics and status conditions.
func (s Support) String() string {
	switch s {
	case SupportYes:
		return "supported"
	case SupportNo:
		return "unsupported"
	case SupportUnknown:
		return "unknown"
	default:
		return "unknown"
	}
}

// Capability is the cached capability record for one spoke.
type Capability struct {
	// Support is the detected level.
	Support Support

	// Mode is the mode that last worked. Meaningful when Support is SupportYes.
	Mode Mode

	// DetectedVia records how the conclusion was reached: "probe-success",
	// "probe-denied", "version-hint" or "configured".
	DetectedVia string

	// ServerVersion is the spoke's reported version, when known. Advisory only.
	ServerVersion string

	// DeterminedAt is when the record was written.
	DeterminedAt time.Time
}

// UsesConstrained reports whether breakglass should build a constrained identity
// for this spoke. Unknown capability returns true so that the constrained path is
// ATTEMPTED first and the legacy fallback is what actually decides — probing beats
// guessing, and a wrong guess here costs one extra denied SelfSubjectAccessReview
// rather than an outage.
func (c Capability) UsesConstrained() bool {
	return c.Support != SupportNo
}

// DefaultCapabilityTTL is how long a capability record is trusted. It is long
// enough to keep the probe off the hot path and short enough that enabling the
// feature gate on a spoke takes effect without restarting the controller.
const DefaultCapabilityTTL = 10 * time.Minute

// CapabilityCache stores per-spoke capability records.
//
// Capability is deliberately per-spoke and never inferred from the hub's own
// Kubernetes version: in a hub-and-spoke topology the hub and every spoke can be
// on different releases, and two spokes at different versions must both work
// inside one running controller.
type CapabilityCache struct {
	mu      sync.RWMutex
	entries map[string]Capability
	ttl     time.Duration
	now     func() time.Time
}

// NewCapabilityCache creates a cache with the given TTL. A non-positive ttl uses
// DefaultCapabilityTTL.
func NewCapabilityCache(ttl time.Duration) *CapabilityCache {
	if ttl <= 0 {
		ttl = DefaultCapabilityTTL
	}
	return &CapabilityCache{
		entries: make(map[string]Capability),
		ttl:     ttl,
		now:     time.Now,
	}
}

// Get returns the cached capability for a spoke. A missing or expired entry
// yields a zero Capability whose Support is SupportUnknown, so the caller
// attempts the constrained path and learns from the outcome.
func (c *CapabilityCache) Get(cluster string) Capability {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.entries[cluster]
	if !ok {
		return Capability{}
	}
	if c.now().Sub(entry.DeterminedAt) > c.ttl {
		return Capability{}
	}
	return entry
}

// Set stores a capability record for a spoke.
func (c *CapabilityCache) Set(cluster string, entry Capability) {
	if entry.DeterminedAt.IsZero() {
		entry.DeterminedAt = c.now()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[cluster] = entry
}

// RecordProbe records the outcome of a real constrained impersonation attempt.
// This is the primary detection mechanism: it observes what the spoke actually
// did rather than inferring from a version string.
func (c *CapabilityCache) RecordProbe(cluster string, mode Mode, worked bool, serverVersion string) Capability {
	entry := Capability{
		Mode:          mode,
		ServerVersion: serverVersion,
		DeterminedAt:  c.now(),
	}
	if worked {
		entry.Support = SupportYes
		entry.DetectedVia = "probe-success"
	} else {
		entry.Support = SupportNo
		entry.DetectedVia = "probe-denied"
	}
	c.Set(cluster, entry)
	return entry
}

// RecordConfigured stores an operator-asserted capability, bypassing detection.
func (c *CapabilityCache) RecordConfigured(cluster string, support Support, mode Mode) Capability {
	entry := Capability{
		Support:      support,
		Mode:         mode,
		DetectedVia:  "configured",
		DeterminedAt: c.now(),
	}
	c.Set(cluster, entry)
	return entry
}

// Forget drops a spoke's record, e.g. when its ClusterConfig changes.
func (c *CapabilityCache) Forget(cluster string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, cluster)
}

// Len reports the number of live (non-expired) entries.
func (c *CapabilityCache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	n := 0
	for _, e := range c.entries {
		if c.now().Sub(e.DeterminedAt) <= c.ttl {
			n++
		}
	}
	return n
}

// firstGateVersionMinor is the Kubernetes minor release in which the
// ConstrainedImpersonation gate first exists (1.35, alpha, off by default).
const firstGateVersionMinor = 35

// defaultOnVersionMinor is the minor release from which the gate is on by
// default (1.36, beta).
const defaultOnVersionMinor = 36

// VersionHint is the ONLY place breakglass compares Kubernetes versions for this
// feature. It is one of the two signals capability detection combines, and it can
// only ever RULE OUT support, never establish it.
//
// The asymmetry is deliberate and is what makes it safe to consult a version at all:
//
//   - SupportNo is authoritative. Constrained impersonation cannot exist before
//     1.35, so a spoke below that is settled without any probe.
//   - SupportYes and SupportUnknown are NOT conclusions. A 1.36+ cluster can have
//     the gate explicitly disabled, a 1.35 cluster can have it explicitly enabled,
//     and in either case the constrained RBAC may not be applied. None of that is
//     visible in the version string, so a probe must confirm before support is
//     claimed.
//
// Unparseable or empty input yields SupportNo — assume not supported — so that a
// spoke whose version cannot be read keeps the legacy behaviour it has today.
//
// Callers must never treat a non-SupportNo result as permission to report a spoke
// supported; see breakglass.detectProbeCapability for the required second signal.
func VersionHint(major, minor string) Support {
	majorNum, ok := parseVersionComponent(major)
	if !ok || majorNum != 1 {
		// Major 0 or unparseable: assume unsupported. A hypothetical major 2 is
		// also treated as unsupported rather than guessed at.
		return SupportNo
	}

	minorNum, ok := parseVersionComponent(minor)
	if !ok {
		return SupportNo
	}

	switch {
	case minorNum >= defaultOnVersionMinor:
		// Gate on by default. Still only a hint: it can be disabled.
		return SupportYes
	case minorNum >= firstGateVersionMinor:
		// Gate exists but is off by default, so it must be opted into. Unknown
		// until probed.
		return SupportUnknown
	default:
		// Feature absent entirely.
		return SupportNo
	}
}

// parseVersionComponent parses a Kubernetes version component, tolerating the
// non-numeric suffixes real clusters report ("36+", "31.2-eks-1234").
func parseVersionComponent(s string) (int, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}
	end := 0
	for end < len(s) && s[end] >= '0' && s[end] <= '9' {
		end++
	}
	if end == 0 {
		return 0, false
	}
	n, err := strconv.Atoi(s[:end])
	if err != nil {
		return 0, false
	}
	return n, true
}

// IsConstrainedImpersonationDenial reports whether an API error indicates that
// constrained impersonation was refused, as opposed to some unrelated failure.
//
// The distinction matters for backwards compatibility. A pre-1.35 spoke does not
// reject the constrained verbs with a special error — it simply never consults
// them, and the request is denied as an ordinary impersonation forbidden. So this
// deliberately matches the general impersonation-forbidden shape rather than
// hunting for feature-specific wording that older releases never emit.
//
// A nil error returns false, and so does any error that is not an impersonation
// refusal: a network failure or an unrelated 500 must NOT be recorded as
// "constrained impersonation unsupported", because that would pin a spoke to
// legacy mode on the strength of a transient blip.
func IsConstrainedImpersonationDenial(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	if !strings.Contains(msg, "impersonat") {
		return false
	}
	return strings.Contains(msg, "forbidden") ||
		strings.Contains(msg, "cannot impersonate") ||
		strings.Contains(msg, "not allowed")
}
