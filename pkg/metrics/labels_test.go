// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"fmt"
	"strings"
	"testing"
)

// TestSafeClusterLabel_BoundedToThreeValues is the cardinality contract for
// unresolved cluster labels: SafeClusterLabel must NEVER return the
// caller-supplied name, so the number of distinct label values it can ever
// produce is exactly three, no matter what a remote caller sends.
//
// Format validation alone would not bound anything — arbitrarily many
// syntactically-valid DNS-1123 names exist — which is why well-formed names
// collapse onto LabelValueUnresolved rather than being passed through.
func TestSafeClusterLabel_BoundedToThreeValues(t *testing.T) {
	inputs := []string{
		// Empty: no cluster supplied.
		"",
		// Malformed: cannot name a Kubernetes object.
		"../../etc/passwd",
		"Cluster With Spaces",
		"UPPERCASE",
		"-leading-dash",
		"under_score",
		strings.Repeat("x", 254),
		"\n",
		`cluster{label="injected"}`,
		// Well-formed but unresolved. Format checking alone would let each of
		// these become its own series.
		"a",
		"prod-cluster-01",
		"totally.valid.subdomain",
	}
	for i := 0; i < 1000; i++ {
		inputs = append(inputs, fmt.Sprintf("attacker-%d", i))
	}

	distinct := map[string]struct{}{}
	for _, in := range inputs {
		got := SafeClusterLabel(in)
		if in != "" && got == in {
			t.Fatalf("SafeClusterLabel(%q) returned the caller-supplied name verbatim", in)
		}
		distinct[got] = struct{}{}
	}

	want := map[string]struct{}{
		LabelValueUnknown:    {},
		LabelValueInvalid:    {},
		LabelValueUnresolved: {},
	}
	if len(distinct) != len(want) {
		t.Fatalf("SafeClusterLabel produced %d distinct label values %v, want exactly %d %v",
			len(distinct), distinct, len(want), want)
	}
	for v := range distinct {
		if _, ok := want[v]; !ok {
			t.Fatalf("SafeClusterLabel produced unexpected label value %q; only the three placeholders are permitted", v)
		}
	}
}

func TestSafeClusterLabel_Classification(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"empty is unknown", "", LabelValueUnknown},
		{"spaces are invalid", "Bad Name", LabelValueInvalid},
		{"uppercase is invalid", "UPPER", LabelValueInvalid},
		{"path traversal is invalid", "../../etc/passwd", LabelValueInvalid},
		{"too long is invalid", strings.Repeat("x", 254), LabelValueInvalid},
		{"well-formed is unresolved", "prod-cluster-01", LabelValueUnresolved},
		{"subdomain is unresolved", "a.b.c", LabelValueUnresolved},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SafeClusterLabel(tt.input); got != tt.want {
				t.Errorf("SafeClusterLabel(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// TestResolvedClusterLabel asserts the other half of the bound: once a name has
// been matched to a registered ClusterConfig it is emitted verbatim, because the
// set of registered clusters is operator-controlled and bounded. Malformed and
// empty names still collapse, so a bad value can never reach Prometheus.
func TestResolvedClusterLabel(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"registered name is verbatim", "prod-cluster-01", "prod-cluster-01"},
		{"registered subdomain is verbatim", "a.b.c", "a.b.c"},
		{"empty still collapses", "", LabelValueUnknown},
		{"malformed still collapses", "Bad Name", LabelValueInvalid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ResolvedClusterLabel(tt.input); got != tt.want {
				t.Errorf("ResolvedClusterLabel(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
