// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"k8s.io/apimachinery/pkg/util/validation"
)

// Placeholder label values substituted for a cluster name that must not be used
// verbatim as a Prometheus label.
//
// Prometheus creates one time series per distinct label-value combination and
// never reclaims them, so a label fed from unvalidated remote input lets a caller
// grow the process heap without bound. Format validation alone does NOT bound
// cardinality: a caller can vary syntactically-valid names indefinitely.
// Cardinality is only bounded by refusing to emit any name that has not been
// resolved against a real ClusterConfig — the set of registered clusters is the
// only genuinely bounded source of cluster label values.
//
// The three placeholders keep that bound at three series while still
// distinguishing the operationally interesting cases on a dashboard.
const (
	// LabelValueUnknown is substituted for an empty cluster name: the caller sent
	// no cluster at all.
	LabelValueUnknown = "_unknown"

	// LabelValueInvalid is substituted for a cluster name that is not a valid
	// Kubernetes object name, so it could not name a real cluster. A rising
	// _invalid series indicates malformed traffic.
	LabelValueInvalid = "_invalid"

	// LabelValueUnresolved is substituted for a well-formed cluster name that has
	// not (yet) been resolved against a registered ClusterConfig. This is the
	// value that actually bounds cardinality: without it, any attacker-chosen
	// valid DNS-1123 name would become its own series.
	LabelValueUnresolved = "_unresolved"
)

// SafeClusterLabel returns a bounded Prometheus label value for an UNRESOLVED
// cluster name.
//
// Use it for every metric label derived from request input (an HTTP route
// parameter, a header, a request body field) that has not yet been matched to a
// registered ClusterConfig. It never returns the caller-supplied name: the result
// is always one of the three placeholders, so a remote caller cannot create more
// than three series regardless of what it sends.
//
// Once the cluster has been resolved, switch the label to the resolved name via
// [ResolvedClusterLabel]; that value is bounded by the number of registered
// clusters.
func SafeClusterLabel(name string) string {
	if name == "" {
		return LabelValueUnknown
	}
	if len(validation.IsDNS1123Subdomain(name)) > 0 {
		return LabelValueInvalid
	}
	return LabelValueUnresolved
}

// ResolvedClusterLabel returns the label value to use once name has been
// confirmed to identify a registered cluster (i.e. a ClusterConfig lookup
// succeeded). The name is returned verbatim, because the set of registered
// clusters is bounded and operator-controlled rather than caller-controlled.
//
// It still guards against a malformed or empty name so that a bad label value can
// never reach Prometheus, no matter how the cluster was resolved.
func ResolvedClusterLabel(name string) string {
	if name == "" {
		return LabelValueUnknown
	}
	if len(validation.IsDNS1123Subdomain(name)) > 0 {
		return LabelValueInvalid
	}
	return name
}
