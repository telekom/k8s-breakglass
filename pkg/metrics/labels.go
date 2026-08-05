// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"k8s.io/apimachinery/pkg/util/validation"
)

// LabelValueInvalid is the placeholder substituted for any label value that is
// not a valid Kubernetes object name.
//
// Prometheus creates one time series per distinct label-value combination and
// never reclaims them, so a label fed from unvalidated remote input lets a caller
// grow the process heap without bound. Collapsing every rejected value onto a
// single series keeps that cardinality at one while still making the condition
// visible on the dashboard.
const LabelValueInvalid = "_invalid"

// LabelValueUnknown is the placeholder substituted for an empty label value, so
// that "the caller sent nothing" is distinguishable from "the caller sent
// something unusable".
const LabelValueUnknown = "_unknown"

// SafeClusterLabel returns name if it is a valid Kubernetes object name suitable
// for use as a Prometheus label value, and a fixed placeholder otherwise.
//
// Use it for every metric label derived from request input (an HTTP route
// parameter, a header, a request body field) BEFORE the value has been resolved
// against a real ClusterConfig. Cluster names in this project are Kubernetes
// object names, so RFC 1123 subdomain validation is exactly the right bound and
// the label value is unchanged for every legitimate cluster.
func SafeClusterLabel(name string) string {
	if name == "" {
		return LabelValueUnknown
	}
	if len(validation.IsDNS1123Subdomain(name)) > 0 {
		return LabelValueInvalid
	}
	return name
}
