// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

// Package impersonation models Kubernetes constrained impersonation (KEP-5284).
//
// The kube-apiserver's constrained impersonation filter authorizes impersonation
// with two families of verbs that do not exist as exported constants anywhere in
// k8s.io/*:
//
//	impersonate:<mode>              — the "identity" check
//	impersonate-on:<mode>:<verb>    — the "action" check
//
// Both verbs are built inline in unexported apiserver code
// (k8s.io/apiserver/pkg/endpoints/filters/impersonation/mode.go), so a platform
// authorizer that needs to recognise them must define its own constants. That is
// what this package is for.
//
// The security consequence that motivates this package: a webhook authorizer
// which allows verbs it does not recognise silently grants constrained
// impersonation on any cluster where the ConstrainedImpersonation feature gate is
// enabled (beta / on by default since Kubernetes 1.36). Breakglass's
// authorization webhook therefore has to classify these verbs explicitly and be
// able to deny them.
package impersonation
