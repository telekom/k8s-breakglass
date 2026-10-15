// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"context"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"k8s.io/apiserver/pkg/authentication/user"
)

// TargetIdentityResolverKey identifies the request-local resolver installed by authentication.
const TargetIdentityResolverKey = "oidc_target_identity_resolver"

// TargetIdentity carries the upstream mapping result.
type TargetIdentity struct {
	User user.Info
}

// TargetIdentityResolver verifies the request token under the effective target
// policy. The token is held by the authentication closure, never exposed in a response.
type TargetIdentityResolver func(context.Context, *breakglassv1alpha1.ClusterConfig, breakglassv1alpha1.UserIdentifierClaimType) (TargetIdentity, error)
