// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

// This file exposes the constrained-impersonation constants that this package
// duplicates from pkg/impersonation, so that the two copies can be asserted equal.
//
// The duplication is deliberate: api/v1alpha1 must not depend on pkg/. But an
// unguarded copy of a security constant is a silent-divergence hazard — if the
// system:masters string or a username prefix drifted, admission-time validation and
// runtime enforcement would disagree, and a configuration accepted at admission
// would be treated as a different (unconstrained) mode at runtime.
//
// pkg/impersonation/apiconsistency_test.go asserts these against the canonical
// definitions, making any divergence a test failure rather than a production
// surprise. These identifiers exist only to make that assertion possible.

const (
	// ExportedImpGroupSystemMasters mirrors impersonation.GroupSystemMasters.
	ExportedImpGroupSystemMasters = impGroupSystemMasters

	// ExportedImpUsernameNodePrefix mirrors impersonation.UsernameNodePrefix.
	ExportedImpUsernameNodePrefix = impUsernameNodePrefix

	// ExportedImpUsernameSAPrefix mirrors impersonation.UsernameServiceAccountPrefix.
	ExportedImpUsernameSAPrefix = impUsernameSAPrefix

	// ExportedImpManyChecksInLoop mirrors impersonation.ManyAuthorizationChecksInLoop.
	ExportedImpManyChecksInLoop = impManyChecksInLoop
)

// ExportedIsImpersonationIdentityResource reports whether r is an identity resource
// kind this package's validation accepts.
func ExportedIsImpersonationIdentityResource(r string) bool {
	return validImpersonationIdentityResources[r]
}

// ExportedImpersonationIdentityResources lists the identity resource kinds this
// package's validation accepts.
func ExportedImpersonationIdentityResources() []string {
	out := make([]string, 0, len(validImpersonationIdentityResources))
	for r := range validImpersonationIdentityResources {
		out = append(out, r)
	}
	return out
}
