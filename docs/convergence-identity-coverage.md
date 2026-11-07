<!-- SPDX-FileCopyrightText: 2026 Deutsche Telekom AG -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Convergence identity coverage

`TestConvergenceIdentityGroupMapping` reads the group claim from a live OIDC
test token, then checks template discovery through the authenticated API. A
binding for the exact token group is visible; the compatibility `oidc:`-prefixed
form is not. The test uses a generic test identity and does not copy production
group names, user identifiers, issuer URLs, or credentials into its fixture.

The case file at `e2e/fixtures/convergence-identity/cases.yaml` pins the claim
name and the compatibility prefix. The expected group comes from the configured test identity and must occur in
the issued token, so this proves the active E2E identity provider's group mapping
and the application's exact-match authorization behavior together.

This case does not prove all issuer/provider combinations, internal IdP object
configuration, or production API-server flags. Multi-provider login and
cluster-specific authentication remain separate E2E/runtime gates.
