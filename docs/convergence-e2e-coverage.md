<!-- SPDX-FileCopyrightText: 2026 Deutsche Telekom AG -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Convergence E2E coverage

This is a bounded readiness regression, not proof that every downstream operation
is covered. Release decisions must keep these claims separate.

The fixture was derived from the internal cluster inventory at
`a0be2c81ce8ad170417e5cb5640419dd9f304cb3`, the bundle inventory at
`19a0e0401defb8165ce15148a2383315e781b9a4`, and the Breakglass Function
`0.3.0-rc.27`. The inventory also references Function versions rc.20, rc.23,
and rc.26; those versions are not all independently executed by this fixture.

| Contract | Evidence / remaining gate |
| --- | --- |
| Empty target set installs successfully | Real Flux HelmRelease with eight bindings |
| dev/ref/tst versus prd/unknown/unlabelled target partition | Live ClusterConfig label transitions and resolved target assertions |
| Capability opt-out clears stale targets | Live label update and empty-list assertions |
| Empty binding grants no session access | Authenticated API rejection |
| Nonproduction requester self-approval | Authenticated approval after PendingApproval |
| Other stages block requester self-approval | Authenticated API rejection |
| Production hub removes stage split | HelmRelease upgrade and target assertions |
| Disabled providers do not block installation | Disabled IdentityProvider, MailProvider and AuditConfig fixtures |
| Binding schema validity | Go validator, including malformed-binding negative regression |
| Internal group and issuer mappings | A live OIDC token exercises exact group matching; test identities replace internal providers and are not equivalent |
| Node diagnostics | Authenticated requester creates the node pod, verifies the selected node, and executes read-only diagnostics with an OIDC token |
| etcd snapshot/defrag execution | Not proven: templates are installed but their tools are not executed |
| Internal utility images and registries | Not proven: private images are replaced |
| Actual Function installation and Bundle reconciliation | Not proven: the test starts from rendered resources in a Helm chart |
| Historical Function versions and all cluster overrides | Not exhaustively executed |

The current suite must not be described as 100% coverage of internal usage.
Closing the remaining gates requires explicit runtime cases for each operational
workflow and a refreshed inventory of Function inputs, bundle pins, identity
mappings, and cluster overrides. Generic upstream tests alone do not establish
that those downstream combinations work.
