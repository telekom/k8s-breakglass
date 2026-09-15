<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
SPDX-License-Identifier: Apache-2.0
-->

# Helper invariants

Namespace selectors use exact membership: `*` is literal, missing labels differ
from empty values, and deny rules take precedence. `GlobMatch` keeps its special
universal wildcard and exact-literal behavior. Approval-reason enrichment keeps
backend/stored reasons ahead of legacy lookups without mutating responses.

Unused frontend wrappers were removed; backend token validation and supported
session actions are unchanged. Run `go test ./pkg/utils` and
`cd frontend && npm test` for the affected helpers.
