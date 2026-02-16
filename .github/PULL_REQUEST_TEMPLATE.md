<!--
SPDX-FileCopyrightText: 2025 Deutsche Telekom AG
SPDX-License-Identifier: Apache-2.0
-->

## Description

<!-- Brief description of the changes in this PR -->

## Type of Change

- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update
- [ ] Configuration / CI change
- [ ] Refactoring (no functional changes)

## Related Issues

<!-- Link related issues: "Fixes #123" or "Relates to #123" -->

## Checklist

- [ ] My code follows the project's code style
- [ ] I have performed a self-review of my code
- [ ] I have added tests that prove my fix is effective or my feature works
- [ ] New and existing unit tests pass locally (`make test`)
- [ ] Linting passes (`make lint`)
- [ ] I have made corresponding changes to the documentation
- [ ] `CHANGELOG.md` updated under `[Unreleased]` for user-facing changes
- [ ] My changes generate no new warnings
- [ ] REUSE SPDX license header compliance check passes (`reuse lint`)

### If CRD / API types changed

- [ ] Ran `make generate && make manifests` and committed generated files

### If Helm chart affected

- [ ] Updated `charts/escalation-config/` templates and values
- [ ] Ran `helm lint charts/escalation-config` and `helm template test charts/escalation-config`

### If Frontend changed

- [ ] TypeScript type-check passes (`cd frontend && npm run typecheck`)
- [ ] Frontend tests pass (`cd frontend && npm test`)

## Component Affected

- [ ] Backend (Go)
- [ ] Frontend (Vue 3 / TypeScript)
- [ ] API / CRDs
- [ ] Helm chart
- [ ] CI / Workflows
- [ ] E2E tests
- [ ] Documentation only

## Testing

<!-- Describe how you tested your changes -->

### Test environment

- Kubernetes version:
- Test type: (unit / e2e / manual)

## Screenshots (if applicable)

<!-- Add screenshots for UI changes -->

## Additional Notes

<!-- Any additional context about the PR -->
