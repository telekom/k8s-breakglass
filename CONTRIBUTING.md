# Contributing to k8s-breakglass

Thanks for taking the time to contribute. This guide aligns with OpenSSF Best Practices and documents the requirements for acceptable contributions.

## Code of Conduct

This project follows the code of conduct in [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). By participating, you agree to uphold these standards.

## Contribution Requirements

To keep the project secure, reliable, and maintainable, all contributions must meet these requirements:

### 1. Coding Standards
- **Go**: Use standard Go formatting (gofmt/goimports) and follow Go idioms
- **Frontend**: Follow Vue 3 + TypeScript conventions and linting rules
- Use standard library constants (e.g., `http.MethodGet` instead of string literals)
- See [.golangci.yml](.golangci.yml) for Go linting rules

### 2. Testing Policy (Required)
All new features and significant changes **must include automated tests**:
- Backend: Add `*_test.go` files colocated with source code
- Frontend: Add tests in `frontend/tests/`
- Cover success cases, error cases, and edge cases
- Aim for >70% code coverage for new code
- Run `make test` (Go) and `cd frontend && npm test` (frontend) before opening PRs

If testing is impractical, document why in the PR description.

### 3. Documentation Updates (Required)
Documentation must be updated for every user-facing change:
- **API changes**: Update [docs/api-reference.md](docs/api-reference.md)
- **CRD changes**: Update relevant resource docs in `docs/`
- **Configuration**: Update [docs/configuration-reference.md](docs/configuration-reference.md) and [docs/cli-flags-reference.md](docs/cli-flags-reference.md)
- **Helm charts**: Update chart README and inline values comments
- **Changelog**: Add entry under `[Unreleased]` in [CHANGELOG.md](CHANGELOG.md)

### 4. Quality Standards
- Maintain or improve test coverage (monitored via Codecov)
- Run linters locally: `make lint` (Go) and `cd frontend && npm run lint` (frontend)
- Fix all linter errors before submitting

### 5. Security and Privacy
- Never commit secrets, credentials, or PII
- Report security issues privately per [SECURITY.md](SECURITY.md)
- Consider security implications in PR descriptions

### 6. License
All contributions are accepted under the Apache-2.0 license. See [LICENCE](LICENCE).

## Workflow

### 1. Find or Create an Issue
- Check existing issues to avoid duplicates
- For features, describe the use case, alternatives, and security impact
- Link your PR to the issue when ready

### 2. Develop Your Changes
```bash
# Create a feature branch
git checkout -b feature/your-feature-name

# Make changes following the architecture in README.md
# For CRD changes, regenerate code:
make generate manifests
```

### 3. Test Locally
```bash
# Backend tests and linting
make test
make lint

# Frontend tests and linting
cd frontend
npm test
npm run lint
npm run typecheck
```

### 4. Update Documentation
- Update relevant docs in `docs/`
- Add changelog entry in [CHANGELOG.md](CHANGELOG.md)
- Update Helm chart docs if applicable

### 5. Open a Pull Request
- Provide a clear description and link related issues
- Note test coverage and any limitations
- Describe security implications if relevant

## Code Review Requirements

All changes require pull request review before merge:

- ✅ At least one approving review
- ✅ All CI checks passing (tests, linting, security scans)
- ✅ Up-to-date with base branch
- ✅ No direct pushes to main branch
- ✅ Stale approvals dismissed on new commits

Any exceptions must be documented in the PR with justification.

## Release Process

For release signing, provenance, and supply-chain requirements, see [docs/release-process.md](docs/release-process.md).

## AI-Assisted Development

This project supports AI coding assistants (GitHub Copilot, etc.):

- **Project conventions**: See [`.github/copilot-instructions.md`](.github/copilot-instructions.md) for comprehensive coding guidelines that AI assistants load automatically.
- **Agent instructions**: See [`AGENTS.md`](AGENTS.md) for a concise reference of critical rules.
- **Context filtering**: [`.copilotignore`](.copilotignore) excludes auto-generated files and build artifacts from AI context.
- **Prompt templates**: Reusable prompts in [`.github/prompts/`](.github/prompts/) for common tasks.

When using AI to generate code, always verify:
1. Auto-generated files (CRDs, DeepCopy) are not directly edited
2. SPDX headers are present on new files
3. Tests are included and pass (`make test`)
4. Frontend tests pass (`cd frontend && npm test`)
5. `make lint` passes without errors
6. `CHANGELOG.md` is updated for user-facing changes

## Questions or Help

Open an issue or discussion with context. See [SECURITY.md](SECURITY.md) for reporting security vulnerabilities.
