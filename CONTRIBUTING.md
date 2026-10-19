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
- For SSA/status patch changes, also run `make test-ssa-envtest`. This installs
  the repository CRDs into envtest and checks actual apply counts, ownership,
  resource-version conflicts, live-read retries, status isolation and deletion.
  CI runs this target with real API-server assets; ordinary unit-test runs skip
  these tests when `KUBEBUILDER_ASSETS` is unset.

If testing is impractical, document why in the PR description.

### 3. Documentation Updates (Required)
Documentation must be updated for every user-facing change:
- **API changes**: Update [docs/api-reference.md](docs/api-reference.md)
- **CRD changes**: Update relevant resource docs in `docs/`
- **Configuration**: Update [docs/configuration-reference.md](docs/configuration-reference.md) and [docs/cli-flags-reference.md](docs/cli-flags-reference.md)
- **Helm charts**: Update chart README and inline values comments
- **Changelog**: Do not edit [CHANGELOG.md](CHANGELOG.md). The PR title is the
  changelog line; add a [`changes/`](changes/README.md) fragment for upgrade
  notes, breaking or behaviour changes (see [Changelog](#changelog))

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

`make test` and `make test-controller` are check-only targets: they run vet and
tests, but do not regenerate manifests, regenerate code, or format Go files. Run
the mutating targets explicitly when you intend to update generated or formatted
files, for example `make generate manifests fmt` or `make prepare-test`.

### 4. Update Documentation
- Update relevant docs in `docs/`
- Give the PR a Conventional Commit title; add a [`changes/`](changes/README.md)
  fragment if the change needs more than its title in the changelog
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

### Pull request titles

PRs are squash-merged, and the PR title becomes the commit title on `main`.
The changelog line comes from that title, so write it for the reader of the
changelog: `<type>(<scope>): <what an operator sees>`, for example
`feat(debug): limit sessions per target cluster on a DebugSessionClusterBinding`.
The type selects the changelog section:

| Type | Section |
|------|---------|
| `feat` | Features |
| `fix` | Fixes |
| `perf` | Performance |
| `docs` | Docs |
| `build`, `ci`, `test` | CI, build and tests |
| `deps`, or any type with a `(deps...)` scope | Dependencies |
| `refactor` | Maintenance |
| `revert` | Reverts |
| `chore`, `style` | not in the changelog |

Use `chore` or `style` only for changes that no user sees. Add `!` after the
type or scope (`feat(api)!: ...`) for a breaking change: the line goes to
"Breaking changes". GitHub titles a revert PR `Revert "..."`, which the check
rejects: retitle it `revert: <title of the reverted PR>`. A commit that is
reverted in the same release is left out together with its revert.

### Changelog

[CHANGELOG.md](CHANGELOG.md) is generated by `hack/changelog.py` with
[git-cliff](https://git-cliff.org/) (`cliff.toml`). Do not edit it in a PR; the
`Changelog Preview` check fails a PR whose title is not a Conventional Commit,
and a PR that changes it, unless the PR is the release PR or a `chore`, `ci` or
`build` change of the generator (`cliff.toml`, `hack/changelog.py`). The section of a release is:

1. the text in `## [Unreleased]` of `CHANGELOG.md`, normally empty;
2. one line per commit since the previous tag, grouped by type, with a link
   to the PR. A line is left out when the Unreleased text already names its PR;
3. the fragments in `changes/*.md`, each in the section that its front matter
   names (see [changes/README.md](changes/README.md)). Use a fragment for
   upgrade notes (new CRD fields, chart values, required order of upgrade),
   breaking changes and behaviour changes.

`make changelog` prints the next release section. It needs git-cliff
(`pipx install git-cliff==2.14.2`, or `GIT_CLIFF="uvx git-cliff@2.14.2" make
changelog`). The `Changelog Preview` CI job runs it on every PR and on `main`.

## Release Process

1. Open a release PR titled `chore(release): vX.Y.Z` with
   `make changelog-release RELEASE=X.Y.Z` and the chart version bumps. It
   writes the section as `## [X.Y.Z] - YYYY-MM-DD`, empties `## [Unreleased]`,
   updates the link references and deletes the fragments in `changes/`. Edit
   the section if needed, for example to add highlights.
2. Merge the release PR and tag the merge commit `vX.Y.Z`.
3. `.github/workflows/release.yml` uses the `## [X.Y.Z]` section of
   `CHANGELOG.md` as the GitHub release body. If the tag has no such section,
   it generates the section from the commits since the previous tag.

For release signing, provenance, and supply-chain requirements, see [docs/release-process.md](docs/release-process.md).

## AI-Assisted Development

This project supports AI coding assistants (GitHub Copilot, etc.):

- **Project conventions**: See [`.github/copilot-instructions.md`](.github/copilot-instructions.md) for comprehensive coding guidelines that AI assistants load automatically.
- **Agent instructions**: [`AGENTS.md`](AGENTS.md) provides a concise reference of critical rules.
- **Context filtering**: [`.copilotignore`](.copilotignore) excludes auto-generated files and build artifacts from AI context.
- **Prompt templates**: Reusable prompts in `.github/prompts/` for common tasks (planned).

Key conventions documented in the instructions include:

- **Go patterns**: controller-runtime idioms, SSA field ownership, structured logging
- **Frontend**: Vue 3 + TypeScript conventions, Pinia store patterns
- **Testing**: Go table-driven tests, fuzz tests, `//go:build` tags, frontend test setup
- **Helm charts**: values structure, CRD management, RBAC generation
- **REUSE compliance**: SPDX headers required in all new files

When using AI to generate code, always verify:
1. Auto-generated files (CRDs, DeepCopy) are not directly edited
2. SPDX headers are present on new files
3. Tests are included and pass (`make test`)
4. Frontend tests pass (`cd frontend && npm test`)
5. `make lint` passes without errors
6. `CHANGELOG.md` is not edited; the PR title is a Conventional Commit and a
   `changes/` fragment carries upgrade notes

## Questions or Help

Open an issue or discussion with context. See [SECURITY.md](SECURITY.md) for reporting security vulnerabilities.
