# Security scan reporting

The Trivy filesystem job scans the repository and produces a SARIF report. On pull requests a failed scan emits a GitHub warning annotation and job summary instead of blocking the PR. The warning covers both detected findings and a scanner execution failure; inspect the logs to distinguish them. When generated, the report is retained as the `trivy-filesystem-results` workflow artifact, including on pull requests.

Pushes to main, scheduled runs, and manual runs retain the enforcing scanner exit code and upload SARIF to GitHub code scanning. Scanner severity selection is unchanged. Although the workflow configures HIGH/CRITICAL, the pinned Trivy action defaults to including all severities in SARIF unless `limit-severities-for-sarif` is enabled; that option remains unset. Other security jobs keep their existing policies.

The dependency update includes `golang.org/x/crypto` v0.56.0 for CVE-2026-78662 and CVE-2026-56855, plus `@humanfs/node` 0.16.8 for GHSA-p498-v437-472g. The latter is a transitive frontend development dependency.

Run `go test ./.github/scripts/security_scan_contract_test.go` to exercise PR versus enforcing-event behavior and the actual warning command.

The frontend development lockfile also uses `qs` 6.16.0 or newer to address GHSA-x5fp-wj9c-mxmx and GHSA-4mjr-xmp4-gh2g. Its compatible transitive update keeps the existing Express/body-parser dependency ranges.
