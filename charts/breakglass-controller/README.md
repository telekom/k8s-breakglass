# breakglass-controller Helm chart

This chart packages the breakglass controller and related resources.

## Usage

Install (example):

```bash
helm install breakglass-controller charts/breakglass-controller -f charts/breakglass-controller/test-values/values-minimal.yaml
```

## Ingress configuration

The chart exposes ingress templating through the following values in `values.yaml`:

- `ingress.enabled` (bool) — set to `true` to create an Ingress resource.
- `ingress.host` (string) — FQDN for the Ingress rule.
- `ingress.annotations` (map) — map of annotations to add to the Ingress metadata (for ingress class, cert-manager, etc.).
- `ingress.tls.enabled` (bool) — if true a `spec.tls` entry is added.
- `ingress.tls.secretName` (string) — TLS secret name for the host(s).
- `ingress.tls.hosts` (list) — hosts array used in the `spec.tls` entry.

Example TLS values are included in `test-values/values-tls.yaml`.

## CI versioning rules

This repository includes a GitHub Actions workflow (`.github/workflows/helm-ci.yaml`) that runs on PRs, pushes and releases. The workflow sets the chart `version` dynamically for the run:

- Pull requests: `pr-<pr-number>-<commit-sha-short>` (e.g. `pr-12-ab12cd34`).
- Releases: uses the release tag name (e.g. `v1.2.3`).
- Other pushes: short commit SHA is used.

The workflow will:

- Run `helm lint --strict` on all charts.
- Render templates via `helm template` using the included test-values sets.
- Package charts with the calculated version (no push to any registry is performed by default).

If you want the packaged chart to be published, extend the workflow to push to your chart repository or GitHub Releases (using a secure token).
