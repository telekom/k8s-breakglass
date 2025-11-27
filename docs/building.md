# Building Breakglass

Instructions for building the breakglass application from source.

## Docker Image Build

### OSS Flavour (Recommended for Non-Telekom)

```bash
docker build -t breakglass:oss .
```

This builds the standard OSS-neutral UI suitable for all organizations.

### ⚠️ Telekom Branded Flavour

```bash
docker build --build-arg UI_FLAVOUR=telekom -t breakglass:telekom .
```

## IMPORTANT: TELEKOM BRANDED UI DISCLAIMER

The Telekom branded UI flavour is **PROPRIETARY TO DEUTSCHE TELEKOM** and is intended exclusively for use within Deutsche Telekom entities.

**Terms of Use:**

- The Telekom UI flavour contains proprietary Deutsche Telekom branding, designs, and customizations
- Unauthorized use outside of Deutsche Telekom is strictly prohibited
- Non-compliance with this restriction violates Deutsche Telekom's intellectual property rights
- Organizations not affiliated with Deutsche Telekom must use the OSS flavour

**Which version should I use?**

- **Deutsche Telekom employees and authorized entities:** May use the Telekom flavour
- **All other organizations:** MUST use the OSS flavour

The OSS flavour is fully functional, feature-complete, and appropriate for all use cases.

## Go Binary Build

Build the backend binary:

```bash
make build
```

Output: `./bin/breakglass`

## Frontend Build

Build the frontend separately:

```bash
cd frontend
npm install
npm run build
```

Output: `./frontend/dist/`

### Rapid local UI preview (mock backend)

Use the bundled mock API to edit the UI with hot module reloading—no controller container or cluster
is required. A single command spins up both the mock backend (port 8080) and the Vite dev server:

```bash
cd frontend
npm run dev:mock
```

What you get:

- Express-based mock API with sample breakglass sessions, escalations, and multi-IDP data
- Requests to `/api/*` are automatically proxied to the mock server via Vite
- Instant WYSIWYG feedback when editing Vue components or CSS
- Ability to approve/reject mock requests without configuring Keycloak/OIDC
- Seeded permutations covering every session state (pending, approved, rejected, withdrawn, expired,
  timeout, approval-timeout, dropped, waiting-for-schedule) plus single/multi-group escalations,
  Azure/Keycloak/no-IDP combinations, and huge approver stacks for chip stress tests

Override the mock API port by setting `MOCK_API_PORT` before running the script if 8080 is busy.

Need an even bigger dataset for scroll performance measurements? Call the REST endpoint with
`mockScale`, `scaleCount`, or `total`, e.g. `/api/breakglassSessions?mockScale=300`. The mock server
will append enough synthetic entries to reach that total without touching the seed file.

## Building for Production

1. Use OSS flavour (unless you are Deutsche Telekom)

```bash
docker build -t breakglass:prod -f Dockerfile .
```

2. Configure for production:

```bash
# Use external OIDC provider
# Enable TLS
# Configure proper email service
# Set resource limits
```

3. Push to your registry:

```bash
docker tag breakglass:prod myregistry.example.com/breakglass:v1.0.0
docker push myregistry.example.com/breakglass:v1.0.0
```

## Development Build

Build with dev configuration:

```bash
make deploy_dev
```

This includes:

- Keycloak for OIDC testing
- Mailhog for email testing
- NodePort services for local access

## Build Flags

Available build arguments for `docker build`:

- `UI_FLAVOUR` - `oss` (default) or `telekom`

Example:

```bash
docker build --build-arg UI_FLAVOUR=telekom -t breakglass:telekom .
```

## Dockerfile Details

The Dockerfile:

1. Builds Go backend
2. Builds frontend (with selected UI flavour)
3. Packages into final image
4. Sets up health checks

### TLS certificates inside the container

The final stage uses `gcr.io/distroless/static:nonroot`, which expects trusted certificates in `/etc/ssl/certs/`. We explicitly copy `/etc/ssl/certs` from the builder stage into the distroless image to ensure the runtime trust store matches the Go toolchain that compiled the binary. This avoids TLS failures when the OIDC proxy dials external authorities. If you change base images, confirm that CA bundles remain at `/etc/ssl/certs/ca-certificates.crt` or update the copy instructions accordingly.

## Cross-Platform Builds

Build for multiple architectures:

```bash
docker buildx build --platform linux/amd64,linux/arm64 \
  -t breakglass:latest .
```

## Compliance

When building for any environment:

- Ensure you comply with licensing terms (REUSE standard)
- Non-Telekom organizations: use OSS flavour only
- Keep dependencies up to date
- Scan for vulnerabilities

## License Compliance

This project uses REUSE standard licensing. Each file contains license information.

View licenses:

```bash
ls ./LICENSES/
cat REUSE.toml
```

## Size Optimization

To reduce image size:

```bash
# Use alpine base (already minimal)
# Disable debug symbols in production
# Use multi-stage builds (automatic in Dockerfile)
```

Current image size: ~150MB (approximate, varies with flavour)
