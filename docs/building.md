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
- Kafka for audit testing
- NodePort services for local access

## Testing

### Unit Tests

Run all unit tests with coverage:

```bash
make test
```

### Linting

Run golangci-lint:

```bash
make lint
```

### End-to-End (E2E) Tests

E2E tests run against a real Kind cluster with all dependencies (Keycloak, Kafka, MailHog).

#### Quick Start

```bash
# Build the dev image
make docker-build-dev

# Set up E2E environment (creates Kind cluster with all deps)
make e2e

# Or manually:
./e2e/kind-setup-single.sh
```

#### Running E2E Tests

```bash
# Run all E2E tests
cd e2e && go test -v ./...

# Run specific test file
go test -v ./e2e/api/session_state_test.go

# Run specific test
go test -v ./e2e/api/... -run TestSessionApprovalWorkflow
```

#### E2E Environment

The E2E environment includes:

| Component | Purpose | Port |
|-----------|---------|------|
| Breakglass Controller | Main service | 30081 |
| Keycloak | OIDC identity provider | 30083 |
| MailHog | Email testing | 30084 |
| Kafka | Audit event streaming | Internal |

#### E2E Test Structure

```text
e2e/
├── api/                    # API integration tests
│   ├── session_state_test.go
│   ├── approval_workflow_test.go
│   ├── deny_policy_test.go
│   └── ...
├── helpers/                # Test utilities
│   ├── api.go              # API client helpers
│   ├── auth.go             # Token management
│   ├── cleanup.go          # Resource cleanup
│   ├── users.go            # Test user definitions
│   └── wait.go             # Polling utilities
├── fixtures/               # Test data
├── kind-setup-single.sh    # Cluster setup script
└── e2e-todo.md             # Test coverage checklist
```

#### Test Users

E2E tests use pre-configured Keycloak users:

| User | Role | Password |
|------|------|----------|
| `requester@example.com` | Session requester | `password` |
| `approver@example.com` | Session approver | `password` |
| `admin@example.com` | Admin user | `password` |

#### Cleanup

```bash
# Teardown E2E environment
./e2e/teardown.sh

# Or delete Kind cluster directly
kind delete cluster --name breakglass-e2e
```

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
