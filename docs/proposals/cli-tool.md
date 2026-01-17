# Breakglass CLI Tool Proposal

## Executive Summary

This proposal outlines a Go-based CLI tool (`bgctl`) that provides a command-line interface for interacting with the Breakglass API. The CLI complements the existing web UI, enabling automation, scripting, and accessibility for users who prefer terminal-based workflows.

## Goals

1. **Feature Parity with UI** - Support all operations available in the web frontend
2. **Multi-Instance Support** - Configure and switch between multiple Breakglass instances
3. **Automation Friendly** - Support scripting with proper exit codes, JSON output, and quiet modes
4. **Accessibility** - Provide terminal-based access for screen readers and keyboard-only users
5. **Developer Experience** - Intuitive command hierarchy with helpful documentation
6. **Library-First Design** - Expose all functionality as importable Go packages for embedding in other CLIs

## Non-Goals

- Real-time WebSocket-based features (e.g., terminal sharing in debug sessions)
- Replace the web UI for complex approval workflows with multi-step forms
- Provide a TUI (text user interface) - commands will be stateless

---

## Installation

### Binary Distribution

Pre-built binaries are available from GitHub Releases for all major platforms.

```bash
# Download the latest release for your platform
# macOS (Intel)
curl -LO https://github.com/telekom/k8s-breakglass/releases/latest/download/bgctl_darwin_amd64.tar.gz

# macOS (Apple Silicon)
curl -LO https://github.com/telekom/k8s-breakglass/releases/latest/download/bgctl_darwin_arm64.tar.gz

# Linux (amd64)
curl -LO https://github.com/telekom/k8s-breakglass/releases/latest/download/bgctl_linux_amd64.tar.gz

# Linux (arm64)
curl -LO https://github.com/telekom/k8s-breakglass/releases/latest/download/bgctl_linux_arm64.tar.gz

# Windows (amd64)
curl -LO https://github.com/telekom/k8s-breakglass/releases/latest/download/bgctl_windows_amd64.zip

# Extract and install (Unix)
tar xzf bgctl_*.tar.gz
sudo mv bgctl /usr/local/bin/

# Or add to user-local bin (no sudo required)
tar xzf bgctl_*.tar.gz
mkdir -p ~/.local/bin
mv bgctl ~/.local/bin/
# Ensure ~/.local/bin is in your PATH
```

### Verification & Initial Setup

Verify the installation and set up your first configuration:

```bash
# 1. Check version
bgctl version
# bgctl v1.0.0 (commit: abc123, built: 2026-01-15T10:00:00Z)

# 2. Verify help system works
bgctl --help
bgctl session --help

# 3. Initialize configuration interactively
bgctl config init
# This will walk you through setting up your first context

# 4. Test connection (requires config setup)
bgctl auth login
bgctl cluster list

# 5. Install shell completion (optional)
bgctl completion bash > /etc/bash_completion.d/bgctl  # or ~/.bash_completion
source ~/.bashrc
```

### Built-in Updater

The CLI includes a self-update mechanism that downloads new versions directly from GitHub Releases:

```bash
# Check for available updates
bgctl update check
# Current version: v1.0.0
# Latest version:  v1.1.0
# Run 'bgctl update' to upgrade

# Update to the latest version
bgctl update
# Downloading bgctl v1.1.0...
# Verifying checksum...
# Updated successfully from v1.0.0 to v1.1.0

# Update to a specific version
bgctl update --version v1.0.5

# Skip confirmation prompt
bgctl update --yes

# Show what would be done without actually updating
bgctl update --dry-run
```

The updater:
- Downloads binaries from `github.com/telekom/k8s-breakglass/releases`
- Verifies SHA256 checksums before replacing the binary
- Does not use GPG signatures in v1 (SHA256 only)
- Preserves file permissions
- Renames current binary to `bgctl.old` before replacing
- Supports manual rollback to previous version
- Can be disabled in enterprise environments via `BGCTL_DISABLE_UPDATE=true`

### Rollback Command

```bash
# Rollback to previous version (bgctl.old)
bgctl update rollback
# Rolling back from v1.2.0 to v1.1.0...
# ✓ Rollback complete

# Rollback to specific version (downloads from GitHub)
bgctl update rollback --version v1.0.5
# Downloading bgctl v1.0.5...
# ✓ Rollback to v1.0.5 complete

# Show rollback candidate
bgctl update rollback --dry-run
# Would rollback to: v1.1.0 (bgctl.old)
```

---

## Configuration

### Config File Location

```
~/.config/bgctl/config.yaml          # Linux/macOS (XDG)
~/.bgctl/config.yaml                 # Alternative
$BGCTL_CONFIG                        # Environment override
```

### Config File Structure

The configuration follows a similar pattern to kubeconfig, with support for shared OIDC providers
across multiple Breakglass instances (useful when the same Keycloak serves multiple environments).

```yaml
# ~/.config/bgctl/config.yaml
version: v1

# Default context to use (like kubectl current-context)
current-context: production

# ============================================================================
# OIDC Providers - Define reusable authentication providers
# ============================================================================
# Multiple contexts can reference the same provider, enabling single sign-on
# across environments that share a Keycloak instance.
oidc-providers:
  # Corporate Keycloak for production and staging
  - name: corporate-keycloak
    authority: https://keycloak.corp.example.com/realms/platform
    client-id: bgctl
    # Optional: Client credentials flow for non-interactive usage
    # Prefer environment variables or files for secrets
    client-secret-env: BGCTL_OIDC_CORP_SECRET
    # client-secret-file: /etc/bgctl/corp-client-secret
    grant-type: authorization-code  # authorization-code | device-code | client-credentials
    # Optional: Custom CA for self-signed certificates
    ca-file: /etc/ssl/certs/corp-ca.pem
    # Optional: Additional scopes beyond openid
    scopes:
      - openid
      - email
      - groups
    # Optional: Prefer device code flow (for headless/SSH environments)
    device-code-flow: false

  # Separate Keycloak for development environment
  - name: dev-keycloak
    authority: https://keycloak.dev.example.com/realms/dev
    client-id: bgctl-dev
    grant-type: device-code
    device-code-flow: true  # Dev often accessed via SSH

  # External IDP (e.g., contractor access)
  - name: contractor-idp
    authority: https://contractor-idp.example.com/realms/external
    client-id: bgctl-contractors
    grant-type: authorization-code

# ============================================================================
# Contexts - Define Breakglass instances (like kubectl contexts)
# ============================================================================
contexts:
  - name: production
    server: https://breakglass.prod.example.com
    # Reference shared OIDC provider by name
    oidc-provider: corporate-keycloak
    # Optional: Override CA (if different from OIDC provider)
    ca-file: /etc/ssl/certs/corp-ca.pem
    # Optional: Skip TLS verification (NOT recommended for production)
    insecure-skip-tls-verify: false

  - name: staging
    server: https://breakglass.staging.example.com
    # Same Keycloak as production - shares tokens!
    oidc-provider: corporate-keycloak

  - name: development
    server: https://breakglass.dev.example.com
    # Different Keycloak for dev environment
    oidc-provider: dev-keycloak

  - name: contractor-prod
    server: https://breakglass.prod.example.com
    # Same server as 'production' but different IDP for contractors
    oidc-provider: contractor-idp

  # Inline OIDC config (for simple single-context setups)
  - name: local
    server: https://localhost:8443
    insecure-skip-tls-verify: true
    oidc:
      authority: https://localhost:9443/realms/test
      client-id: bgctl
      device-code-flow: true

# ============================================================================
# Global Settings
# ============================================================================
settings:
  # Default output format: table, json, yaml
  output-format: table
  # Enable colors (auto, always, never)
  color: auto
  # Pagination settings
  page-size: 50
```

### Configuration Commands

```bash
# Initialize configuration interactively
bgctl config init

# Add a new OIDC provider (reusable across contexts)
bgctl config add-oidc-provider corporate-keycloak \
  --authority https://keycloak.corp.example.com/realms/platform \
  --client-id bgctl \
  --ca-file /etc/ssl/certs/corp-ca.pem \
  --grant-type authorization-code

# Non-interactive client-credentials provider with env var (validates existence)
bgctl config add-oidc-provider ci-keycloak \
  --authority https://keycloak.corp.example.com/realms/platform \
  --client-id bgctl-ci \
  --client-secret-env BGCTL_OIDC_CI_SECRET \
  --grant-type client-credentials
# Warning: BGCTL_OIDC_CI_SECRET not set in environment
# Provider will fail to authenticate until variable is set

# Inline client secret (NOT RECOMMENDED for production)
bgctl config add-oidc-provider test-keycloak \
  --authority https://keycloak.test.local/realms/test \
  --client-id bgctl-test \
  --client-secret "my-secret-value" \
  --grant-type client-credentials
# ⚠ WARNING: Storing secrets inline is insecure!
# ⚠ Prefer --client-secret-env or --client-secret-file for production use
# ⚠ Config file permissions: 0600

# Add a new context referencing an existing OIDC provider
bgctl config add-context production \
  --server https://breakglass.prod.example.com \
  --oidc-provider corporate-keycloak

# Add a context with inline OIDC config (simpler for single-context setups)
bgctl config add-context local \
  --server https://localhost:8443 \
  --oidc-authority https://localhost:9443/realms/test \
  --oidc-client-id bgctl \
  --insecure-skip-tls-verify

# List configured contexts (shows current context with *)
bgctl config get-contexts
# NAME             SERVER                                    OIDC PROVIDER
# * production     https://breakglass.prod.example.com       corporate-keycloak
#   staging        https://breakglass.staging.example.com    corporate-keycloak
#   development    https://breakglass.dev.example.com        dev-keycloak

# List OIDC providers
bgctl config get-oidc-providers
# NAME                 AUTHORITY                                           CLIENT-ID
# corporate-keycloak   https://keycloak.corp.example.com/realms/platform   bgctl
# dev-keycloak         https://keycloak.dev.example.com/realms/dev         bgctl-dev

# Switch default context (persistent)
bgctl config set-context staging
# Alias: bgctl config use-context staging

# View current context
bgctl config current-context
# staging

# View full configuration
bgctl config view

# Set a specific value
bgctl config set settings.output-format json

# Remove a context
bgctl config delete-context development

# Remove an OIDC provider (fails if still referenced by contexts)
bgctl config delete-oidc-provider dev-keycloak
```

---

## Multi-Instance Usage (Like kubectl --context)

Every command supports `--context` to override the default context for that invocation.
This enables easy scripting and one-off operations against different instances.

```bash
# Use --context flag (like kubectl --context)
bgctl --context production session list
bgctl --context staging session list --mine
bgctl --context development session request --cluster dev-1 --group admin

# Environment variable override (useful for scripts)
BGCTL_CONTEXT=production bgctl session list

# Shorthand alias: -c
bgctl -c production session list

# Context flag works with any command
bgctl -c staging auth status
bgctl -c production escalation list
bgctl -c development debug session list

# Compare sessions across instances
echo "=== Production ===" && bgctl -c production session list --mine
echo "=== Staging ===" && bgctl -c staging session list --mine
```

### Token Sharing Across Contexts

When multiple contexts share the same OIDC provider, authentication is shared:

```bash
# Login once to corporate-keycloak
bgctl --context production auth login
# ✓ Authenticated as user@example.com via corporate-keycloak

# Staging uses the same OIDC provider - no re-login needed!
bgctl --context staging auth status
# ✓ Authenticated as user@example.com (via shared provider: corporate-keycloak)
# Token expires: 2026-01-15 12:30:00 UTC

# Development uses a different OIDC provider - separate login required
bgctl --context development auth status
# ✗ Not authenticated (provider: dev-keycloak)
# Run 'bgctl --context development auth login' to authenticate
```

### Scripting Example

```bash
#!/bin/bash
# Request emergency access across all environments

REASON="Incident INC-12345: Database connectivity issues"

for ctx in production staging; do
  echo "Requesting access on $ctx..."
  bgctl -c "$ctx" session request \
    --cluster "primary-cluster" \
    --group "breakglass-emergency-admin" \
    --reason "$REASON" \
    --output json | jq -r '.name'
done
```

---

## Authentication

### Browser-Based OIDC Flow (Default)

```bash
# Login to current context - opens browser for OIDC authentication
bgctl auth login

# Login to specific context (authenticates the associated OIDC provider)
bgctl auth login --context production

# Login to an OIDC provider directly (useful when setting up)
bgctl auth login --oidc-provider corporate-keycloak

# Check authentication status
bgctl auth status
# ✓ Authenticated as user@example.com
# Token expires: 2026-01-15 12:30:00 UTC
# Context: production
# OIDC Provider: corporate-keycloak
# Groups: sre-team, platform-admins

# Check auth status for all contexts
bgctl auth status --all
# CONTEXT        OIDC PROVIDER        STATUS              EXPIRES
# production     corporate-keycloak   ✓ user@example.com  2026-01-15 12:30
# staging        corporate-keycloak   ✓ user@example.com  2026-01-15 12:30 (shared)
# development    dev-keycloak         ✗ Not authenticated

# Logout from current context's OIDC provider
bgctl auth logout

# Logout from a specific provider (affects all contexts using it)
bgctl auth logout --oidc-provider corporate-keycloak

# Logout from all providers
bgctl auth logout --all
```

### Device Code Flow (Headless/SSH)

```bash
# Use device code flow for headless environments
bgctl auth login --device-code

# Output:
# To authenticate, visit: https://keycloak.example.com/device
# Enter code: ABCD-1234
# Waiting for authentication...
# ✓ Authenticated as user@example.com
```

### Client Credentials Flow (Non-Interactive)

For automation or service accounts, use client credentials. The provider must define
`grant-type: client-credentials` and a client secret source.

```bash
# Login using client credentials (no browser)
bgctl auth login --oidc-provider corporate-keycloak --client-credentials

# Use current context provider (if configured for client-credentials)
bgctl auth login --client-credentials
```

Notes:
- Client secrets must be provided via `client-secret-env` or `client-secret-file`.
- Tokens are cached per OIDC provider.
- `--token` bypasses OIDC entirely for one-off commands.

### Token Management

```bash
# View current token info (redacted)
bgctl auth token-info

# Export token for use with curl (advanced)
bgctl auth token --raw

# Refresh token if close to expiry (refreshes current context's provider)
bgctl auth refresh
# ✓ Refreshed token for provider: corporate-keycloak
# ✓ Token valid for contexts: production, staging

# Refresh tokens for all OIDC providers
bgctl auth refresh --all
# ✓ Refreshed corporate-keycloak (contexts: production, staging)
# ✓ Refreshed dev-keycloak (contexts: development)
# ✗ Failed to refresh contractor-idp (not authenticated)
```

---

## Command Hierarchy

```
bgctl
├── update                        # Self-update commands
│   ├── (default)                 # Update to latest version
│   └── check                     # Check for available updates
│
├── auth                          # Authentication commands
│   ├── login                     # Authenticate with OIDC
│   ├── logout                    # Clear authentication
│   ├── status                    # Show auth status
│   ├── token-info                # Show token information
│   └── refresh                   # Refresh token
│
├── config                        # Configuration management
│   ├── init                      # Interactive setup
│   ├── view                      # Show configuration
│   ├── add-context               # Add new context
│   ├── delete-context            # Remove context
│   ├── use-context               # Switch context
│   ├── current-context           # Show current context
│   ├── get-contexts              # List contexts
│   ├── add-oidc-provider         # Add reusable OIDC provider
│   ├── delete-oidc-provider      # Remove OIDC provider
│   ├── get-oidc-providers        # List OIDC providers
│   └── set                       # Set config value
│
├── session                       # Breakglass session management
│   ├── list                      # List sessions
│   ├── get                       # Get session details
│   ├── request                   # Request new session
│   ├── approve                   # Approve pending session
│   ├── reject                    # Reject pending session
│   ├── withdraw                  # Withdraw own request
│   ├── drop                      # Drop own session
│   ├── cancel                    # Cancel session (approver)
│   └── watch                     # Watch session status changes
│
├── escalation                    # Escalation policy information
│   ├── list                      # List available escalations
│   └── get                       # Get escalation details
│
├── debug                         # Debug session management
│   ├── session
│   │   ├── list                  # List debug sessions
│   │   ├── get                   # Get debug session details
│   │   ├── create                # Create debug session
│   │   ├── renew                 # Extend debug session
│   │   ├── terminate             # Terminate debug session
│   │   ├── approve               # Approve debug session
│   │   └── reject                # Reject debug session
│   │   # Note: join/leave deferred until terminal sharing (tmux) is implemented
│   │
│   ├── template
│   │   ├── list                  # List debug session templates
│   │   └── get                   # Get template details
│   │
│   ├── pod-template
│   │   ├── list                  # List debug pod templates
│   │   └── get                   # Get pod template details
│   │
│   └── kubectl                   # Kubectl-debug operations
│       ├── inject                # Inject ephemeral container
│       ├── copy-pod              # Create pod copy for debugging
│       └── node-debug            # Create node debug pod
│
├── cluster                       # Cluster information
│   └── list                      # List available clusters
│
├── completion                    # Shell completion scripts
│   ├── bash
│   ├── zsh
│   ├── fish
│   └── powershell
│
└── version                       # Show version information
```

---

## Global Flags

These flags are available on all commands (similar to kubectl):

| Flag | Short | Env Variable | Description |
|------|-------|--------------|-------------|
| `--context` | `-c` | `BGCTL_CONTEXT` | Override the current-context for this command |
| `--config` | | `BGCTL_CONFIG` | Path to config file (default: `~/.config/bgctl/config.yaml`) |
| `--server` | | `BGCTL_SERVER` | Override server URL (bypasses context server) |
| `--token` | | `BGCTL_TOKEN` | Use bearer token (bypasses OIDC and context auth) |
| `--output` | `-o` | `BGCTL_OUTPUT` | Output format: `table`, `json`, `yaml` (default: `table`) |
| `--no-color` | | `NO_COLOR` | Disable colored output |
| `--verbose` | `-v` | `BGCTL_VERBOSE` | Enable verbose output (can be repeated: `-vv`, `-vvv`) |
| `--quiet` | `-q` | | Suppress non-essential output |
| `--page` | | | Page number for paginated output (default: 1) |
| `--page-size` | | `BGCTL_PAGE_SIZE` | Items per page (overrides config, default: 50) |
| `--all` | | | Disable pagination, show all results |
| `--non-interactive` | | `BGCTL_NON_INTERACTIVE` | Fail instead of prompting (for CI/CD) |
| `--help` | `-h` | | Show help for command |

### Examples

```bash
# Override context for a single command
bgctl --context production session list
bgctl -c staging session get my-session

# Use JSON output for scripting
bgctl -o json session list | jq '.[].name'

# Verbose mode for debugging
bgctl -vv session request --cluster prod --group admin --reason "test"

# Quiet mode for scripts (only errors and essential output)
bgctl -q session approve my-session
```

---

## Detailed Command Reference

### Session Commands

#### List Sessions

```bash
# List all sessions you can view
bgctl session list

# Filter by state
bgctl session list --state pending
bgctl session list --state approved
bgctl session list --state approved,pending

# Filter by cluster
bgctl session list --cluster prod-cluster-1

# Show only your sessions
bgctl session list --mine

# Show sessions you can approve
bgctl session list --approver

# Show sessions you have approved
bgctl session list --approved-by-me

# Show only active (currently running) sessions
bgctl session list --active-only

# Combine filters
bgctl session list --mine --state pending --cluster prod-*

# Output as JSON
bgctl session list -o json

# Output as YAML
bgctl session list -o yaml

# Wide output with more columns (approver, scheduled start, idle timeout)
bgctl session list -o wide

# Pagination (default page size from config: 50)
bgctl session list --page 2
# Output: Showing page 2 of 5 (237 total items)

# Show all results (disable pagination)
bgctl session list --all
```

**Example Output (table):**

```
NAME                  CLUSTER         USER              GROUP           STATE     CREATED               EXPIRES
session-abc123        prod-cluster-1  user@example.com  cluster-admin   Pending   2026-01-15 10:30:00   -
session-def456        staging-01      other@example.com cluster-admin   Approved  2026-01-15 09:00:00   2026-01-15 11:00:00
```

#### Get Session Details

```bash
# Get session by name
bgctl session get session-abc123

# Output as JSON
bgctl session get session-abc123 -o json
```

**Example Output:**

```
Name:           session-abc123
Namespace:      breakglass-system
Cluster:        prod-cluster-1
User:           user@example.com
Group:          cluster-admin
State:          Pending
Reason:         Emergency fix for incident INC-12345

Created:        2026-01-15 10:30:00 UTC
Timeout At:     2026-01-15 10:45:00 UTC

Conditions:
  TYPE      STATUS    REASON    MESSAGE
  Pending   True      Created   Session created and awaiting approval
```

#### Request Session

```bash
# Interactive request (prompts for required fields)
bgctl session request

# Specify all options
bgctl session request \
  --cluster prod-cluster-1 \
  --group cluster-admin \
  --reason "Emergency fix for incident INC-12345"

# Request with custom duration (if allowed by escalation)
bgctl session request \
  --cluster prod-cluster-1 \
  --group cluster-admin \
  --reason "Debugging performance issue" \
  --duration 2h

# Request access to multiple clusters atomically (all-or-nothing approval)
bgctl session request \
  --cluster prod-1,prod-2,staging-* \
  --group cluster-admin \
  --reason "Multi-cluster deployment for incident INC-12345"

# Schedule for future time
bgctl session request \
  --cluster prod-cluster-1 \
  --group cluster-admin \
  --reason "Scheduled maintenance" \
  --scheduled-start "2026-01-16T02:00:00Z"

# Wait for approval (blocks until approved/rejected/timeout)
bgctl session request \
  --cluster prod-cluster-1 \
  --group cluster-admin \
  --reason "Emergency fix" \
  --wait

# Wait with timeout
bgctl session request \
  --cluster prod-cluster-1 \
  --group cluster-admin \
  --reason "Emergency fix" \
  --wait --wait-timeout 5m
```

#### Approve Session

```bash
# Approve with reason
bgctl session approve session-abc123 --reason "Verified incident details"

# Approve without reason (if not required)
bgctl session approve session-abc123
```

#### Reject Session

```bash
# Reject with reason
bgctl session reject session-abc123 --reason "Insufficient justification"
```

#### Withdraw Session

```bash
# Withdraw your own pending request
bgctl session withdraw session-abc123
```

#### Drop Session

```bash
# Drop your own pending or active session
bgctl session drop session-abc123
```

#### Cancel Session (Approver)

```bash
# Cancel an active session as an approver
bgctl session cancel session-abc123 --reason "Session no longer needed"
```

#### Watch Session

```bash
# Watch for state changes (polling-based, 2s interval by default)
bgctl session watch session-abc123

# Watch all pending sessions
bgctl session watch --state pending

# Show full object instead of diffs
bgctl session watch session-abc123 --show-full

# Custom polling interval
bgctl session watch session-abc123 --interval 5s

# Output events as JSON (for scripting)
bgctl session watch --state pending -o json
```

**Note**: Watch uses polling with configurable interval (default 2s). WebSocket support planned for future release.

---

### Escalation Commands

#### List Escalations

```bash
# List all escalations available to you
bgctl escalation list

# Filter by cluster
bgctl escalation list --cluster prod-*

# Output as JSON
bgctl escalation list -o json
```

**Example Output:**

```
NAME                      DISPLAY NAME              CLUSTER           GROUP           MAX DURATION  SELF-APPROVAL
cluster-admin-escalation  Cluster Admin Access      prod-cluster-*    cluster-admin   2h            No
viewer-escalation         Read-Only Access          *                 viewer          8h            Yes
```

#### Get Escalation Details

```bash
bgctl escalation get cluster-admin-escalation
```

**Example Output:**

```
Name:               cluster-admin-escalation
Display Name:       Cluster Admin Access
Description:        Temporary cluster admin access for incident response

Target Group:       cluster-admin
Max Duration:       2h
Idle Timeout:       30m
Retain For:         30d

Allowed Clusters:   prod-cluster-*, staging-*
Allowed Groups:     sre-team, platform-admins

Approvers:
  Users:            admin@example.com
  Groups:           security-team

Self Approval:      No
Approval Timeout:   15m

Request Reason:     Required
Approval Reason:    Optional
```

---

### Debug Session Commands

#### List Debug Sessions

```bash
# List all debug sessions
bgctl debug session list

# Filter by state
bgctl debug session list --state Active

# Filter by cluster
bgctl debug session list --cluster production

# Show only your sessions
bgctl debug session list --mine
```

#### Create Debug Session

```bash
# Create interactively
bgctl debug session create

# Create with options
bgctl debug session create \
  --template standard-debug \
  --cluster production \
  --duration 2h \
  --reason "Investigating issue #12345"

# Create with node selector
bgctl debug session create \
  --template standard-debug \
  --cluster production \
  --node-selector zone=us-east-1a \
  --reason "Debugging node-specific issue"
```

#### Renew Debug Session

**Note**: `join` and `leave` commands are not implemented in v1. These will be added when terminal sharing via tmux is fully implemented.



```bash
# Extend session by 1 hour
bgctl debug session renew my-debug-session --extend-by 1h
```

#### Terminate Debug Session

```bash
bgctl debug session terminate my-debug-session
```

#### List Templates

```bash
bgctl debug template list
```

**Example Output:**

```
NAME             DISPLAY NAME           MODE      WORKLOAD TYPE  REQUIRES APPROVAL
standard-debug   Standard Debug Access  workload  DaemonSet      Yes
netshoot         Network Debugging      workload  Deployment     No
kubectl-debug    Kubectl Debug Mode     kubectl   -              Yes
```

---

### Debug Kubectl Commands

**Prerequisite**: Debug session must be in "Active" state. The API enforces this requirement and will return an error if the session is Pending, Expired, or Terminated.

```bash
# Inject ephemeral container (requires active session)
bgctl debug kubectl inject my-debug-session \
  --namespace default \
  --pod my-app-pod-xyz \
  --image busybox:latest \
  --container-name debug
# Error: Session my-debug-session is not active (current state: Pending)

# Create pod copy
bgctl debug kubectl copy-pod my-debug-session \
  --namespace default \
  --pod my-app-pod-xyz \
  --debug-image busybox:latest

# Create node debug pod
bgctl debug kubectl node-debug my-debug-session \
  --node worker-node-1
```

---

### Cluster Commands

```bash
# List available clusters
bgctl cluster list

# Output as JSON
bgctl cluster list -o json
```

**Example Output:**

```
NAME             TENANT      ENVIRONMENT  STATUS
prod-cluster-1   acme-corp   production   Ready
prod-cluster-2   acme-corp   production   Ready
staging-01       acme-corp   staging      Ready
dev-01           acme-corp   development  Ready
```

---

### Shell Completion

```bash
# Generate completion script
bgctl completion bash > /etc/bash_completion.d/bgctl

# Zsh
bgctl completion zsh > "${fpath[1]}/_bgctl"

# Fish
bgctl completion fish > ~/.config/fish/completions/bgctl.fish

# PowerShell
bgctl completion powershell > bgctl.ps1
```

#### Context-Aware Completion

Shell completion supports context-aware suggestions using local caching:

```bash
# Complete context names from config
bgctl --context <TAB>
# production  staging  development

# Complete pending session names (from cache)
bgctl session approve <TAB>
# session-abc123  session-def456
# (cached 2m ago)

# Complete cluster names (from cache)
bgctl session request --cluster <TAB>
# prod-cluster-1  prod-cluster-2  staging-01
# (cached 5m ago, run 'bgctl completion refresh-cache' to update)
```

**Caching behavior**:
- Completions are cached locally in `~/.config/bgctl/completion-cache/`
- Cache refreshed automatically on miss or when stale (>5 minutes)
- Manual refresh: `bgctl completion refresh-cache`
- Warning shown if cache is stale during completion

---

## Global Flags

All commands support these global flags:

```
--context string      Override the current context
--server string       Override the server URL
--token string        Use specific bearer token (bypasses OIDC)
-o, --output string   Output format: table, json, yaml, wide (default "table")
-q, --quiet           Suppress non-essential output
-v, --verbose         Enable verbose/debug output
--no-color            Disable colored output
--timeout duration    Request timeout (default 30s)
--config string       Config file path (default ~/.config/bgctl/config.yaml)
-h, --help            Show help for command
```

Notes:
- `--server` overrides the context server and does not require a configured context.
- `--token` bypasses OIDC and uses the provided bearer token for this command only.

---

## Exit Codes

Follows Unix standard exit codes where applicable:

| Code | Meaning |
|------|---------|
| 0    | Success |
| 1    | General error |
| 2    | Invalid arguments/usage (misuse of shell command) |
| 3    | Authentication required/failed |
| 4    | Authorization denied (permission error) |
| 5    | Resource not found |
| 6    | Conflict (e.g., session already exists) |
| 7    | Server error (remote service failure) |
| 8    | Timeout |
| 9    | Configuration error (invalid config file) |
| 64   | Command line usage error (EX_USAGE, invalid flags) |
| 130  | Interrupted by Ctrl+C (128 + SIGINT) |

**Note on precedence**: Flag > Environment Variable > Config File
```bash
# Example: Flag takes precedence
BGCTL_CONTEXT=prod bgctl --context staging session list  # Uses 'staging'
```

---

## Scripting Examples

### Request and Wait for Approval

```bash
#!/bin/bash
set -e

# Request session and wait
SESSION=$(bgctl session request \
  --cluster prod-cluster-1 \
  --group cluster-admin \
  --reason "Automated deployment" \
  --wait --wait-timeout 10m \
  -o json)

SESSION_NAME=$(echo "$SESSION" | jq -r '.metadata.name')
echo "Session approved: $SESSION_NAME"

# Do work...
kubectl --context=prod-cluster-1 apply -f manifests/

# Drop session when done
bgctl session drop "$SESSION_NAME"
```

### Batch Approval

```bash
#!/bin/bash
# Approve all pending sessions from SRE team members

bgctl session list --state pending -o json | \
  jq -r '.[] | select(.spec.user | test("@sre-team.example.com$")) | .metadata.name' | \
  while read -r session; do
    echo "Approving $session"
    bgctl session approve "$session" --reason "Batch approval for SRE team"
  done
```

### CI/CD Integration

```bash
# In CI pipeline - use service account token
export BGCTL_TOKEN="$CI_BREAKGLASS_TOKEN"

bgctl --server https://breakglass.example.com \
  session request \
  --cluster "$TARGET_CLUSTER" \
  --group deployer \
  --reason "CI/CD deployment #$CI_PIPELINE_ID" \
  --wait --wait-timeout 5m

# Deploy...
```

---

## Implementation Architecture

### Design Principle: Library-First

The CLI is designed as a **library-first** tool, meaning all functionality is exposed through importable Go packages. The `bgctl` binary is simply a thin wrapper around these packages. This enables:

1. **Embedding in other CLIs** - Import bgctl functionality into your organization's unified CLI tool
2. **Programmatic access** - Use bgctl as a Go SDK for automation and custom tooling
3. **Custom frontends** - Build alternative interfaces (TUI, GUI) on top of the same core logic
4. **Testing** - Easy unit testing of CLI logic without spawning processes

### Project Structure

```
pkg/bgctl/                        # PUBLIC API - importable by other projects
├── client/                       # Breakglass API client (SDK)
│   ├── client.go                # Main client interface
│   ├── options.go               # Client configuration options
│   ├── sessions.go              # Session operations
│   ├── escalations.go           # Escalation operations
│   ├── debug.go                 # Debug session operations
│   ├── clusters.go              # Cluster operations
│   └── types.go                 # Request/response types
├── auth/                         # Authentication handling
│   ├── auth.go                  # Auth interface and factory
│   ├── oidc.go                  # OIDC browser flow
│   ├── device.go                # Device code flow
│   ├── token.go                 # Token management
│   └── keyring.go               # Secure token storage
├── config/                       # Configuration management
│   ├── config.go                # Config types and loading
│   ├── context.go               # Context management
│   └── paths.go                 # Platform-specific paths
├── output/                       # Output formatting (reusable)
│   ├── output.go                # Output interface
│   ├── table.go                 # Table formatter
│   ├── json.go                  # JSON/YAML formatter
│   └── writer.go                # Configurable output writer
└── cmd/                          # Cobra command builders (composable)
    ├── root.go                  # Root command factory
    ├── auth.go                  # Auth subcommands
    ├── config.go                # Config subcommands
    ├── session.go               # Session subcommands
    ├── escalation.go            # Escalation subcommands
    ├── debug.go                 # Debug session subcommands
    ├── cluster.go               # Cluster subcommands
    └── completion.go            # Shell completion

cmd/bgctl/                        # Standalone binary entry point
└── main.go                      # Minimal main.go using pkg/bgctl

internal/                         # Private implementation details
└── util/
    ├── prompt.go                # Interactive prompts
    └── spinner.go               # Progress indicators
```

### Standalone Binary (cmd/bgctl/main.go)

The standalone `bgctl` binary is a minimal wrapper demonstrating the library-first approach:

```go
// cmd/bgctl/main.go
package main

import (
    "os"

    bgctlcmd "github.com/telekom/k8s-breakglass/pkg/bgctl/cmd"
)

func main() {
    // Create the root command with default configuration
    rootCmd := bgctlcmd.NewRootCommand(bgctlcmd.DefaultConfig())
    
    if err := rootCmd.Execute(); err != nil {
        os.Exit(1)
    }
}
```

This minimal entry point shows that all logic lives in the importable packages.

### Key Dependencies

- `github.com/spf13/cobra` - CLI framework
- `github.com/spf13/viper` - Configuration management
- `github.com/coreos/go-oidc/v3` - OIDC authentication
- `golang.org/x/oauth2` - OAuth2 flows
- `github.com/olekukonko/tablewriter` - Table output
- `github.com/fatih/color` - Colored output
- `github.com/manifoldco/promptui` - Interactive prompts

---

## Library Usage (Embedding in Other CLIs)

### Installing as a Dependency

```bash
go get github.com/telekom/k8s-breakglass/pkg/bgctl@latest
```

### Using the Client SDK Directly

The `pkg/bgctl/client` package provides a standalone SDK for interacting with the Breakglass API programmatically:

```go
package main

import (
    "context"
    "fmt"
    "log"
    "time"

    "github.com/telekom/k8s-breakglass/pkg/bgctl/client"
    "github.com/telekom/k8s-breakglass/pkg/bgctl/auth"
)

func main() {
    ctx := context.Background()

    // Option 1: Create client with token directly
    bgClient, err := client.New(
        client.WithServer("https://breakglass.example.com"),
        client.WithToken("your-jwt-token"),
    )

    // Option 2: Create client with OIDC authentication
    authenticator := auth.NewOIDC(auth.OIDCConfig{
        Authority: "https://keycloak.example.com/realms/prod",
        ClientID:  "bgctl",
    })
    bgClient, err = client.New(
        client.WithServer("https://breakglass.example.com"),
        client.WithAuthenticator(authenticator),
    )

    // Option 3: Load from bgctl config file
    bgClient, err = client.NewFromConfig(client.DefaultConfigPath())

    if err != nil {
        log.Fatal(err)
    }

    // List sessions
    sessions, err := bgClient.Sessions().List(ctx, client.SessionListOptions{
        Mine:  true,
        State: []string{"pending", "approved"},
    })
    if err != nil {
        log.Fatal(err)
    }

    for _, s := range sessions {
        fmt.Printf("Session: %s, State: %s\n", s.Name, s.Status.State)
    }

    // Request a session
    session, err := bgClient.Sessions().Request(ctx, client.SessionRequest{
        Cluster: "prod-cluster-1",
        Group:   "cluster-admin",
        Reason:  "Emergency fix",
    })
    if err != nil {
        log.Fatal(err)
    }

    // Wait for approval
    approved, err := bgClient.Sessions().WaitForApproval(ctx, session.Name, 5*time.Minute)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Session %s approved!\n", approved.Name)
}
```

### Embedding Cobra Commands in Your CLI

The `pkg/bgctl/cmd` package exports Cobra command factories that can be embedded into your existing CLI:

```go
package main

import (
    "os"

    "github.com/spf13/cobra"
    bgctlcmd "github.com/telekom/k8s-breakglass/pkg/bgctl/cmd"
    "github.com/telekom/k8s-breakglass/pkg/bgctl/config"
)

func main() {
    // Your organization's root CLI command
    rootCmd := &cobra.Command{
        Use:   "mycli",
        Short: "My organization's unified CLI",
    }

    // Add your other commands
    rootCmd.AddCommand(newDeployCmd())
    rootCmd.AddCommand(newMonitorCmd())

    // Embed bgctl as a subcommand tree under "breakglass"
    // This adds: mycli breakglass session list, mycli breakglass auth login, etc.
    bgConfig := bgctlcmd.Config{
        ConfigPath:     config.DefaultConfigPath(),  // Or custom path
        DefaultContext: "production",
    }
    rootCmd.AddCommand(bgctlcmd.NewBreakglassCommand(bgConfig))

    // Or embed individual command groups selectively
    // rootCmd.AddCommand(bgctlcmd.NewSessionCommand(bgConfig))   // mycli session ...
    // rootCmd.AddCommand(bgctlcmd.NewDebugCommand(bgConfig))     // mycli debug ...

    if err := rootCmd.Execute(); err != nil {
        os.Exit(1)
    }
}

func newDeployCmd() *cobra.Command { return &cobra.Command{Use: "deploy"} }
func newMonitorCmd() *cobra.Command { return &cobra.Command{Use: "monitor"} }
```

### Customizing Command Behavior

You can customize the embedded commands by providing hooks and overrides:

```go
package main

import (
    "fmt"
    "net/http"
    "os"

    "github.com/spf13/cobra"
    bgctlcmd "github.com/telekom/k8s-breakglass/pkg/bgctl/cmd"
)

func main() {
    rootCmd := &cobra.Command{Use: "mycli"}

    bgConfig := bgctlcmd.Config{
        // Use your CLI's config directory
        ConfigPath: "~/.mycli/breakglass.yaml",
        
        // Custom output writer (e.g., for structured logging)
        OutputWriter: &myCustomWriter{},
        
        // Override authentication (use your org's auth system)
        Authenticator: myOrgAuthenticator,
        
        // Add custom headers to all requests
        HTTPMiddleware: func(req *http.Request) {
            req.Header.Set("X-My-Org-Trace-ID", getTraceID())
        },
        
        // Callback hooks for telemetry and notifications
        Hooks: bgctlcmd.Hooks{
            OnSessionRequested: func(session *client.Session) {
                // Custom telemetry, audit logging, etc.
                metrics.Counter("breakglass.session.requested").Inc()
            },
            OnSessionApproved: func(session *client.Session) {
                slack.Notify("#security", fmt.Sprintf("Session %s approved", session.Name))
            },
        },
        
        // Disable certain commands if you want to use your own
        DisabledCommands: []string{"auth", "config"}, // Use your own auth/config
    }

    rootCmd.AddCommand(bgctlcmd.NewBreakglassCommand(bgConfig))
    rootCmd.Execute()
}
```

### Using Individual Components

You can also use individual packages without the full CLI:

```go
package main

import (
    "context"
    "os"

    "github.com/telekom/k8s-breakglass/pkg/bgctl/auth"
    "github.com/telekom/k8s-breakglass/pkg/bgctl/config"
    "github.com/telekom/k8s-breakglass/pkg/bgctl/output"
)

func main() {
    // Just use the config management
    cfg, _ := config.Load("~/.config/bgctl/config.yaml")
    ctx := cfg.CurrentContext()
    
    // Just use the authentication
    authenticator := auth.NewOIDC(auth.OIDCConfig{
        Authority: ctx.OIDC.Authority,
        ClientID:  ctx.OIDC.ClientID,
    })
    token, _ := authenticator.GetToken(context.Background())
    
    // Just use the output formatting
    formatter := output.NewTableFormatter(os.Stdout)
    formatter.SetHeaders([]string{"Name", "State", "Cluster"})
    formatter.AddRow([]string{"session-1", "Approved", "prod"})
    formatter.Render()
}
```

### Shared Configuration with Standalone bgctl

When embedding bgctl in your CLI, you can choose to:

1. **Share config with standalone bgctl** - Use the same `~/.config/bgctl/config.yaml`
2. **Use separate config** - Store in your CLI's config directory
3. **Hybrid approach** - Read bgctl config but add organization-specific overrides

```go
// Hybrid: Load bgctl config, overlay org-specific settings
cfg, _ := config.Load(config.DefaultConfigPath())
cfg.SetDefault("server", "https://breakglass.myorg.com")  // Org default
cfg.SetDefault("oidc.client-id", "myorg-cli")             // Different client
```

---

### Token Storage

Tokens are stored securely using OS-native keyrings when available:

- **macOS**: Keychain via `github.com/zalando/go-keyring`
- **Linux**: Secret Service API (GNOME Keyring, KWallet) or encrypted file fallback
- **Windows**: Windows Credential Manager

Tokens are cached per OIDC provider (shared across contexts that reference the same provider).

#### Encrypted File Fallback (Linux without keyring)

If no keyring is available, tokens are stored in an encrypted file:

```
~/.config/bgctl/tokens.enc      # AES-256 encrypted tokens
```

**Key derivation**: On first use, `bgctl` prompts for a password:
```bash
bgctl auth login
# No keyring detected. Token storage requires encryption.
# Enter password for token encryption: ********
# Confirm password: ********
# ✓ Password stored securely
```

**Password storage**: The password itself is stored in `~/.config/bgctl/.keyring` (0600 permissions) hashed with bcrypt.

**Migration to keyring**: If a keyring becomes available later (e.g., after installing GNOME Keyring):
```bash
bgctl auth migrate-to-keyring
# Detected available keyring: GNOME Keyring
# Enter current encryption password: ********
# ✓ Migrating 3 tokens to keyring...
# ✓ Migration complete. Encrypted file backup: ~/.config/bgctl/tokens.enc.backup
```

**File permissions**: All config and token files use 0600 permissions (user read/write only).

---

## Security Considerations

1. **Token Storage**: Use OS keyring where available, encrypted file as fallback
2. **TLS Verification**: Enabled by default, warn loudly if disabled
3. **Token Refresh**: Automatic refresh before expiry
4. **Credential Logging**: Never log tokens, even in verbose mode
5. **Config File Permissions**: Validate 0600 permissions on config files
6. **Device Code Flow**: Support for headless environments without exposing browser

---

## API Stability and Versioning

### Public API Guarantees

The following packages are considered **public API** with stability guarantees:

| Package | Stability | Description |
|---------|-----------|-------------|
| `pkg/bgctl/client` | **Stable** | Breakglass API client SDK |
| `pkg/bgctl/auth` | **Stable** | Authentication interfaces and implementations |
| `pkg/bgctl/config` | **Stable** | Configuration types and loading |
| `pkg/bgctl/output` | **Stable** | Output formatting utilities |
| `pkg/bgctl/cmd` | **Stable** | Cobra command factories for embedding |
| `internal/*` | **Unstable** | Internal implementation details, may change |

### Semantic Versioning

- **Major versions** (v1.x.x → v2.x.x): Breaking changes to public API
- **Minor versions** (v1.1.x → v1.2.x): New features, backward compatible
- **Patch versions** (v1.1.1 → v1.1.2): Bug fixes only

### Compatibility Promise

For v1.x releases:
- Public package interfaces will remain backward compatible
- New methods may be added to interfaces (use type assertions for optional methods)
- Struct fields will only be added, never removed or renamed
- Embedded CLI commands will maintain consistent flag names and behavior

```go
// Example: Checking for optional interface methods
if watcher, ok := bgClient.Sessions().(client.SessionWatcher); ok {
    // Use watch functionality if available
    watcher.Watch(ctx, sessionName, callback)
}
```

---

## Future Enhancements (Out of Scope for v1)

1. **Interactive TUI Mode** - Full-screen terminal UI with `github.com/charmbracelet/bubbletea`
2. **Plugin System** - Allow custom commands via plugins
3. **Notifications** - Desktop notifications for session state changes
4. **Offline Mode** - Cache cluster/escalation info for offline reference
5. **Audit Log Viewer** - View audit trail for sessions
6. **Multi-Cluster Commands** - Operations across multiple clusters simultaneously

---

## Migration from UI Workflows

| UI Action | CLI Equivalent |
|-----------|----------------|
| Click "Request Access" | `bgctl session request --cluster X --group Y --reason "..."` |
| View pending approvals | `bgctl session list --approver --state pending` |
| Approve session | `bgctl session approve SESSION_NAME --reason "..."` |
| View my sessions | `bgctl session list --mine` |
| Create debug session | `bgctl debug session create --template X --cluster Y` |
| Browse escalations | `bgctl escalation list` |

---

## Testing Strategy

1. **Unit Tests**: Mock HTTP client for API calls
2. **Integration Tests**: Against test Breakglass instance
3. **E2E Tests**: Full workflow tests in CI
4. **Golden Files**: Output format verification
5. **Fuzz Testing**: Input validation

---

## E2E Testing in CI

### Overview

The CLI E2E tests run as part of the existing multi-cluster E2E test suite in GitHub Actions.
They verify real-world workflows against a live Breakglass instance with Keycloak authentication.

### CI Workflow Integration

```yaml
# .github/workflows/ci.yml (additions)
jobs:
  e2e-multi-cluster:
    # ... existing setup ...
    steps:
      # ... existing cluster setup ...
      
      - name: Build bgctl binary
        run: |
          make build-bgctl
          chmod +x ./bin/bgctl
          echo "$PWD/bin" >> $GITHUB_PATH
      
      - name: Run CLI E2E tests
        env:
          BGCTL_CONFIG: ${{ runner.temp }}/bgctl-config.yaml
          # Service account credentials for automated testing
          BGCTL_TEST_USERNAME: ${{ secrets.E2E_TEST_USER }}
          BGCTL_TEST_PASSWORD: ${{ secrets.E2E_TEST_PASSWORD }}
        run: |
          go test -v ./e2e/cli/... -tags=e2e -timeout 30m
```

### Test Configuration

The CLI E2E tests use a dedicated config file generated during test setup:

```go
// e2e/cli/setup_test.go
func setupCLIConfig(t *testing.T) string {
    configPath := filepath.Join(t.TempDir(), "bgctl-config.yaml")
    
    config := fmt.Sprintf(`
version: v1
current-context: e2e-hub

oidc-providers:
  - name: e2e-keycloak
    authority: %s
    client-id: bgctl
    device-code-flow: true  # Required for non-interactive CI

contexts:
  - name: e2e-hub
    server: %s
    oidc-provider: e2e-keycloak
    insecure-skip-tls-verify: true
  - name: e2e-spoke-a
    server: %s
    oidc-provider: e2e-keycloak
    insecure-skip-tls-verify: true
`, helpers.GetKeycloakIssuerURL(), helpers.GetHubAPIURL(), helpers.GetSpokeAAPIURL())
    
    require.NoError(t, os.WriteFile(configPath, []byte(config), 0600))
    return configPath
}
```

### Test Categories

#### 1. Config Command Tests

```go
// e2e/cli/config_test.go
func TestConfigCommands(t *testing.T) {
    t.Run("add-context", func(t *testing.T) {
        // Test adding a new context
        output := runBgctl(t, "config", "add-context", "test-ctx",
            "--server", "https://test.example.com",
            "--oidc-provider", "e2e-keycloak")
        assert.Contains(t, output, "Context 'test-ctx' added")
    })
    
    t.Run("get-contexts", func(t *testing.T) {
        output := runBgctl(t, "config", "get-contexts")
        assert.Contains(t, output, "e2e-hub")
        assert.Contains(t, output, "e2e-spoke-a")
    })
    
    t.Run("use-context", func(t *testing.T) {
        runBgctl(t, "config", "use-context", "e2e-spoke-a")
        output := runBgctl(t, "config", "current-context")
        assert.Equal(t, "e2e-spoke-a\n", output)
    })
}
```

#### 2. Authentication Tests

```go
// e2e/cli/auth_test.go
func TestAuthCommands(t *testing.T) {
    t.Run("login-device-code", func(t *testing.T) {
        // Use resource owner password grant for CI (test-only)
        // In real scenarios, device code flow would be used
        output := runBgctlWithAuth(t, "auth", "status")
        assert.Contains(t, output, "Authenticated as")
    })
    
    t.Run("auth-status-all", func(t *testing.T) {
        output := runBgctlWithAuth(t, "auth", "status", "--all")
        assert.Contains(t, output, "e2e-hub")
        assert.Contains(t, output, "e2e-keycloak")
    })
    
    t.Run("token-refresh", func(t *testing.T) {
        output := runBgctlWithAuth(t, "auth", "refresh")
        assert.Contains(t, output, "Token refreshed")
    })
}
```

#### 3. Session Workflow Tests

```go
// e2e/cli/session_test.go
func TestSessionWorkflow(t *testing.T) {
    ctx := context.Background()
    
    t.Run("full-session-lifecycle", func(t *testing.T) {
        // 1. Request a session
        output := runBgctlWithAuth(t, "session", "request",
            "--cluster", "spoke-cluster-a",
            "--group", "breakglass-pods-admin",
            "--reason", "CLI E2E test",
            "-o", "json")
        
        var session SessionResponse
        require.NoError(t, json.Unmarshal([]byte(output), &session))
        sessionName := session.Name
        
        // 2. Verify session appears in list
        output = runBgctlWithAuth(t, "session", "list", "--mine", "-o", "json")
        assert.Contains(t, output, sessionName)
        
        // 3. Get session details
        output = runBgctlWithAuth(t, "session", "get", sessionName, "-o", "json")
        assert.Contains(t, output, "pending")
        
        // 4. Approve session (as approver)
        runBgctlAsApprover(t, "session", "approve", sessionName,
            "--reason", "CLI E2E approval test")
        
        // 5. Verify session is approved
        output = runBgctlWithAuth(t, "session", "get", sessionName, "-o", "json")
        assert.Contains(t, output, "approved")
        
        // 6. Drop the session
        runBgctlWithAuth(t, "session", "drop", sessionName)
        
        // 7. Verify session is dropped
        output = runBgctlWithAuth(t, "session", "get", sessionName, "-o", "json")
        assert.Contains(t, output, "dropped")
    })
    
    t.Run("session-withdraw", func(t *testing.T) {
        // Request and immediately withdraw
        output := runBgctlWithAuth(t, "session", "request",
            "--cluster", "spoke-cluster-a",
            "--group", "breakglass-read-only",
            "--reason", "Will withdraw",
            "-o", "json")
        
        var session SessionResponse
        require.NoError(t, json.Unmarshal([]byte(output), &session))
        
        runBgctlWithAuth(t, "session", "withdraw", session.Name)
        
        output = runBgctlWithAuth(t, "session", "get", session.Name, "-o", "json")
        assert.Contains(t, output, "withdrawn")
    })
}
```

#### 4. Multi-Context Tests

```go
// e2e/cli/multicontext_test.go
func TestMultiContextOperations(t *testing.T) {
    t.Run("context-flag-override", func(t *testing.T) {
        // Default context is e2e-hub, but we can query spoke
        output := runBgctlWithAuth(t, "--context", "e2e-spoke-a",
            "cluster", "list", "-o", "json")
        assert.Contains(t, output, "spoke-cluster-a")
    })
    
    t.Run("cross-context-session-request", func(t *testing.T) {
        // Request session on spoke-a while default context is hub
        output := runBgctlWithAuth(t,
            "-c", "e2e-hub",
            "session", "request",
            "--cluster", "spoke-cluster-a",
            "--group", "breakglass-read-only",
            "--reason", "Cross-context test",
            "-o", "json")
        
        var session SessionResponse
        require.NoError(t, json.Unmarshal([]byte(output), &session))
        assert.NotEmpty(t, session.Name)
        
        // Cleanup
        runBgctlWithAuth(t, "-c", "e2e-hub", "session", "withdraw", session.Name)
    })
}
```

#### 5. Output Format Tests

```go
// e2e/cli/output_test.go
func TestOutputFormats(t *testing.T) {
    t.Run("table-output", func(t *testing.T) {
        output := runBgctlWithAuth(t, "escalation", "list", "-o", "table")
        // Verify table headers
        assert.Contains(t, output, "NAME")
        assert.Contains(t, output, "CLUSTER")
        assert.Contains(t, output, "GROUP")
    })
    
    t.Run("json-output", func(t *testing.T) {
        output := runBgctlWithAuth(t, "escalation", "list", "-o", "json")
        var escalations []interface{}
        require.NoError(t, json.Unmarshal([]byte(output), &escalations))
        assert.NotEmpty(t, escalations)
    })
    
    t.Run("yaml-output", func(t *testing.T) {
        output := runBgctlWithAuth(t, "escalation", "list", "-o", "yaml")
        var escalations []interface{}
        require.NoError(t, yaml.Unmarshal([]byte(output), &escalations))
        assert.NotEmpty(t, escalations)
    })
}
```

#### 6. Update Command Tests

```go
// e2e/cli/update_test.go
func TestUpdateCommand(t *testing.T) {
    t.Run("check-updates", func(t *testing.T) {
        output := runBgctl(t, "update", "check")
        // Should show current version at minimum
        assert.Contains(t, output, "Current version:")
    })
    
    t.Run("update-dry-run", func(t *testing.T) {
        output := runBgctl(t, "update", "--dry-run")
        assert.Contains(t, output, "Would update")
    })
}
```

#### 7. Error Handling Tests

```go
// e2e/cli/errors_test.go
func TestErrorHandling(t *testing.T) {
    t.Run("invalid-context", func(t *testing.T) {
        _, err := runBgctlExpectError(t, "--context", "nonexistent", "session", "list")
        assert.Error(t, err)
        assert.Contains(t, err.Error(), "context 'nonexistent' not found")
    })
    
    t.Run("unauthenticated-request", func(t *testing.T) {
        // Clear auth and try to make request
        _, err := runBgctlExpectError(t, "session", "list")
        assert.Error(t, err)
        assert.Contains(t, err.Error(), "not authenticated")
    })
    
    t.Run("invalid-session-name", func(t *testing.T) {
        _, err := runBgctlWithAuthExpectError(t, "session", "get", "nonexistent-session")
        assert.Error(t, err)
        assert.Contains(t, err.Error(), "not found")
    })
    
    t.Run("exit-codes", func(t *testing.T) {
        // Verify correct exit codes
        cmd := exec.Command("bgctl", "--context", "nonexistent", "session", "list")
        err := cmd.Run()
        var exitErr *exec.ExitError
        require.ErrorAs(t, err, &exitErr)
        assert.Equal(t, 1, exitErr.ExitCode())
    })
}
```

### Test Helpers

```go
// e2e/cli/helpers_test.go
package cli_test

import (
    "bytes"
    "os"
    "os/exec"
    "testing"
    
    "github.com/stretchr/testify/require"
)

var (
    bgctlBinary string
    configPath  string
)

func TestMain(m *testing.M) {
    // Setup: build bgctl and create config
    bgctlBinary = os.Getenv("BGCTL_BINARY")
    if bgctlBinary == "" {
        bgctlBinary = "bgctl"
    }
    configPath = os.Getenv("BGCTL_CONFIG")
    
    os.Exit(m.Run())
}

func runBgctl(t *testing.T, args ...string) string {
    t.Helper()
    cmd := exec.Command(bgctlBinary, args...)
    cmd.Env = append(os.Environ(), "BGCTL_CONFIG="+configPath)
    
    var stdout, stderr bytes.Buffer
    cmd.Stdout = &stdout
    cmd.Stderr = &stderr
    
    err := cmd.Run()
    require.NoError(t, err, "bgctl failed: %s\nstderr: %s", stdout.String(), stderr.String())
    
    return stdout.String()
}

func runBgctlWithAuth(t *testing.T, args ...string) string {
    t.Helper()
    // Inject token via environment or pre-authenticate
    ensureAuthenticated(t)
    return runBgctl(t, args...)
}

func runBgctlAsApprover(t *testing.T, args ...string) string {
    t.Helper()
    // Switch to approver credentials
    ensureAuthenticatedAsApprover(t)
    return runBgctl(t, args...)
}

func runBgctlExpectError(t *testing.T, args ...string) (string, error) {
    t.Helper()
    cmd := exec.Command(bgctlBinary, args...)
    cmd.Env = append(os.Environ(), "BGCTL_CONFIG="+configPath)
    
    var stdout, stderr bytes.Buffer
    cmd.Stdout = &stdout
    cmd.Stderr = &stderr
    
    err := cmd.Run()
    return stderr.String(), err
}

func ensureAuthenticated(t *testing.T) {
    t.Helper()
    // Use resource owner password grant for CI automation
    // This is test-only; real users would use device code or browser flow
    username := os.Getenv("BGCTL_TEST_USERNAME")
    password := os.Getenv("BGCTL_TEST_PASSWORD")
    
    if username == "" || password == "" {
        t.Skip("BGCTL_TEST_USERNAME and BGCTL_TEST_PASSWORD required for auth tests")
    }
    
    // Authenticate using test helper (ROPC grant)
    token := helpers.GetOIDCToken(t, username, password)
    injectToken(t, token)
}
```

### CI Matrix Testing

```yaml
# .github/workflows/ci.yml
jobs:
  cli-e2e:
    strategy:
      matrix:
        os: [ubuntu-latest, macos-latest]
        go: ['1.23']
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version: ${{ matrix.go }}
      
      - name: Build bgctl
        run: make build-bgctl
      
      - name: Run CLI unit tests
        run: go test -v ./pkg/bgctl/...
      
      - name: Run CLI E2E tests (requires cluster)
        if: matrix.os == 'ubuntu-latest'  # E2E only on Linux
        run: |
          # Setup Kind clusters (reuse existing e2e setup)
          ./e2e/kind-setup-multi.sh
          
          # Run CLI E2E tests
          go test -v ./e2e/cli/... -tags=e2e -timeout 30m
```

### Golden File Testing

For output format verification, we use golden files with regex matching and templating
to handle non-deterministic values:

```go
// e2e/cli/golden_test.go
func TestGoldenFiles(t *testing.T) {
    tests := []struct {
        name     string
        args     []string
        useRegex bool  // Use regex matching for timestamps/IDs
    }{
        {"escalation-list-table", []string{"escalation", "list", "-o", "table"}, false},
        {"session-list-with-timestamps", []string{"session", "list", "--mine", "-o", "table"}, true},
        {"config-view", []string{"config", "view"}, false},
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            output := runBgctlWithAuth(t, tt.args...)
            
            goldenPath := filepath.Join("testdata", tt.name+".golden")
            if *update {
                // Sanitize output before saving (replace timestamps/IDs with placeholders)
                sanitized := sanitizeOutput(output)
                os.WriteFile(goldenPath, []byte(sanitized), 0644)
                return
            }
            
            expected, err := os.ReadFile(goldenPath)
            require.NoError(t, err)
            
            if tt.useRegex {
                // Use regex matching for dynamic content
                assertRegexMatch(t, string(expected), output)
            } else {
                assert.Equal(t, string(expected), output)
            }
        })
    }
}

// sanitizeOutput replaces dynamic values with placeholders
func sanitizeOutput(s string) string {
    // Replace timestamps: 2026-01-15 10:30:00 → {{TIMESTAMP}}
    s = regexp.MustCompile(`\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}`).ReplaceAllString(s, "{{TIMESTAMP}}")
    // Replace session IDs: session-abc123 → session-{{ID}}
    s = regexp.MustCompile(`session-[a-z0-9]+`).ReplaceAllString(s, "session-{{ID}}")
    // Replace token expiry: expires in 1h30m → expires in {{DURATION}}
    s = regexp.MustCompile(`expires in \d+[hms]+`).ReplaceAllString(s, "expires in {{DURATION}}")
    return s
}

// assertRegexMatch treats {{PLACEHOLDER}} as .+ regex patterns
func assertRegexMatch(t *testing.T, pattern, actual string) {
    t.Helper()
    // Convert {{PLACEHOLDER}} to regex: {{TIMESTAMP}} → \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}
    regexPattern := pattern
    regexPattern = strings.ReplaceAll(regexPattern, "{{TIMESTAMP}}", `\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}`)
    regexPattern = strings.ReplaceAll(regexPattern, "{{ID}}", `[a-z0-9]+`)
    regexPattern = strings.ReplaceAll(regexPattern, "{{DURATION}}", `\d+[hms]+`)
    
    matched, err := regexp.MatchString(regexPattern, actual)
    require.NoError(t, err)
    assert.True(t, matched, "Output does not match expected pattern")
}
```

**Golden file example** (`testdata/session-list-with-timestamps.golden`):
```
NAME              CLUSTER         USER              STATE     CREATED               EXPIRES
session-{{ID}}    prod-cluster-1  user@example.com  Pending   {{TIMESTAMP}}         -
session-{{ID}}    staging-01      user@example.com  Approved  {{TIMESTAMP}}         {{TIMESTAMP}}
```

### Makefile Targets

```makefile
# Makefile additions
.PHONY: build-bgctl test-cli test-cli-e2e

build-bgctl:
	CGO_ENABLED=0 go build -o bin/bgctl ./cmd/bgctl

test-cli:
	go test -v ./pkg/bgctl/...

test-cli-e2e:
	go test -v ./e2e/cli/... -tags=e2e -timeout 30m

# Update golden files
test-cli-golden-update:
	go test -v ./e2e/cli/... -tags=e2e -update
```

---

## Documentation

1. **Man Pages**: Generated from Cobra commands
2. **Online Docs**: Markdown docs in `docs/cli/`
3. **Built-in Help**: `bgctl help`, `bgctl session --help`
4. **Examples**: Embedded in command help text

---

## Release Plan

### v0.1.0 (MVP)
- Config management
- Authentication (browser OIDC)
- Session commands (list, get, request, approve, reject, withdraw)
- Escalation commands (list, get)
- Table and JSON output
- Basic E2E tests in CI

**v0.x Stability Warning**: Pre-1.0 releases may include breaking changes following semantic versioning.
Each release will include prominent warnings about API stability:
```bash
bgctl version
# bgctl v0.2.0 (commit: abc123, built: 2026-02-15T10:00:00Z)
# ⚠ WARNING: Pre-1.0 version - API may change between releases
# ⚠ See CHANGELOG.md for breaking changes before upgrading
```

### v0.2.0
- Debug session support
- Device code authentication
- Shell completion with caching
- Watch command (polling-based)
- Self-update functionality with rollback
- Token migration to keyring
- Expanded E2E test coverage

### v1.0.0 (Stable Release)
- Full feature parity with UI
- Kubectl debug operations
- Comprehensive documentation
- **Stable API with backward compatibility guarantees**
- Full E2E test suite with golden files
- Multi-session atomic requests
- Context-aware shell completion

---

## Decisions

### Core Design
1. **Name**: `bgctl`
2. **Config Format**: YAML
3. **Go Module Path**: `pkg/bgctl` within this repo
4. **Updater Verification**: SHA256 only (no GPG for v1)
5. **Token Cache Scope**: per OIDC provider
6. **Auth Flows**: browser OIDC + device code + client-credentials
7. **Global Overrides**: `--server` and `--token` may bypass config defaults

### Authentication & Security
8. **Keyring Fallback**: AES-256 with password prompt, supports migration to keyring when available
9. **Token Refresh**: Refreshing a shared OIDC provider refreshes tokens for all contexts using it
10. **Secrets Validation**: Config commands validate that referenced env vars exist
11. **Inline Secrets**: Supported with security warnings (not recommended for production)
12. **Vault Integration**: Not planned for v1

### Multi-Session Workflows
13. **Atomic Multi-Session Requests**: Supported - request access to multiple clusters in one command
    ```bash
    # Request access to multiple clusters atomically
    bgctl session request --cluster prod-1,prod-2,staging-* --group admin --reason "Multi-cluster deployment"
    
    # All sessions must be approved (all-or-nothing for approval workflow)
    # Partial approvals not supported - approvers approve the entire multi-session request
    ```

### Output & Pagination
14. **Wide Output**: All `list` commands support `-o wide` for additional columns
15. **Pagination**: Use `--page N` for paging, `--all` to disable pagination
    - Default page size from config (`page-size: 50`)
    - Output shows: `Showing page 1 of 5 (250 total items)`
16. **List Streaming**: Not planned for v1

### Watch Command
17. **Watch Implementation**: Polling-based (interval configurable, default 2s)
    - WebSocket support deferred to future version
    - Can watch single session or all matching a filter
    - Output shows diffs (what changed) by default, `--show-full` for full object

### Exit Codes (Unix Standard)
18. **Standard Exit Codes**:
    - 0: Success
    - 1: General error
    - 2: Invalid arguments/usage (misuse of shell command)
    - 3: Authentication required/failed
    - 4: Authorization denied (permission error)
    - 5: Resource not found
    - 6: Conflict (e.g., session already exists)
    - 7: Server error (remote service failure)
    - 8: Timeout
    - 9: Configuration error (invalid config file)
    - 64: Command line usage error (EX_USAGE)
    - 130: Interrupted by Ctrl+C (128 + SIGINT)

### Context Management
19. **Context Switching Commands**:
    - `bgctl config set-context <name>` - persistent default change (alias: `use-context`)
    - `bgctl --context <name>` - temporary override for single command

### CI/CD & Automation
20. **Non-Interactive Mode**: `--non-interactive` flag fails instead of prompting (also via `BGCTL_NON_INTERACTIVE=true`)
21. **Service Account Approvals**: Not implemented in v1 - service accounts follow normal approval workflows

### Shell Completion
22. **Context-Aware Completion**: Supported with local caching
    - `bgctl session approve <TAB>` lists pending sessions (from cache if available)
    - Cache refresh on miss or explicit `bgctl completion refresh-cache`
    - Warning shown if cache is stale: `(cached 5m ago, run 'bgctl completion refresh-cache')`

### Flag/Env/Config Precedence
23. **Configuration Precedence**: Flag > Environment Variable > Config File
    ```bash
    # Flag wins over env
    BGCTL_CONTEXT=prod bgctl --context staging session list  # Uses 'staging'
    ```

### Update & Rollback
24. **Update Rollback**: Manual rollback supported
    ```bash
    bgctl update rollback         # Rollback to previous version
    bgctl update rollback --version v1.0.5  # Rollback to specific version
    ```
    - Previous binary renamed to `bgctl.old` during update
    - All versions available in GitHub Releases for manual download

### Debug Sessions
25. **Debug Session Join**: Command removed from v1 - will be added when terminal sharing (tmux) is implemented
26. **Kubectl Debug State**: Session must be in "Active" state, API enforces this requirement

### Testing
27. **Golden Files**: Use regex matching for timestamps/IDs, templating for structured data
28. **E2E Coverage**: Full workflow tests with deterministic fixtures

### Versioning
29. **v0.x Breaking Changes**: Allowed (follows semver) - prominent warnings in release notes and `--version` output
30. **API Compatibility**: Version negotiation not planned for v1 - assume current API version

---

## Appendix: API Endpoint Mapping

| CLI Command | HTTP Method | API Endpoint |
|-------------|-------------|--------------|
| `session list` | GET | `/api/breakglass/breakglassSessions` |
| `session get NAME` | GET | `/api/breakglass/breakglassSessions/{name}` |
| `session request` | POST | `/api/breakglass/breakglassSessions` |
| `session approve NAME` | POST | `/api/breakglass/breakglassSessions/{name}/approve` |
| `session reject NAME` | POST | `/api/breakglass/breakglassSessions/{name}/reject` |
| `session withdraw NAME` | POST | `/api/breakglass/breakglassSessions/{name}/withdraw` |
| `session drop NAME` | POST | `/api/breakglass/breakglassSessions/{name}/drop` |
| `session cancel NAME` | POST | `/api/breakglass/breakglassSessions/{name}/cancel` |
| `escalation list` | GET | `/api/breakglass/breakglassEscalations` |
| `debug session list` | GET | `/api/debugSessions` |
| `debug session get NAME` | GET | `/api/debugSessions/{name}` |
| `debug session create` | POST | `/api/debugSessions` |
| `debug session join NAME` | POST | `/api/debugSessions/{name}/join` |
| `debug session leave NAME` | POST | `/api/debugSessions/{name}/leave` |
| `debug session renew NAME` | POST | `/api/debugSessions/{name}/renew` |
| `debug session terminate NAME` | POST | `/api/debugSessions/{name}/terminate` |
| `debug session approve NAME` | POST | `/api/debugSessions/{name}/approve` |
| `debug session reject NAME` | POST | `/api/debugSessions/{name}/reject` |
| `debug template list` | GET | `/api/debugSessions/templates` |
| `debug template get NAME` | GET | `/api/debugSessions/templates/{name}` |
| `debug pod-template list` | GET | `/api/debugSessions/podTemplates` |
| `debug pod-template get NAME` | GET | `/api/debugSessions/podTemplates/{name}` |
| `debug kubectl inject` | POST | `/api/debugSessions/{name}/injectEphemeralContainer` |
| `debug kubectl copy-pod` | POST | `/api/debugSessions/{name}/createPodCopy` |
| `debug kubectl node-debug` | POST | `/api/debugSessions/{name}/createNodeDebugPod` |
| `config` | GET | `/api/config` |
| `auth login` | GET | `/api/identity-provider` + OIDC flow |

---

## References

- [Breakglass API Reference](../api-reference.md)
- [Debug Session Documentation](../debug-session.md)
- [Breakglass Escalation](../breakglass-escalation.md)
- [Identity Provider](../identity-provider.md)
- [kubectl CLI Design](https://kubernetes.io/docs/reference/kubectl/)
- [gh CLI Design](https://cli.github.com/manual/)
