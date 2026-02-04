# Breakglass CLI (bgctl)

The `bgctl` CLI provides terminal access to the Breakglass API for automation and scripting. It offers full feature parity with the web UI, enabling session management, debug sessions, escalation queries, and kubectl-debug operations.

## Features

- **Session Management** - Request, approve, reject, withdraw sessions
- **Debug Sessions** - Create and manage debug sessions with kubectl-debug operations
- **Escalation Queries** - List and view available escalations
- **Multi-Context Support** - Manage multiple Breakglass instances
- **OIDC Authentication** - Browser-based, device code, and client credentials flows
- **Multiple Output Formats** - Table (default), JSON, YAML, wide
- **Pagination** - Built-in pagination with `--page` and `--page-size` flags
- **Watch Mode** - Monitor session changes in real-time
- **Shell Completion** - Bash, zsh, fish, powershell
- **Self-Update** - Update to latest release with rollback support

## Installation

### Option 1: Build from Source

```bash
make build-bgctl
./bin/bgctl version
```

### Option 2: Download Pre-built Binary

```bash
# Example: macOS (Apple Silicon)
curl -LO https://github.com/telekom/k8s-breakglass/releases/latest/download/bgctl_darwin_arm64.tar.gz
curl -LO https://github.com/telekom/k8s-breakglass/releases/latest/download/bgctl_darwin_arm64.tar.gz.sha256

# Verify checksum
shasum -a 256 -c bgctl_darwin_arm64.tar.gz.sha256

# Extract and install
tar xzf bgctl_darwin_arm64.tar.gz
sudo mv bgctl /usr/local/bin/
chmod +x /usr/local/bin/bgctl
```

Available binaries for each release:
- `bgctl_linux_amd64.tar.gz`
- `bgctl_linux_arm64.tar.gz`
- `bgctl_darwin_amd64.tar.gz`
- `bgctl_darwin_arm64.tar.gz`
- `bgctl_windows_amd64.zip`
- `bgctl_windows_arm64.zip`

## Quick Start

```bash
# Initialize config
bgctl config init \
  --server https://breakglass.example.com \
  --oidc-authority https://idp.example.com/realms/prod \
  --oidc-client-id bgctl

# Authenticate
bgctl auth login

# List sessions
bgctl session list --mine

# Request a session
bgctl session request \
  --cluster prod-1 \
  --group breakglass-admin \
  --reason "Incident INC-12345"
```

## Output Formats

```bash
bgctl session list -o json
bgctl escalation list -o yaml
bgctl session list -o wide
```

## Pagination

```bash
bgctl session list --page 2 --page-size 25
bgctl debug session list --all
```

## Debug Sessions

```bash
# List debug sessions
bgctl debug session list

# Create a debug session
bgctl debug session create \
  --template standard-debug \
  --cluster prod-1 \
  --duration 1h \
  --reason "Investigate outage"

# Create with scheduling option and custom namespace
bgctl debug session create \
  --template network-debug \
  --cluster prod-1 \
  --duration 2h \
  --reason "Network analysis" \
  --scheduling-option sriov \
  --target-namespace debug-netops

# Approve a debug session
bgctl debug session approve SESSION_NAME --reason "Approved"
```

## Debug Templates and Bindings

Manage debug session templates and their cluster bindings:

```bash
# List available templates
bgctl debug template list

# Get template details
bgctl debug template get standard-debug

# List available clusters for a template
bgctl debug template clusters standard-debug

# Filter by environment or location
bgctl debug template clusters standard-debug --environment production
bgctl debug template clusters standard-debug --location eu-west-1

# Wide output with constraints
bgctl debug template clusters standard-debug -o wide
```

### Cluster Bindings

ClusterBindings control which templates are available on which clusters with what constraints:

```bash
# List all cluster bindings
bgctl debug binding list

# Filter by namespace, template, or cluster
bgctl debug binding list -n debug-system
bgctl debug binding list --template standard-debug
bgctl debug binding list --cluster prod-1

# Get binding details
bgctl debug binding get my-binding -n debug-system

# List bindings that apply to a specific cluster
bgctl debug binding for-cluster prod-1
```

## Kubectl Debug Operations

```bash
bgctl debug kubectl inject SESSION_NAME \
  --namespace default \
  --pod api-7d9c \
  --image alpine:3.20

bgctl debug kubectl copy-pod SESSION_NAME \
  --namespace default \
  --pod api-7d9c

bgctl debug kubectl node-debug SESSION_NAME \
  --node worker-1
```

## Watch Mode

Watch for real-time session state changes (polling-based, 2-second interval by default):

```bash
# Watch all sessions you can approve
bgctl session watch --approver --interval 2s

# Watch your own sessions
bgctl session watch --mine --interval 2s

# Show full session JSON on changes
bgctl session watch --mine --show-full

# Watch debug sessions
bgctl debug session watch --cluster prod-1
```

## Configuration Management

```bash
# View current configuration
bgctl config view

# List contexts
bgctl config get-contexts
#  * production    https://breakglass.example.com
#    staging       https://breakglass-staging.example.com

# Switch context
bgctl config use-context staging

# Add new context
bgctl config add-context my-context \
  --server https://breakglass.mycompany.com \
  --oidc-provider corporate-keycloak

# Add OIDC provider (reusable across contexts)
bgctl config add-oidc-provider corporate-keycloak \
  --authority https://keycloak.corp.example.com/realms/platform \
  --client-id bgctl \
  --grant-type authorization-code
```

## Authentication

```bash
# Login with browser (default)
bgctl auth login

# Login with device code (for SSH sessions)
bgctl auth login --device-code

# Check authentication status
bgctl auth status

# Logout (remove cached token)
bgctl auth logout
```

## Global Flags

All commands support these flags:

- `--context` / `-c` - Override current context
- `--output` / `-o` - Output format: `table`, `json`, `yaml`, `wide`
- `--config` - Path to config file (default: `~/.config/bgctl/config.yaml`)
- `--server` - Override server URL (bypasses context)
- `--token` - Bearer token override (bypasses OIDC)
- `--verbose` / `-v` - Enable verbose output with correlation IDs for debugging (writes to stderr)
- `--page` - Page number for paginated output
- `--page-size` - Items per page
- `--all` - Disable pagination
- `--non-interactive` - Fail instead of prompting for input

### Environment Variables

Global flags can also be set via environment variables:

- `BGCTL_CONTEXT` - Context name override
- `BGCTL_OUTPUT` - Output format
- `BGCTL_SERVER` - Server URL override
- `BGCTL_TOKEN` - Bearer token override
- `BGCTL_VERBOSE` - Set to `true` to enable verbose logging (output goes to stderr)
- `BGCTL_NON_INTERACTIVE` - Set to `true` to disable interactive prompts

## Shell Completion

```bash
# Bash
bgctl completion bash > /etc/bash_completion.d/bgctl
source ~/.bashrc

# Zsh
bgctl completion zsh > "${fpath[1]}/_bgctl"

# Fish
bgctl completion fish > ~/.config/fish/completions/bgctl.fish

# PowerShell
bgctl completion powershell > bgctl.ps1
```

## Self-Update

```bash
# Check for updates
bgctl update check

# Update to latest version
bgctl update

# Update to specific version
bgctl update --version v1.2.0

# Rollback to previous version
bgctl update rollback
```

## Exit Codes

- `0` - Success
- `1` - General error
- `2` - Invalid arguments/usage
- `3` - Authentication required/failed
- `4` - Authorization denied
- `5` - Resource not found
- `6` - Conflict
- `7` - Server error
- `8` - Timeout

## Environment Variables

- `BGCTL_CONFIG` - Path to config file
- `BGCTL_CONTEXT` - Default context
- `BGCTL_OUTPUT` - Default output format
- `BGCTL_SERVER` - Override server URL
- `BGCTL_TOKEN` - Bearer token override
- `BGCTL_NON_INTERACTIVE` - Fail instead of prompting (for CI/CD)
- `BGCTL_DISABLE_UPDATE` - Disable self-update feature

## Examples

### Request and Approve a Session

```bash
# As requester
bgctl session request \
  --cluster prod-cluster-1 \
  --group cluster-admin \
  --reason "Emergency patching for CVE-2024-12345" \
  -o json | jq -r '.metadata.name'
# Output: session-abc123

# As approver
bgctl session list --approver --state pending -o wide
bgctl session approve session-abc123 --reason "Approved for emergency maintenance"
```

### Debug a Pod

```bash
# Create debug session
bgctl debug session create \
  --template standard-debug \
  --cluster prod-1 \
  --duration 1h \
  --reason "Investigate memory leak in api-server"

# Create debug session with specific scheduling and namespace
bgctl debug session create \
  --template network-debug \
  --cluster prod-1 \
  --duration 2h \
  --reason "Network analysis" \
  --scheduling-option sriov-nodes \
  --target-namespace debug-netops

# Approve (if required)
bgctl debug session approve DEBUG_SESSION_NAME

# Inject ephemeral container
bgctl debug kubectl inject DEBUG_SESSION_NAME \
  --namespace production \
  --pod api-7d9c4f8b-xkj2p \
  --image alpine:3.20 \
  --container-name debug

# Then use kubectl exec to attach
kubectl exec -it api-7d9c4f8b-xkj2p -c debug -n production -- sh
```

### Debug Session Create Flags

| Flag | Description |
|------|-------------|
| `--template` | (Required) Debug session template name |
| `--cluster` | (Required) Target cluster name |
| `--duration` | Requested duration (e.g., `1h`, `2h`, `1d`) |
| `--reason` | Reason for the debug session request |
| `--scheduling-option` | Scheduling option name from template (e.g., `sriov`, `standard`) |
| `--target-namespace` | Namespace where debug pods will be deployed |
| `--invite` | Users to invite as participants (can be repeated) |
| `--set` | Set template variable value (key=value), can be repeated |
| `--binding` | Binding reference (namespace/name or name) when multiple bindings exist |

### Using Template Variables

When a debug session template defines `extraDeployVariables`, you can provide values using the `--set` flag:

```bash
# Create session with template variables
bgctl debug session create \
  --template network-debug \
  --cluster production \
  --set logLevel=debug \
  --set enableTracing=true \
  --set captureSize=1000
```

### Automation with JSON Output

```bash
#!/bin/bash
# Check for pending sessions and notify
PENDING=$(bgctl session list --approver --state pending -o json)
COUNT=$(echo "$PENDING" | jq 'length')

if [ "$COUNT" -gt 0 ]; then
  echo "You have $COUNT pending approval(s)"
  echo "$PENDING" | jq -r '.[] | "\(.metadata.name): \(.spec.user) → \(.spec.grantedGroup)"'
fi
```

## Troubleshooting

### Config Not Found

```bash
# Initialize a new config
bgctl config init \
  --server https://breakglass.example.com \
  --oidc-authority https://idp.example.com/realms/prod \
  --oidc-client-id bgctl
```

### Authentication Failed

```bash
# Re-authenticate
bgctl auth logout
bgctl auth login

# Check token status
bgctl auth status
```

### Connection Refused

```bash
# Verify server URL
bgctl config view | grep server

# Test connectivity
curl -k https://breakglass.example.com/health
```

## Further Reading

- [Breakglass CLI Proposal](./proposals/cli-tool.md) - Full design document
- [API Reference](./api-reference.md) - REST API endpoints
- [BreakglassSession CRD](./breakglass-session.md) - Session lifecycle

## Watch

```bash
bgctl session watch --mine --interval 2s
bgctl debug session watch --state Active
```

## Updates & Completion

```bash
bgctl update check
bgctl update

bgctl completion bash > ~/.bash_completion
```

## Notes

- Use `--context` to switch between configured instances.
- Tokens are cached per OIDC provider in the user config directory.
- Device code and client-credentials flows are supported via OIDC provider config.