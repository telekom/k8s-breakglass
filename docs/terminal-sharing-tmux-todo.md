# Terminal Sharing with tmux - Work in Progress

## Current Status

The terminal sharing feature with tmux provider is **temporarily disabled** in E2E tests due to infrastructure requirements.

## Issue

Debug sessions that enable terminal sharing with `Provider: "tmux"` fail when using standard container images (e.g., `busybox`, `alpine`) because these images do not include the `tmux` binary.

**Error observed:**
```
Error: failed to create containerd task: failed to create shim task: OCI runtime create failed: 
runc create failed: unable to start container process: error during container init: 
exec: "tmux": executable file not found in $PATH
```

## What Works

- **Terminal sharing feature itself**: The API, CRDs, and reconciler logic for terminal sharing are fully implemented
- **Debug sessions without tmux**: Debug sessions work correctly when terminal sharing is disabled or when Provider is not set to "tmux"

## What Needs Work

### 1. Custom Debug Pod Images

Create dedicated debug pod images that include:
- `tmux` binary
- Common debugging tools (curl, netcat, etc.)
- Appropriate entrypoint for interactive shells

**Example Dockerfile:**
```dockerfile
FROM alpine:latest
RUN apk add --no-cache \
    tmux \
    bash \
    curl \
    bind-tools \
    netcat-openbsd \
    && rm -rf /var/cache/apk/*
ENTRYPOINT ["/bin/bash"]
```

### 2. Update DebugPodTemplate Examples

Update sample templates in `config/samples/` to reference images with tmux:
- `debug-pod-template-network.yaml` → use custom network debug image
- `debug-pod-template-minimal.yaml` → use lightweight image with tmux
- `debug-pod-template-log-inspector.yaml` → use image with log tools + tmux

### 3. Test Updates Required

Files that have tmux temporarily disabled (search for "TODO: Re-enable tmux"):
- `e2e/api/functional_verification_test.go`
- `e2e/api/debug_session_advanced_test.go`
- `e2e/kubectl_debug_test.go`
- `e2e/debug_session_e2e_test.go`

Once custom images are available:
1. Uncomment the `// Provider: "tmux"` lines
2. Update `DebugPodTemplate` definitions to use the custom image
3. Re-enable tmux provider assertions in tests

### 4. Documentation Updates

After implementation:
- Update `docs/debug-session.md` with tmux usage examples
- Document custom image requirements in `docs/advanced-features.md`
- Add troubleshooting section for tmux-related issues

## Temporary Workaround

For now, terminal sharing tests run **without** explicitly setting the tmux provider. The feature is enabled (`Enabled: true`) but the Provider field is commented out, allowing the reconciler to use default behavior.

## Related Files

- Core implementation: `pkg/breakglass/debug_session_*.go`
- API types: `api/v1alpha1/debug_session_types.go`
- Test fixtures: `e2e/**/*test.go` (search for "tmux")

## Next Steps

1. Build and publish custom debug images to a container registry
2. Update `DebugPodTemplate` samples and test fixtures to reference these images
3. Re-enable tmux provider in E2E tests
4. Validate full terminal sharing workflow with tmux
5. Update documentation with complete usage examples
