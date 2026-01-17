# Terminal Sharing with tmux - Enabled

## Current Status

The terminal sharing feature with tmux provider is **enabled** in E2E tests using a dedicated debug image that includes tmux.

## Requirement

Debug sessions that enable terminal sharing with `Provider: "tmux"` require a debug image that includes the `tmux` binary.

**Error observed:**
```
Error: failed to create containerd task: failed to create shim task: OCI runtime create failed: 
runc create failed: unable to start container process: error during container init: 
exec: "tmux": executable file not found in $PATH
```

## What's Enabled

- **Terminal sharing feature**: API, CRDs, and reconciler logic are fully implemented and tested
- **Tmux image support**: E2E builds use a tmux-enabled debug image defined in this repo

## Implementation

- **Tmux debug image**: [e2e/images/tmux-debug/Dockerfile](../e2e/images/tmux-debug/Dockerfile)
- **Build hook**: E2E setup scripts build and preload the tmux image into kind clusters
- **Tests updated**: Terminal sharing E2E cases now set `Provider: "tmux"` and assert the provider

## Related Files

- Core implementation: `pkg/breakglass/debug_session_*.go`
- API types: `api/v1alpha1/debug_session_types.go`
- Test fixtures: `e2e/**/*test.go` (search for "tmux")

## Next Steps

1. Publish the tmux debug image to a registry (optional)
2. Update sample DebugPodTemplate manifests if a public image is published
3. Add a troubleshooting entry for missing tmux in custom images
