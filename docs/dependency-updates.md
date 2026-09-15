# Kubernetes dependency updates

After updating Kubernetes or controller-runtime dependencies, run `make generate && make manifests` with the repository's Go toolchain and controller-gen version. Embedded upstream Kubernetes types can change generated CRD schemas and apply-configuration parser models even when local API declarations have not changed.

The certificate-manager test double implements controller-runtime's combined event recorder, including annotated events. `go test ./pkg/cert` verifies that it continues to satisfy the manager interface during dependency updates.
