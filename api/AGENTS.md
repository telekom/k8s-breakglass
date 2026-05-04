# Breakglass API Types — Agent Instructions

This document provides conventions specifically for AI coding agents working in the `api` directory (Kubernetes CRDs).

## Critical Rules
1. **Never Remove Scaffold Comments**: Always preserve `// +kubebuilder:scaffold:*` comments. These are essential for code generation.
2. **Generation Required**: After making any changes to `*_types.go` files, you MUST run `make generate && make manifests` from the project root.
3. **Validation**: Use kubebuilder validation markers (e.g. `//+kubebuilder:validation:Required`, `//+kubebuilder:validation:Enum=...`) on all new fields to enforce API constraints.
4. **Fuzz Testing**: Add cases to `fuzz_test.go` when adding new complex types or validations.
5. **Backwards Compatibility**: Do not make backwards-incompatible changes to `v1alpha1` unless absolutely necessary and documented in the CHANGELOG.
