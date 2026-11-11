---
section: Breaking changes
---

- Go API of `github.com/telekom/k8s-breakglass/pkg/bgctl/client`:
  `InjectEphemeralContainerRequest.SecurityContext` is now
  `*corev1.SecurityContext` instead of `map[string]interface{}`. Callers that
  built the map must build a `corev1.SecurityContext`; the JSON sent to the
  hub is unchanged (#1667).
