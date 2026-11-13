---
section: Behaviour changes
---

- The HTTPS server reloads `server.tlsCertFile`/`server.tlsKeyFile` and
  `server.clientCAFile` when they change, so a rotated certificate or client
  CA is used for new connections without a pod restart. Set
  `server.tlsReloadDisabled: true` to keep reading them once at startup; this
  opt-out is transitional and will be removed in a future release.
