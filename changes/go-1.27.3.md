---
section: Security
---

- Build the controller, `bgctl` and the utility images with Go 1.27.3. Go
  1.27.2 is affected by GO-2026-6809 in `crypto/x509`, which is reachable
  through certificate verification (#1545).
