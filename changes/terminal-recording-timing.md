---
section: Upgrade notes
---

- Apply the CRDs before the controller: `DebugSessionArtifact`
  `spec.recording.formatVersion` now accepts `2`. New terminal recordings use
  framing version 2 with monotonic per-frame timing and resize frames; version 1
  artifacts remain verifiable. New `bgctl debug terminal` and
  `bgctl debug recordings list|get|verify|export` commands (#1486).
