---
section: Fixes
---

- A terminal recording stream whose input or output can no longer be recorded
  (byte limit reached) now ends at once with incomplete evidence, instead of
  leaving the target running with its output silently dropped until the session
  expired (#1742).
