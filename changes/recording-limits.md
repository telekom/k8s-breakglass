---
section: Added
---

- New optional `artifacts.terminalRecordingMaxBytes` and
  `artifacts.terminalRecordingMaxConcurrent` settings make the terminal
  recording size cap and per-replica concurrent stream limit configurable.
  Defaults keep current behaviour (`uploadMaxBytes`, 2 streams); out-of-range
  values are rejected at startup (#1741).
