---
section: Features
---

- Opt-in incremental flush of terminal recordings
  (`artifacts.terminalRecordingSegmentBytes`, default off): the recording is
  persisted in segments while the stream runs, which bounds per-stream memory.
  After a controller crash the artifact controller publishes the committed
  prefix as incomplete evidence and audits it with `recovered: true`. The audit
  schema gains the optional `recovered` field and the `flush` stage (#1737).
