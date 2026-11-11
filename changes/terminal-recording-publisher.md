---
section: Behaviour changes
---

- Terminal recording (`DebugSessionTemplate.spec.audit.enableTerminalRecording`)
  now works end to end on the server: the controller publishes the connection
  credential generation bound to all hub credential and trust inputs of the
  target ClusterConfig and rotates it when any of them changes (including
  metadata-only updates, which abort active recorded streams). Streams require
  an enabled `AuditConfig` and emit `debug_session.terminal_recording_started`,
  `_finalized`, `_failed` and `_accessed` audit events. Templates without the
  flag are unchanged; ClusterConfigs without a credential Secret and
  controllers without an artifact backend or audit pipeline still fail closed
  (#1486).
