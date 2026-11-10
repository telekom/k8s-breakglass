---
section: Behaviour changes
---

- Terminal recording (`DebugSessionTemplate.spec.audit.enableTerminalRecording`)
  now works end to end on the server: the controller publishes the connection
  credential generation bound to the target ClusterConfig credential Secret UID
  and resourceVersion, and rotates it when that Secret changes. Streams emit
  `debug_session.terminal_recording_started`, `_finalized` and `_failed` audit
  events. Templates without the flag are unchanged; ClusterConfigs without a
  credential Secret and controllers without an artifact backend still fail
  closed (#1486).
