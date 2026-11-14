---
section: Upgrade notes
---

- Apply the CRDs before the controller: `DebugSessionTemplate` has the new
  opt-in field `trafficMirror` and `DebugSession` the new `spec.trafficMirror`
  and `status.trafficMirror` (session-scoped traffic mirroring). Mirror Pods
  run in the existing `breakglass-node-maintenance` namespace with `hostPID`
  and `NET_ADMIN`, `SYS_ADMIN`, `SYS_PTRACE`; admit them there before
  enabling a template. `--disable-traffic-mirror` refuses new mirrors.
