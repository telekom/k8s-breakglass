---
section: Upgrade notes
---

- Terminal recording credential rotation can now be blue/green (TCAAS-1633):
  - New config `artifacts.credentialRotationGrace` (for example `30s`, maximum `15m`) keeps running streams on the retired credential generation until the grace deadline; new streams bind to the new generation immediately.
  - The default `0s` keeps today's behaviour: rotation aborts running streams. No action is needed on upgrade.
