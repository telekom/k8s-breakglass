---
section: Upgrade notes
---

- Local diagnostic artifact storage can now be provisioned through a supported path (#1659):
  - `breakglass artifacts provision` provisions an empty volume from the controller config.
  - The opt-in kustomize component `config/components/artifact-local-provision` runs it as a one-shot Job.

  Controller startup still never provisions, so empty, replaced or repointed volumes keep failing closed. Volumes that are already provisioned are unaffected.
