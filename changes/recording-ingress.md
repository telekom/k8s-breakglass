---
section: Features
---

- Recorded terminals through ingress-nginx: the opt-in kustomize component
  `config/components/streaming-ingress` sets the streaming annotations (and
  disables the HTTPRoute timeouts with Gateway API). The controller names the
  recording in the new response header `X-Breakglass-Recording-Pending-ID`, and
  `bgctl debug terminal` reads the outcome from the recording listing when a
  proxy drops the response trailers. Also set `client-body-timeout` in the
  ingress-nginx ConfigMap (#1744).
