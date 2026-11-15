---
section: Behaviour changes
---

- The UI ends its session when the identity provider session ends (OIDC
  Session Management through `check_session_iframe`); before, it stayed signed
  in until the access token expired. Where the browser hides the identity
  provider cookie from the iframe (blocked third-party cookies), the UI keeps
  the previous behaviour and logs a warning. Set `frontend.monitorSession:
  false` to turn monitoring off; this opt-out is transitional and will be
  removed in a future release. See `docs/configuration-reference.md`.
