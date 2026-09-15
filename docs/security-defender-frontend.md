# Frontend security hardening

The optional `frontend/mock-api/` server is a local development fixture. It uses synthetic,
in-memory records and a fixed mock identity, performs no Kubernetes operations, and is excluded
from the production runtime image. Its generated scale dataset is capped at 1,000 records.

OIDC refresh tokens are removed from the loaded user before persistence. If the sanitized write
fails, the in-memory user remains stripped and the service attempts to remove the persisted user as
a fail-closed cleanup. If that cleanup also fails, an older persisted value may remain and requires
fresh authentication or storage recovery; the code cannot promise that the token was never
temporarily persisted by the OIDC library before the loaded-user event. The SPA still needs its
access token to call the API; this change keeps refresh tokens out of the exported user state on
the failure path.

Approval view failures use `handleAxiosError`, which strips Axios request configuration that may
contain bearer headers before logging; non-Axios errors and backend messages retain their existing
logging behavior.

Regression checks:

Run these commands from the repository root:

- `(cd frontend && npm test -- --run tests/unit/auth.spec.ts tests/unit/views/SessionApprovalView.spec.ts)`
- `(cd frontend && npm test -- --run tests/unit/components/App.spec.ts)`
- `(cd frontend && node --test mock-api/data.test.mjs)`
- `(cd frontend && npm run typecheck)`
