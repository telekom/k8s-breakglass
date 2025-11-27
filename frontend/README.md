# breakglass

This template should help get you started developing with Vue 3 in Vite.

## Recommended IDE Setup

[VSCode](https://code.visualstudio.com/) + [Volar](https://marketplace.visualstudio.com/items?itemName=johnsoncodehk.volar) (and disable Vetur) + [TypeScript Vue Plugin (Volar)](https://marketplace.visualstudio.com/items?itemName=johnsoncodehk.vscode-typescript-vue-plugin).

## Type Support for `.vue` Imports in TS

TypeScript cannot handle type information for `.vue` imports by default, so we replace the `tsc` CLI with `vue-tsc` for type checking. In editors, we need [TypeScript Vue Plugin (Volar)](https://marketplace.visualstudio.com/items?itemName=johnsoncodehk.vscode-typescript-vue-plugin) to make the TypeScript language service aware of `.vue` types.

If the standalone TypeScript plugin doesn't feel fast enough to you, Volar has also implemented a [Take Over Mode](https://github.com/johnsoncodehk/volar/discussions/471#discussioncomment-1361669) that is more performant. You can enable it by the following steps:

1. Disable the built-in TypeScript Extension
    1) Run `Extensions: Show Built-in Extensions` from VSCode's command palette
    2) Find `TypeScript and JavaScript Language Features`, right click and select `Disable (Workspace)`
2. Reload the VSCode window by running `Developer: Reload Window` from the command palette.

## Customize configuration

See [Vite Configuration Reference](https://vitejs.dev/config/).

## Project Setup

```sh
npm install
```

### Compile and Hot-Reload for Development

```sh
npm run dev
```

Mock authentication is enabled automatically for all Vite dev builds so the UI can log in instantly
without contacting a real identity provider. To exercise the full OIDC flow against a real backend run:

```sh
npm run dev:real
```

or prefix the dev command with `VITE_USE_MOCK_AUTH=false`.

### Run the mock UI workspace (no backend required)

```sh
npm run dev:mock
```

This command starts the lightweight mock API server (`mock-api/server.mjs`) together with Vite. Mock
authentication is already on by default in dev mode, so when you click **Log in** the UI skips real
OIDC redirects and immediately issues a synthetic token/profile so that delegated approval
flows, request creation, and multi-IDP selection all behave as if a real user signed in.

The frontend proxies `http://localhost:5173/api/*` traffic to `http://localhost:8080`, so any
changes you make to Vue components or the mock data refresh instantly without rebuilding a
container. The mock backend preloads sample breakglass escalations, sessions, and multi-IDP data
so you can tweak UI layouts WYSIWYG-style.

### Switching UI flavours locally

Need to preview the Telekom theme versus the OSS/neutral look without touching the mock data? Use
one of the following quick overrides while running any dev server (`npm run dev`, `dev:mock`, or
`dev:real`):

- **Query parameter** – Append `?flavour=telekom` or `?flavour=oss` to the dev URL
  (`http://localhost:5173/?flavour=telekom`). The chosen value is persisted to
  `localStorage` (`k8sBreakglassUiFlavourOverride`) so you can refresh without retyping it.
- **Reset override** – Append `?flavour=reset` (or `clear`, `default`, `auto`) to remove the stored
  value and fall back to whatever the backend delivers.

These overrides are resolved entirely in the browser; no backend changes are required and you can
flip the theme in seconds when demoing or iterating on styles.

#### Mock API coverage

The dataset includes:

- All session states: `Pending`, `Approved`, `Rejected`, `Withdrawn`, `Dropped`, `Expired`, `Timeout`,
  `ApprovalTimeout`, and `WaitingForScheduledTime`
- Variations for scheduled sessions (future/past start), mandatory/optional request & approval reasons,
  Keycloak/Azure/no-IDP flows, and owner/approver combinations
- Escalations with single and multi-cluster targeting, single- and multi-group requesters, and dozens of
  approver group chips for stress testing UI layouts
- Scale-testing hook: append `?mockScale=250` (or `scaleCount` / `total`) to `/api/breakglassSessions` to
  generate synthetic records without editing the seed data

Edit `frontend/mock-api/data.mjs` if you want to pin additional permutations. The Node `--watch` flag reloads the
Express server automatically after each save.

### Type-Check, Compile and Minify for Production

```sh
npm run build
```

### Lint with [ESLint](https://eslint.org/)

```sh
npm run lint
```

## State Management Architecture

The frontend uses a **state-first validation approach** where:

### Session State Handling

- **State is Ultimate Authority** - Use the `state` field to determine session validity, not timestamps
- **Terminal States** - Sessions in states `Rejected`, `Withdrawn`, `Expired`, or `ApprovalTimeout` are never valid
- **Approved State Only Valid** - Only sessions with `state: Approved` can grant access (if not expired)
- **Timestamp Preservation** - Timestamps are preserved during state transitions for audit history

### UI Components

The `BreakglassSessionCard` component displays session state and timestamps with proper semantics:

```vue
<!-- State display -->
<span :class="'state state-' + (breakglass.status.state || 'unknown').toLowerCase()">
  {{ breakglass.status.state || 'Unknown' }}
</span>

<!-- Terminal state timestamps -->
<p v-if="rejectedAt"><b>Rejected at:</b> {{ rejectedAt }}</p>
<p v-if="withdrawnAt"><b>Withdrawn at:</b> {{ withdrawnAt }}</p>

<!-- Preserved audit timestamps -->
<p v-if="approvedAt"><b>Approved at:</b> {{ approvedAt }}</p>
```

### State Display Styles

```scss
.state {
  font-weight: bold;
  padding: 0.1em 0.5em;
  border-radius: 0.3em;
}
.state-approved  { color: #1565c0; background: #e3f2fd; }  // Blue
.state-rejected  { color: #b71c1c; background: #ffebee; }  // Red
.state-withdrawn { color: #616161; background: #f5f5f5; }  // Gray
.state-timeout   { color: #f9a825; background: #fffde7; }  // Yellow
.state-unknown   { color: #757575; background: #f5f5f5; }  // Gray
```

### API Integration

When calling the backend API:

```typescript
// List sessions by state (state-first filtering)
GET /api/breakglass/breakglassSessions?state=approved,pending

// The API response includes:
// - state: The current state (Pending, Approved, Rejected, Withdrawn, Expired, ApprovalTimeout)
// - timestamps: All preserved timestamps (createdAt, approvedAt, rejectedAt, withdrawnAt, etc.)
// - Validity checks are done server-side using isSessionValid()
```

#### Response Example

```json
{
  "apiVersion": "breakglass.t-caas.telekom.com/v1alpha1",
  "kind": "BreakglassSession",
  "metadata": {
    "name": "session-abc123",
    "creationTimestamp": "2024-01-15T10:30:00Z"
  },
  "spec": {
    "cluster": "prod-cluster",
    "user": "user@example.com",
    "grantedGroup": "cluster-admin"
  },
  "status": {
    "state": "Approved",
    "createdAt": "2024-01-15T10:30:00Z",
    "approvedAt": "2024-01-15T10:31:00Z",
    "expiresAt": "2024-01-15T11:31:00Z",
    "retainedUntil": "2024-02-14T10:31:00Z"
  }
}
```

### Validation Logic

The frontend should **never** implement its own session validity logic. Instead:

1. Display the session state from the API response
2. Show all timestamps for audit trail
3. Let the backend (via `isSessionValid()`) determine if a session is valid
4. Render UI based on state + backend response codes (e.g., 403 for invalid access)

