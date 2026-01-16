# Logging and Debugging

This document describes the logging infrastructure in the Breakglass Controller application, covering both backend (Go) and frontend (TypeScript/Vue) components.

## Frontend Logging

### Logger Service

The frontend uses a centralized logging service (`services/logger-console.ts`) that provides structured, environment-aware logging:

**Features:**
- Environment-aware log levels (development vs production)
- Structured JSON context for better debugging
- Automatic timestamping
- Component-based logging with consistent formatting
- Exposed globally as `window.logger` for browser console debugging

**Usage:**

```typescript
import logger from '@/services/logger-console';

// Basic logging
logger.debug('ComponentName', 'Debug message', { data: value });
logger.info('ComponentName', 'Info message', { data: value });
logger.warn('ComponentName', 'Warning message', { data: value });
logger.error('ComponentName', 'Error message', error, { context: value });

// Specialized logging
logger.request('ComponentName', 'GET', '/api/endpoint', requestData);
logger.response('ComponentName', 'GET', '/api/endpoint', 200, responseData);
logger.action('ComponentName', 'User clicked button', { buttonId: 'submit' });
logger.stateChange('ComponentName', 'idle', 'loading', 'User initiated action');
```

**Log Levels:**
- **Development mode**: All levels enabled (debug, info, warn, error)
- **Production mode**: Only warnings and errors enabled

**Browser Console Access:**
```javascript
// In browser console, dynamically change log levels
window.logger.enableAll()        // Enable all logging
window.logger.errorsOnly()       // Only errors
window.logger.setLogLevel(['debug', 'error'])  // Custom levels
```

### HTTP Request/Response Logging

The `httpClient.ts` uses axios interceptors to automatically log all HTTP requests and responses:

**What's logged:**
- **Requests**: HTTP method, URL, request data
- **Responses**: HTTP method, URL, status code, response data
- **Errors**: HTTP status, error message, error code, request details

**Example output:**
```
[2024-01-15T10:30:45.123Z] [HttpClient] HTTP GET /api/sessions | {"params":{}}
[2024-01-15T10:30:45.456Z] [HttpClient] HTTP GET /api/sessions - 200 | {"items":[...]}
```

### Router Navigation Logging

The router (`router/index.ts`) logs all navigation events:

**What's logged:**
- Navigation attempts (from → to)
- Navigation completion
- Navigation failures
- Router errors

**Example output:**
```
[2024-01-15T10:31:00.123Z] [Router] Navigation: /sessions → /session/abc123/approve | {"toName":"sessionApproval","params":{"sessionName":"abc123"}}
[2024-01-15T10:31:00.456Z] [Router] Navigation completed | {"path":"/session/abc123/approve","name":"sessionApproval"}
```

### Application Lifecycle Logging

The `main.ts` logs key application lifecycle events:

**What's logged:**
- Application startup (environment, mode, configuration)
- Configuration loading
- UI flavour determination
- Vue app initialization
- Router readiness
- OIDC authentication callback processing
- Silent token renewal
- Mount completion

**Example output:**
```
[2024-01-15T10:30:00.000Z] [App] Application starting | {"mode":"production","dev":false,"useMockAuth":false}
[2024-01-15T10:30:00.123Z] [App] Fetching runtime config from backend
[2024-01-15T10:30:00.456Z] [App] UI flavour determined | {"flavour":"oss"}
[2024-01-15T10:30:01.000Z] [App] Router ready | {"currentPath":"/"}
[2024-01-15T10:30:01.500Z] [App] Mounting Vue application
```

### Component Logging

Individual Vue components use the logger service for:

- Component lifecycle (onMounted, onUnmounted)
- User actions (button clicks, form submissions)
- API calls
- State changes
- Error conditions

**Example (SessionApprovalView.vue):**
```typescript
onMounted(() => {
  logger.info(COMPONENT_NAME, 'Component mounted', { 
    sessionName: sessionName.value,
    route: route.path 
  });
  loadSession();
});

const handleApprove = async () => {
  logger.action(COMPONENT_NAME, 'Approve session', { sessionName: sessionName.value });
  // ... approval logic ...
  logger.info(COMPONENT_NAME, 'Session approved successfully');
};
```

## Backend Logging

### Structured Logging

The Go backend uses structured logging (see `pkg/logging/`) with consistent formatting across components.

**Key logging locations:**
- **API Server** (`pkg/api/`): HTTP requests, responses, errors
- **Controllers** (`pkg/breakglass/`): Reconciliation loops, state transitions
- **Webhooks** (`pkg/webhook/`): Authorization decisions, admission validation
- **Cluster Clients** (`pkg/cluster/`): Cluster connectivity, kubeconfig updates

### Build Information Endpoint

The backend exposes build metadata via `/api/debug/buildinfo`:

**Response:**
```json
{
  "version": "v1.2.3",
  "gitCommit": "abc123def456",
  "buildDate": "2024-01-15T10:00:00Z",
  "goVersion": "go1.25.5",
  "platform": "linux/amd64"
}
```

**Usage:**
```bash
curl http://localhost:8080/api/debug/buildinfo
```

This endpoint is useful for:
- Verifying deployed version
- Debugging version mismatches
- CI/CD validation
- Support ticket information

### Build Metadata Injection

Build information is injected at compile time using Go `-ldflags`:

**Makefile variables:**
```makefile
VERSION ?= $(shell git describe --tags --always --dirty)
GIT_COMMIT ?= $(shell git rev-parse HEAD)
BUILD_DATE ?= $(shell date -u +'%Y-%m-%dT%H:%M:%SZ')
```

**Docker build:**
```dockerfile
ARG VERSION=dev
ARG GIT_COMMIT=unknown
ARG BUILD_DATE=unknown

RUN go build -ldflags="\
  -X 'github.com/telekom/k8s-breakglass/pkg/version.Version=${VERSION}' \
  -X 'github.com/telekom/k8s-breakglass/pkg/version.GitCommit=${GIT_COMMIT}' \
  -X 'github.com/telekom/k8s-breakglass/pkg/version.BuildDate=${BUILD_DATE}'" \
  -o /breakglass ./cmd/main.go
```

**CI/CD (GitHub Actions):**
```yaml
- name: Build & Push Image
  uses: docker/build-push-action@v6
  with:
    build-args: |
      VERSION=${{ github.ref_name }}
      GIT_COMMIT=${{ github.sha }}
      BUILD_DATE=${{ github.event.head_commit.timestamp }}
```

## Debugging Tips

### Frontend Debugging

1. **Enable all logging in production:**
   ```javascript
   // In browser console
   window.logger.enableAll()
   ```

2. **Filter logs by component:**
   ```javascript
   // In browser console
   console.log = (function() {
     const original = console.log;
     return function(...args) {
       if (args[0] && args[0].includes('[SessionApprovalView]')) {
         original.apply(console, args);
       }
     };
   })();
   ```

3. **Check Vue Router state:**
   ```javascript
   // In browser console (dev mode with mock auth)
   window.__VUE_ROUTER__.currentRoute.value
   window.__VUE_ROUTER__.getRoutes()  // See all registered routes
   ```

4. **Inspect auth state:**
   ```javascript
   // In browser console (dev mode with mock auth)
   window.__BREAKGLASS_AUTH.getUser()
   window.__BREAKGLASS_AUTH.isAuthenticated()
   ```

### Backend Debugging

1. **Check build info:**
   ```bash
   kubectl exec -n breakglass deploy/breakglass-controller -- /breakglass --version
   ```

2. **View API logs:**
   ```bash
   kubectl logs -n breakglass deploy/breakglass-controller -c manager --follow
   ```

3. **Enable verbose logging:**
   ```yaml
   # In deployment
   args:
     - --zap-log-level=debug
     - --zap-development=true
   ```

4. **Check metrics:**
   ```bash
   kubectl port-forward -n breakglass svc/breakglass-controller-metrics 8443:8443
   curl -k https://localhost:8443/metrics
   ```

### E2E Testing with Logging

When running E2E tests, logging is automatically enabled:

**Playwright test logging:**
```typescript
test('session approval flow', async ({ page }) => {
  // Enable console logging from page
  page.on('console', msg => console.log(`[Browser] ${msg.text()}`));
  
  await page.goto('/session/test-session/approve');
  // All logger calls from the app will be visible
});
```

## Common Troubleshooting Scenarios

### "Route not found" in production

1. Check browser console for router logs
2. Verify route is registered: `window.__VUE_ROUTER__.getRoutes()`
3. Check Vue Router history mode vs hash mode
4. Verify Nginx/server SPA fallback configuration

### API calls failing with 401

1. Check HttpClient logs for Authorization header
2. Verify token expiry: `window.__BREAKGLASS_AUTH.getUser()`
3. Check silent renewal logs
4. Inspect backend logs for token validation errors

### Component not loading

1. Check component lifecycle logs (onMounted/onUnmounted)
2. Verify route params match component expectations
3. Check for JavaScript errors in console
4. Inspect network tab for failed chunk loads

### Build version mismatch

1. Check frontend: `GET /api/debug/buildinfo`
2. Check backend: `kubectl exec ... -- /breakglass --version`
3. Verify image tags match deployed version
4. Check CI build logs for correct VERSION/GIT_COMMIT

## Best Practices

1. **Always log at appropriate levels:**
   - `debug`: Verbose details for debugging (dev only)
   - `info`: Normal operations, user actions
   - `warn`: Unexpected but handled situations
   - `error`: Errors that need attention

2. **Include context in logs:**
   ```typescript
   // Good
   logger.error('Component', 'Failed to load', error, { sessionName, retryCount });
   
   // Bad
   logger.error('Component', 'Failed to load');
   ```

3. **Log state transitions:**
   ```typescript
   logger.stateChange('Component', oldState, newState, 'User action');
   ```

4. **Don't log sensitive data:**
   - Avoid logging full tokens
   - Redact passwords, secrets
   - Be careful with user PII

5. **Use structured context:**
   ```typescript
   // Good
   logger.info('API', 'Request completed', { method, url, status, duration });
   
   // Bad
   logger.info('API', `Request ${method} ${url} completed with ${status}`);
   ```
