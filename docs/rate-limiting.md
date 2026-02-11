# Rate Limiting

Comprehensive reference for the breakglass built-in rate limiting system.

## Overview

Breakglass implements multi-tier, in-process rate limiting using the [token bucket algorithm](https://en.wikipedia.org/wiki/Token_bucket) via Go's `golang.org/x/time/rate` package. Each tracked key (IP address or user identity) gets its own bucket that refills at a constant rate and allows short bursts up to a configured maximum.

Rate limiting operates at three tiers:

1. **Global per-IP** — applied to all incoming requests as the first middleware layer
2. **Authenticated per-user** — applied to both authentication-optional public endpoints and authentication-required API routes (e.g., escalation management), with separate limits for authenticated vs unauthenticated callers
3. **SAR webhook per-IP** — applied to SubjectAccessReview endpoints used by spoke clusters

## Architecture

```
                                ┌─────────────────────────┐
  Incoming Request ─────────►   │  Global Per-IP Limiter  │  20 req/s, burst 50
                                │  (all non-static)       │
                                └───────────┬─────────────┘
                       ┌────────────────────┼──────────────────────┐
                       │                    │                      │
               ┌───────▼──────┐     ┌───────▼──────┐       ┌──────▼──────┐
               │  Auth-Optional│     │  Auth-Required│       │  SAR        │
               │  Endpoints   │     │  API Routes   │       │  Authorize  │
               │  /api/config │     │  /api/sessions│       │  Webhook    │
               └───────┬──────┘     └───────┬──────┘       └──────┬──────┘
                       │                    │                     │
               ┌───────▼──────┐     ┌───────▼──────┐       ┌──────▼──────┐
               │  Authenticated│     │  Authenticated│       │  SAR Limiter│
               │  Limiter      │     │  Limiter      │       │  1000 req/s │
               │  10/s or 50/s │     │  50/s         │       │  burst 5000 │
               └──────────────┘     └──────────────┘       └─────────────┘

  Static Assets (/assets/, /favicon) bypass all rate limiters entirely.
```

### Dual-Layer Behavior

All non-static requests pass through the **global per-IP limiter** (20 req/s, burst 50) applied at the Gin engine level. Tier-specific limiters are applied on top:

- **Auth-optional endpoints** (e.g., `/api/config`, `/api/identity-provider`): Global limiter → Authenticated limiter (10 req/s unauthenticated, 50 req/s authenticated)
- **Auth-required API routes** (e.g., `/api/sessions`): Global limiter → Authenticated limiter (50 req/s per user)
- **SAR webhook** (`/api/breakglass/webhook/authorize/:cluster_name`): Global limiter → SAR limiter (1000 req/s, burst 5000)

Both layers must allow the request. The global limiter acts as a coarse per-IP filter; the tier-specific limiter provides finer-grained control.

> **Important:** Under the default configuration, SAR webhook traffic is constrained to 20 req/s per source IP by the global limiter, even though the SAR-specific limiter allows 1000 req/s. If your spoke clusters generate higher SAR volumes from a single API server IP, consider increasing the global limiter rate or excluding the webhook paths from the global limiter.

## Rate Limit Tiers

### Global Per-IP Limiter

Applied as Gin middleware to **all** incoming requests except static assets.

| Parameter | Value |
|-----------|-------|
| Rate | 20 requests/second |
| Burst | 50 |
| Tracking Key | `ClientIP()` |
| Cleanup Interval | 60 seconds |
| Entry MaxAge | 5 minutes |
| Excluded Paths | `/assets/`, `/favicon` |

**Source:** `ratelimit.DefaultAPIConfig()`

### Authenticated Limiter

Applied to public API endpoints that accept optional authentication and to authentication-required API routes (e.g., the escalation controller via `MiddlewareWithRateLimiting`). The limiter inspects the Gin context for a user identity (the `email` key set by the authentication middleware).

**Identity extraction differs by authentication mode:**

- **Auth-required endpoints** (`Middleware()`): The `email` context key is set directly from the JWT `email` claim. If the `email` claim is missing or empty, the rate limiter falls back to per-IP tracking.
- **Auth-optional endpoints** (`OptionalAuthRateLimitMiddleware`): The middleware uses `tryExtractUserIdentity()`, which prefers the JWT `email` claim and falls back to `sub` (subject) when email is unavailable.

#### Unauthenticated Path

| Parameter | Value |
|-----------|-------|
| Rate | 10 requests/second |
| Burst | 20 |
| Tracking Key | `ClientIP()` |
| Cleanup Interval | 60 seconds |
| Entry MaxAge | 5 minutes |

#### Authenticated Path (valid JWT present)

| Parameter | Value |
|-----------|-------|
| Rate | 50 requests/second |
| Burst | 100 |
| Tracking Key | User identity (`email` claim; `sub` fallback on optional-auth endpoints only) |
| Cleanup Interval | 60 seconds |
| Entry MaxAge | 10 minutes |

**Source:** `ratelimit.DefaultAuthenticatedAPIConfig()`

### SAR Webhook Limiter

Applied to the SubjectAccessReview authorization webhook endpoint. This endpoint is registered at two paths for backwards compatibility:

- `/api/breakglass/webhook/authorize/:cluster_name` (canonical)
- `/breakglass/webhook/authorize/:cluster_name` (legacy)

This endpoint receives high-volume requests from the Kubernetes API server on spoke clusters.

| Parameter | Value |
|-----------|-------|
| Rate | 1000 requests/second |
| Burst | 5000 |
| Tracking Key | `ClientIP()` |
| Cleanup Interval | 60 seconds |
| Entry MaxAge | 5 minutes |

**Source:** `ratelimit.DefaultSARConfig()`

## Response Format

When a request is rate limited, the server returns HTTP `429 Too Many Requests` with a JSON body:

**Global limiter response:**
```json
{
  "error": "Rate limit exceeded, please try again later"
}
```

**Authenticated limiter response (unauthenticated caller):**
```json
{
  "error": "Rate limit exceeded. Please authenticate for higher limits.",
  "authenticated": false
}
```

**Authenticated limiter response (authenticated caller):**
```json
{
  "error": "Rate limit exceeded, please try again later",
  "authenticated": true
}
```

> **Note:** The server does **not** currently emit `Retry-After`, `X-RateLimit-Limit`, `X-RateLimit-Remaining`, or `X-RateLimit-Reset` headers. Clients should implement exponential backoff when receiving `429` responses.

## Memory Management

Each rate limiter runs a background goroutine that periodically cleans up stale entries:

- **Cleanup interval:** Every 60 seconds, the limiter scans all tracked entries
- **Eviction policy:** Entries not accessed within `MaxAge` (5 or 10 minutes depending on tier) are removed
- **Shutdown:** `Server.Close()` stops all cleanup goroutines via the `Stop()` method

Memory usage is proportional to the number of unique IPs/users that have made requests within the MaxAge window. For typical deployments, this is negligible.

## Client IP Detection

Rate limiting uses Gin's `ClientIP()` function to identify clients:

- **Without `trustedProxies`** configured: Uses the direct TCP connection IP. This is secure but may rate-limit your ingress controller/proxy instead of individual clients.
- **With `trustedProxies`** configured: Parses `X-Forwarded-For` headers from trusted proxies to determine the real client IP.

> **⚠️ Security Warning:** Only trust proxies you control. Misconfigured `trustedProxies` allows attackers to spoof `X-Forwarded-For` headers and bypass per-IP rate limiting. See [Security Best Practices](./security-best-practices.md#rate-limiting) for detailed configuration guidance.

## Customization

### Runtime Configuration

Rate limits are **not currently configurable at runtime** via `config.yaml` or environment variables. All limits are defined as compile-time defaults in `pkg/ratelimit/ratelimit.go`.

### Modifying Limits

To change rate limits, modify the default configuration functions and rebuild:

```go
// pkg/ratelimit/ratelimit.go

func DefaultAPIConfig() Config {
    return Config{
        Rate:            20,                  // Change this for global limit (float64)
        Burst:           50,                  // Change this for burst allowance
        CleanupInterval: time.Minute,
        MaxAge:          5 * time.Minute,
    }
}
```

### Ingress-Level Rate Limiting

For production deployments, consider adding rate limiting at the ingress controller level as defense in depth. This protects the breakglass service before requests reach the application:

- **NGINX Ingress:** Use `nginx.ingress.kubernetes.io/limit-rps` annotation
- **Traefik:** Use `RateLimit` middleware
- **Istio:** Use `EnvoyFilter` with `local_ratelimit`

See [Security Best Practices](./security-best-practices.md#rate-limiting) for complete ingress rate limiting examples.

## Troubleshooting

### "Rate limit exceeded" for legitimate users

**Symptoms:** Users receive `429` responses during normal usage.

**Common causes:**

1. **Missing `trustedProxies`:** All requests appear to come from the ingress controller IP, consuming the single-IP rate limit for all users.
   ```yaml
   server:
     trustedProxies:
       - 10.0.0.0/8  # Your pod network CIDR
   ```

2. **Shared NAT/proxy:** Multiple users behind the same NAT share a single rate limit bucket. Consider configuring `trustedProxies` and ensuring your proxy forwards `X-Forwarded-For`.

3. **Automated tooling:** Scripts or CI/CD pipelines making rapid API calls. Consider adding delays between requests or authenticating for higher limits.

### Verifying rate limiter behavior

```bash
# Quick burst test against local server
for i in $(seq 1 60); do
  curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8080/api/config
done | sort | uniq -c
# Expected: ~50 200s followed by 429s

# Check logs for rate limiting (if using structured logging)
kubectl logs -n breakglass-system -l app=breakglass-manager | grep -i "rate"
```

### Memory usage concerns

The rate limiter tracks one entry per unique IP (or user). With the default 5-minute MaxAge and 60-second cleanup:

- 1,000 unique IPs → ~50 KB memory overhead
- 10,000 unique IPs → ~500 KB memory overhead
- Entries are automatically evicted after 5 minutes of inactivity

For extremely high-traffic deployments, prefer ingress-level rate limiting to reduce the number of requests reaching the application.
