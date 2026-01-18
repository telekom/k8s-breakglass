# Ingress Configuration

This document covers how to properly configure breakglass behind a Kubernetes ingress controller, including security headers, CORS, and proxy configuration.

## Overview

When deploying breakglass behind an ingress controller (NGINX, Traefik, HAProxy, etc.), several considerations apply:

1. **Trusted Proxies** - Configure which IPs can set X-Forwarded-* headers
2. **CORS Origins** - Ensure browser origins match the ingress host
3. **Security Headers** - HSTS requires X-Forwarded-Proto to work correctly
4. **TLS Termination** - Ingress typically terminates TLS, forwarding HTTP to the backend

## Configuration

### Trusted Proxies

Configure `trustedProxies` in your config.yaml to enable proper handling of X-Forwarded-* headers:

```yaml
server:
  listenAddress: :8080
  trustedProxies:
    - 10.0.0.0/8        # Kubernetes pod network (adjust to your cluster)
    - 172.16.0.0/12     # Private networks
    - 192.168.0.0/16    # Private networks
```

**Why this matters:**

- **Rate limiting**: Uses `X-Forwarded-For` to identify real client IPs
- **Logging**: Records actual client IPs instead of ingress pod IPs
- **HSTS**: Uses `X-Forwarded-Proto` to detect HTTPS and set Strict-Transport-Security header

**Security Warning:** Only trust proxies you control. An attacker with access to a trusted IP could spoof client addresses.

### Allowed Origins

Configure `allowedOrigins` to match your ingress hostname:

```yaml
server:
  allowedOrigins:
    - https://breakglass.example.com   # Must match ingress host
    - https://breakglass.example.net   # Additional domains if needed
```

**Important:** The origin must exactly match what the browser sends, including:
- Protocol (`https://`)
- Hostname (`breakglass.example.com`)
- Port (omit for standard 443)

### Frontend Base URL

Configure the frontend base URL to match your external hostname:

```yaml
frontend:
  baseURL: https://breakglass.example.com
```

This affects:
- Links in notification emails
- OIDC redirect URIs
- CSP connect-src directive

## Ingress Examples

### NGINX Ingress Controller

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: breakglass
  namespace: breakglass-system
  annotations:
    # Enable HTTPS redirect
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    # Preserve client IP (default behavior, but explicit)
    nginx.ingress.kubernetes.io/use-forwarded-headers: "true"
    # Optional: Rate limiting at ingress level
    nginx.ingress.kubernetes.io/limit-rps: "20"
    nginx.ingress.kubernetes.io/limit-burst-multiplier: "5"
    # Optional: Add security headers (breakglass sets these, but defense in depth)
    nginx.ingress.kubernetes.io/configuration-snippet: |
      more_set_headers "X-Content-Type-Options: nosniff";
      more_set_headers "X-Frame-Options: DENY";
spec:
  ingressClassName: nginx
  tls:
    - hosts:
        - breakglass.example.com
      secretName: breakglass-tls
  rules:
    - host: breakglass.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: breakglass
                port:
                  number: 8080
```

**Find your pod network CIDR:**

```bash
# For most clusters, check the CNI configuration
kubectl get pods -n kube-system -l k8s-app=kube-dns -o wide
# Note the IP range of your pods

# Or check cluster info
kubectl cluster-info dump | grep -i cidr
```

### Traefik Ingress

```yaml
apiVersion: traefik.io/v1alpha1
kind: IngressRoute
metadata:
  name: breakglass
  namespace: breakglass-system
spec:
  entryPoints:
    - websecure
  routes:
    - match: Host(`breakglass.example.com`)
      kind: Rule
      services:
        - name: breakglass
          port: 8080
      middlewares:
        - name: security-headers
        - name: rate-limit
  tls:
    secretName: breakglass-tls
---
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: security-headers
  namespace: breakglass-system
spec:
  headers:
    stsSeconds: 31536000
    stsIncludeSubdomains: true
    forceSTSHeader: true
    frameDeny: true
    contentTypeNosniff: true
    browserXssFilter: true
---
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: rate-limit
  namespace: breakglass-system
spec:
  rateLimit:
    average: 20
    burst: 50
```

### HAProxy Ingress

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: breakglass
  namespace: breakglass-system
  annotations:
    haproxy.org/ssl-redirect: "true"
    haproxy.org/rate-limit-requests: "20"
    haproxy.org/rate-limit-period: "1s"
spec:
  ingressClassName: haproxy
  tls:
    - hosts:
        - breakglass.example.com
      secretName: breakglass-tls
  rules:
    - host: breakglass.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: breakglass
                port:
                  number: 8080
```

## Security Headers

Breakglass automatically sets the following security headers:

| Header | Value | Purpose |
|--------|-------|---------|
| `X-Content-Type-Options` | `nosniff` | Prevent MIME type sniffing |
| `X-Frame-Options` | `DENY` | Prevent clickjacking |
| `X-XSS-Protection` | `1; mode=block` | XSS filter for older browsers |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Control referrer information |
| `Permissions-Policy` | `geolocation=(), microphone=(), camera=()` | Restrict browser features |
| `Content-Security-Policy` | Dynamic (see below) | Prevent XSS and injection attacks |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` | Enforce HTTPS (only when HTTPS detected) |

### HSTS Behind Ingress

The `Strict-Transport-Security` header is only set when the server detects HTTPS. Behind an ingress that terminates TLS, this is detected via:

1. `X-Forwarded-Proto: https` header
2. `X-Forwarded-Ssl: on` header
3. Direct TLS connection (when TLS is not terminated by ingress)

**Ensure your ingress forwards these headers:**

```yaml
# NGINX Ingress - enabled by default
nginx.ingress.kubernetes.io/use-forwarded-headers: "true"

# Traefik - configure entry point
entryPoints:
  websecure:
    forwardedHeaders:
      trustedIPs:
        - "10.0.0.0/8"
```

## X-Forwarded Headers Reference

| Header | Purpose | Example |
|--------|---------|---------|
| `X-Forwarded-For` | Original client IP | `203.0.113.50, 10.0.0.1` |
| `X-Forwarded-Proto` | Original protocol | `https` |
| `X-Forwarded-Host` | Original hostname | `breakglass.example.com` |
| `X-Forwarded-Ssl` | SSL indicator | `on` |
| `X-Request-ID` | Request correlation | `abc123-def456` |

**Note:** Breakglass propagates `X-Request-ID` if provided, or generates one if absent. This is useful for distributed tracing.

## CORS Configuration

When the frontend and API are on the same origin (typical with ingress), CORS is straightforward:

```yaml
server:
  allowedOrigins:
    - https://breakglass.example.com
frontend:
  baseURL: https://breakglass.example.com
```

For multi-domain setups:

```yaml
server:
  allowedOrigins:
    - https://breakglass.example.com    # Primary domain
    - https://breakglass-dr.example.com # DR site
    - https://admin.example.com         # Admin portal
```

## Troubleshooting

### Check Security Headers

```bash
curl -v https://breakglass.example.com/api/config 2>&1 | grep -E "^< (X-|Content-Security|Strict-Transport|Referrer)"
```

Expected output:
```
< X-Content-Type-Options: nosniff
< X-Frame-Options: DENY
< X-XSS-Protection: 1; mode=block
< X-Request-ID: abc123...
< Referrer-Policy: strict-origin-when-cross-origin
< Content-Security-Policy: default-src 'self'; ...
< Strict-Transport-Security: max-age=31536000; includeSubDomains
```

### HSTS Not Being Set

If HSTS header is missing:

1. Check `X-Forwarded-Proto` is being forwarded:
   ```bash
   kubectl exec -it deploy/breakglass -- curl -H "X-Forwarded-Proto: https" localhost:8080/api/config -v 2>&1 | grep Strict
   ```

2. Verify `trustedProxies` includes your ingress pod network:
   ```bash
   kubectl get pods -n ingress-nginx -o wide
   ```

3. Check ingress controller configuration forwards headers

### CORS Errors in Browser

If you see CORS errors in browser console:

1. Check `allowedOrigins` includes the exact origin:
   ```bash
   kubectl logs -l app=breakglass | grep blocked_request_origin
   ```

2. Verify origin matches exactly (including protocol and port)

3. Check response headers:
   ```bash
   curl -v -H "Origin: https://breakglass.example.com" \
        https://breakglass.example.com/api/config 2>&1 | grep -i access-control
   ```

### Rate Limiting Showing Wrong IPs

If rate limiting logs show ingress IPs instead of client IPs:

1. Verify `trustedProxies` is configured:
   ```yaml
   server:
     trustedProxies:
       - 10.0.0.0/8
   ```

2. Check ingress is forwarding `X-Forwarded-For`:
   ```bash
   kubectl logs deploy/breakglass | grep "remote"
   ```

## Related Documentation

- [Security Best Practices](security-best-practices.md)
- [Configuration Reference](configuration-reference.md)
- [Installation Guide](installation.md)
