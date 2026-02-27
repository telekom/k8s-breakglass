# Gateway API Configuration

This document covers how to expose the breakglass service using [Gateway API](https://gateway-api.sigs.k8s.io/) as an alternative to traditional Kubernetes Ingress. For Ingress-based configuration, see [Ingress Configuration](ingress-configuration.md).

## Overview

Gateway API is the successor to Kubernetes Ingress, offering:

- **Role-oriented design** — Platform admins manage Gateways, application teams manage HTTPRoutes
- **Advanced traffic management** — Canary deployments, header-based routing, traffic splitting
- **Portable configuration** — Works across implementations (Istio, Envoy Gateway, Kong, etc.)
- **Better TLS model** — TLS is configured on the Gateway, not per-route
- **Cross-namespace references** — Secure delegation via ReferenceGrants

### When to Use Gateway API vs Ingress

| Use Case | Recommendation |
|----------|---------------|
| New deployments on K8s 1.26+ | Gateway API |
| Existing Ingress working well | Keep Ingress (migration optional) |
| Need canary/traffic splitting | Gateway API |
| Using Istio, Envoy Gateway, or Kong | Gateway API |
| Minimal setup, single backend | Either works |

## Enabling Gateway API

Breakglass ships a **kustomize Component** that replaces the default Ingress with an HTTPRoute and ReferenceGrant. To enable it, add the component to your kustomize overlay.

### Prerequisites

1. **Kubernetes 1.26+** — Gateway API v1 requires 1.26 or later
2. **Gateway API CRDs installed** — Install the standard CRDs:

   ```bash
   kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.2.1/standard-install.yaml
   ```

3. **A Gateway resource provisioned** — Your platform team must create a Gateway. Example:

   ```yaml
   apiVersion: gateway.networking.k8s.io/v1
   kind: Gateway
   metadata:
     name: api-gateway
     namespace: gateway-system
   spec:
     gatewayClassName: envoy  # or istio, kong, etc.
     listeners:
       - name: https
         protocol: HTTPS
         port: 443
         tls:
           mode: Terminate
           certificateRefs:
             - name: wildcard-tls
         allowedRoutes:
           namespaces:
             from: All
   ```

### Enable the Component

Create or modify your kustomize overlay to include the Gateway API component:

```yaml
# config/overlays/production/kustomization.yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

resources:
  - ../../base

components:
  - ../../components/gateway-api

# Customize for your environment
patches:
  - target:
      kind: HTTPRoute
      name: breakglass
    patch: |
      - op: replace
        path: /spec/parentRefs/0/name
        value: production-gateway
      - op: replace
        path: /spec/parentRefs/0/namespace
        value: infra-system
      - op: replace
        path: /spec/hostnames/0
        value: breakglass.production.example.com
  - target:
      kind: ReferenceGrant
      name: allow-gateway-to-breakglass
    patch: |
      - op: replace
        path: /spec/from/0/namespace
        value: infra-system
```

Build and verify:

```bash
kustomize build config/overlays/production/
```

The output should contain an HTTPRoute and ReferenceGrant — but **no** Ingress resource.

### What the Component Does

The Gateway API component:

1. **Adds** an HTTPRoute pointing to the breakglass Service on port 8080
2. **Adds** a ReferenceGrant for cross-namespace deployments (restricted by `spec.to.name` to only the `breakglass-breakglass` service). In the default deployment (HTTPRoute and Service both in `breakglass-system`), the ReferenceGrant is technically not required but is included for safety.
3. **Removes** the default Ingress resource to avoid dual exposure

## Customization

### Changing the Gateway Reference

The HTTPRoute must reference your Gateway by name and namespace:

```yaml
patches:
  - target:
      kind: HTTPRoute
      name: breakglass
    patch: |
      - op: replace
        path: /spec/parentRefs/0/name
        value: my-gateway
      - op: replace
        path: /spec/parentRefs/0/namespace
        value: my-gateway-namespace
      - op: add
        path: /spec/parentRefs/0/sectionName
        value: https     # Optional: target a specific listener
```

### Adding Multiple Hostnames

```yaml
patches:
  - target:
      kind: HTTPRoute
      name: breakglass
    patch: |
      - op: replace
        path: /spec/hostnames
        value:
          - breakglass.example.com
          - breakglass-dr.example.com
```

### Header Modification

Add request headers via HTTPRoute filters:

```yaml
patches:
  - target:
      kind: HTTPRoute
      name: breakglass
    patch: |
      - op: add
        path: /spec/rules/0/filters
        value:
          - type: RequestHeaderModifier
            requestHeaderModifier:
              add:
                - name: X-Breakglass-Version
                  value: v1
```

### Removing the ReferenceGrant

If your Gateway and breakglass are in the same namespace, remove the ReferenceGrant:

```yaml
patches:
  - target:
      kind: ReferenceGrant
      name: allow-gateway-to-breakglass
    patch: |
      apiVersion: gateway.networking.k8s.io/v1
      kind: ReferenceGrant
      metadata:
        name: allow-gateway-to-breakglass
      $patch: delete
```

## Implementation Examples

### Istio

Istio supports Gateway API natively since v1.15+.

**Gateway:**

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: istio-gateway
  namespace: istio-system
spec:
  gatewayClassName: istio
  listeners:
    - name: https
      protocol: HTTPS
      port: 443
      tls:
        mode: Terminate
        certificateRefs:
          - name: breakglass-tls
      allowedRoutes:
        namespaces:
          from: All
```

**Overlay:**

```yaml
components:
  - ../../components/gateway-api

patches:
  - target:
      kind: HTTPRoute
      name: breakglass
    patch: |
      - op: replace
        path: /spec/parentRefs/0/name
        value: istio-gateway
      - op: replace
        path: /spec/parentRefs/0/namespace
        value: istio-system
      - op: replace
        path: /spec/hostnames/0
        value: breakglass.example.com
  - target:
      kind: ReferenceGrant
      name: allow-gateway-to-breakglass
    patch: |
      - op: replace
        path: /spec/from/0/namespace
        value: istio-system
```

**Rate limiting** (via Istio policy attachment):

```yaml
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: breakglass-rate-limit
  namespace: breakglass-system
spec:
  targetRefs:
    - kind: Service
      group: ""
      name: breakglass
  action: CUSTOM
  provider:
    name: rate-limiter
  rules:
    - to:
        - operation:
            paths: ["/api/*"]
```

### Envoy Gateway

Envoy Gateway is a CNCF project providing a managed Envoy proxy via Gateway API.

**Gateway:**

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: envoy-gateway
  namespace: envoy-gateway-system
spec:
  gatewayClassName: eg
  listeners:
    - name: https
      protocol: HTTPS
      port: 443
      tls:
        mode: Terminate
        certificateRefs:
          - name: breakglass-tls
      allowedRoutes:
        namespaces:
          from: All
```

**Overlay:**

```yaml
components:
  - ../../components/gateway-api

patches:
  - target:
      kind: HTTPRoute
      name: breakglass
    patch: |
      - op: replace
        path: /spec/parentRefs/0/name
        value: envoy-gateway
      - op: replace
        path: /spec/parentRefs/0/namespace
        value: envoy-gateway-system
      - op: replace
        path: /spec/hostnames/0
        value: breakglass.example.com
  - target:
      kind: ReferenceGrant
      name: allow-gateway-to-breakglass
    patch: |
      - op: replace
        path: /spec/from/0/namespace
        value: envoy-gateway-system
```

**Rate limiting** (via BackendTrafficPolicy):

```yaml
apiVersion: gateway.envoyproxy.io/v1alpha1
kind: BackendTrafficPolicy
metadata:
  name: breakglass-rate-limit
  namespace: breakglass-system
spec:
  targetRefs:
    - group: gateway.networking.k8s.io
      kind: HTTPRoute
      name: breakglass
  rateLimit:
    type: Global
    global:
      rules:
        - limit:
            requests: 20
            unit: Second
```

### Kong Gateway

Kong supports Gateway API via the Kong Ingress Controller (KIC) 3.0+.

**Gateway:**

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: kong-gateway
  namespace: kong-system
spec:
  gatewayClassName: kong
  listeners:
    - name: https
      protocol: HTTPS
      port: 443
      tls:
        mode: Terminate
        certificateRefs:
          - name: breakglass-tls
      allowedRoutes:
        namespaces:
          from: All
```

**Overlay:**

```yaml
components:
  - ../../components/gateway-api

patches:
  - target:
      kind: HTTPRoute
      name: breakglass
    patch: |
      - op: replace
        path: /spec/parentRefs/0/name
        value: kong-gateway
      - op: replace
        path: /spec/parentRefs/0/namespace
        value: kong-system
      - op: replace
        path: /spec/hostnames/0
        value: breakglass.example.com
  - target:
      kind: ReferenceGrant
      name: allow-gateway-to-breakglass
    patch: |
      - op: replace
        path: /spec/from/0/namespace
        value: kong-system
```

**Rate limiting** (via KongPlugin):

```yaml
apiVersion: configuration.konghq.com/v1
kind: KongPlugin
metadata:
  name: breakglass-rate-limit
  namespace: breakglass-system
  annotations:
    konghq.com/plugins: rate-limiting
spec:
  plugin: rate-limiting
  config:
    second: 20
    policy: local
```

## TLS Configuration

With Gateway API, TLS is configured on the **Gateway listener** rather than on individual routes. This is managed by platform admins:

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
spec:
  listeners:
    - name: https
      protocol: HTTPS
      port: 443
      tls:
        mode: Terminate
        certificateRefs:
          - name: breakglass-tls    # TLS secret in the Gateway namespace
            kind: Secret
```

**cert-manager integration:**

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: breakglass-tls
  namespace: gateway-system
spec:
  secretName: breakglass-tls
  issuerRef:
    name: letsencrypt-prod
    kind: ClusterIssuer
  dnsNames:
    - breakglass.example.com
```

## Breakglass Server Configuration

The same server configuration applies regardless of whether you use Ingress or Gateway API:

```yaml
server:
  listenAddress: :8080
  trustedProxies:
    - 10.0.0.0/8          # Adjust to your cluster's pod CIDR
  allowedOrigins:
    - https://breakglass.example.com
frontend:
  baseURL: https://breakglass.example.com
```

See [Ingress Configuration](ingress-configuration.md) for details on trusted proxies, CORS, and security headers — these apply identically to Gateway API deployments.

## Troubleshooting

### HTTPRoute Not Accepted

Check the HTTPRoute status:

```bash
kubectl get httproute breakglass -n breakglass-system -o yaml
```

Look for the `status.parents` field — each parent Gateway reports acceptance:

```yaml
status:
  parents:
    - parentRef:
        name: api-gateway
        namespace: gateway-system
      conditions:
        - type: Accepted
          status: "True"
        - type: ResolvedRefs
          status: "True"
```

**Common issues:**

| Condition | Status | Cause | Fix |
|-----------|--------|-------|-----|
| `Accepted` | `False` | Gateway doesn't allow routes from this namespace | Update Gateway `allowedRoutes.namespaces` |
| `ResolvedRefs` | `False` | Missing ReferenceGrant | Apply the ReferenceGrant resource |
| `ResolvedRefs` | `False` | Service name/port mismatch | Verify service `breakglass-breakglass` exists on port 8080 |

### ReferenceGrant Not Working

Verify the grant is in the **target** namespace (where the Service lives):

```bash
kubectl get referencegrant -n breakglass-system
```

The ReferenceGrant must be in the same namespace as the resource being referenced (the Service), not in the Gateway namespace.

### Traffic Not Reaching the Service

1. Check the Gateway is programmed:

   ```bash
   kubectl get gateway -A
   ```

2. Verify the HTTPRoute is attached:

   ```bash
   kubectl get httproute -n breakglass-system -o wide
   ```

3. Test connectivity directly to the Service:

   ```bash
   kubectl port-forward svc/breakglass-breakglass -n breakglass-system 8080:8080
   curl http://localhost:8080/api/config
   ```

4. Check gateway controller logs:

   ```bash
   # Envoy Gateway
   kubectl logs -n envoy-gateway-system deploy/envoy-gateway

   # Istio
   kubectl logs -n istio-system deploy/istiod

   # Kong
   kubectl logs -n kong-system deploy/kong-controller
   ```

### Migrating from Ingress

To migrate an existing deployment from Ingress to Gateway API:

1. Deploy a Gateway in your cluster (if not already present)
2. Add the Gateway API component to your kustomize overlay
3. Verify the HTTPRoute is accepted and traffic flows correctly
4. The component automatically removes the Ingress — no manual cleanup needed

If you need to run both temporarily during migration, remove the `$patch: delete` for Ingress in the component by adding a no-op patch.

## Related Documentation

- [Ingress Configuration](ingress-configuration.md) — Traditional Ingress setup and security headers
- [Installation Guide](installation.md) — Step-by-step deployment
- [Production Deployment Checklist](production-deployment-checklist.md) — Production readiness
- [Security Best Practices](security-best-practices.md) — Security hardening
- [Gateway API Documentation](https://gateway-api.sigs.k8s.io/) — Upstream Gateway API docs
