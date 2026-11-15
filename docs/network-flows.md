<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
SPDX-License-Identifier: CC-BY-4.0
-->

# Network flows of the Breakglass manager

This page lists every connection the Breakglass manager accepts and opens, so
you can write NetworkPolicies, host firewall rules or egress proxies for it.
Ports are the defaults from the flags in `pkg/cli/cli.go`, the server settings
in `config.yaml` and the manifests in `config/deployment/`. If you change a
flag or setting, change the rule with it.

All flows are TCP, except DNS, which also uses UDP.

## Ingress

| Port (default) | Listener | Set by | Peers | Required |
|---|---|---|---|---|
| 8080 | HTTP server: UI, REST API, OIDC proxy, terminal streams and the SubjectAccessReview authorization webhook (`/api/breakglass/webhook/authorize/{cluster}`) | `server.listenAddress` in `config.yaml` (`:8080` in the shipped configs) | Ingress controller or gateway (browsers, `bgctl`); kube-apiservers of the target clusters (authorization webhook); collector Jobs on the target clusters when diagnostic artifacts are on (upload to `artifacts.controllerURL`) | Yes, when `--enable-frontend` or `--enable-api` is true (the default) |
| none (for example 8443) | Dedicated mTLS listener for the authorization webhook only | `server.webhook.listenAddress` | kube-apiservers of the target clusters | Optional, off when empty. With `server.webhook.disableOnMainListener: true` the webhook routes leave 8080 |
| 9443 | controller-runtime webhook server: validating admission webhooks for the Breakglass CRDs | `--webhook-bind-address` | kube-apiserver of the hub cluster | Only when `--enable-webhooks` is true (the default) |
| 8081 | Metrics (controller-runtime and Breakglass) | `--metrics-bind-address` (`0` disables it; `--metrics-secure` serves HTTPS) | Prometheus | Optional |
| none (8083 in `config/deployment/`) | Separate webhook metrics | `--webhooks-metrics-bind-address` (off when empty) | Prometheus | Optional |
| 8082 | Health probes `/healthz`, `/readyz` | `--health-probe-bind-address` | kubelet | Yes |

How the target kube-apiservers reach the authorization webhook depends on the
URL in their webhook kubeconfig (see [Webhook Setup](webhook-setup.md)). With
the usual external URL the traffic comes in through the ingress controller, so
the pod sees the ingress controller as the peer, not the apiservers. Only a
direct connection, such as a dedicated listener exposed by a LoadBalancer
Service, reaches the pod from the apiservers.

The mTLS settings `server.clientAuth` and `server.webhook.clientAuth` apply
only to their own listener. Ports 9443, 8081, 8083 and 8082 keep their own TLS
settings (see [Configuration Reference](configuration-reference.md#clientauth-optional)).

## Egress

| Peer | Port | Used for | Set by | Required |
|---|---|---|---|---|
| Hub cluster kube-apiserver | 443 (Service `kubernetes.default`) or the apiserver port | Watches and writes all Breakglass resources, Secrets, leader-election Leases, Events | In-cluster config | Yes |
| Target cluster kube-apiservers | The port in the server URL, usually 443 or 6443 | SubjectAccessReviews and impersonated checks for sessions, debug session workloads, `kubectl debug`, exec and port-forward, cluster health checks | ClusterConfig `spec.kubeconfigSecretRef` (server in the kubeconfig), `spec.oidcAuth.server` or `spec.oidcFromIdentityProvider.server` | Yes, one per ClusterConfig |
| OIDC issuer of each IdentityProvider | Port of the URL, usually 443 | Discovery and JWKS to verify user tokens; the OIDC proxy for the UI | IdentityProvider `spec.oidc.authority` (and `spec.oidc.discoveryURL`, `spec.oidc.jwksEndpoint` when set) | Yes |
| Keycloak admin API | Port of the URL, usually 443 | Group sync: resolving approver group members | IdentityProvider `spec.keycloak.baseURL` with `spec.groupSyncProvider: Keycloak` | Optional |
| OIDC issuer for cluster credentials | Port of the URL, usually 443 | Client credentials, refresh token or token exchange for the target cluster credentials | ClusterConfig `spec.oidcAuth.issuerURL`, or the IdentityProvider named in `spec.oidcFromIdentityProvider` | Only with OIDC cluster authentication |
| SMTP server | MailProvider `spec.smtp.port` (for example 587 or 465) | Notification email | MailProvider `spec.smtp.host` | Optional |
| Kafka brokers | Port in each broker address | Audit events | AuditConfig `spec.sinks[].kafka.brokers` | Optional |
| Audit webhook | Port of each URL | Audit events | AuditConfig `spec.sinks[].webhook.url`, and `spec.sinks[].webhook.batchUrl` for batches when set | Optional |
| Debug session audit webhook | Port of the URL | Debug session audit events | DebugSessionTemplate `spec.audit.destinations[].url` (type `webhook`) | Optional |
| OTLP collector | 4317 by default (gRPC) | Traces | `telemetry.endpoint` or `--otel-endpoint`, with `telemetry.enabled` or `--otel-enabled` | Optional |
| S3 endpoint | Port of the URL | Diagnostic artifact storage | `artifacts.s3.endpoint` with `artifacts.enabled` and `artifacts.backend: s3` | Optional |
| DNS | 53 (UDP and TCP) | Name resolution for all of the above | Cluster DNS | Yes |

The `log` and `kubernetes` audit sinks need no extra flow: they write to the
manager log and to the hub kube-apiserver. Not every client of the manager
uses the `HTTPS_PROXY` environment variable, so plan for direct egress to the
peers rather than relying on an egress proxy.

## The chart's NetworkPolicy

The `escalation-config` chart renders a NetworkPolicy for the pods labelled
`app: breakglass` in the release namespace when `networkPolicy.enabled` is
true (default `false`), so it only applies when the chart is installed into the
manager's namespace. The policy has `policyTypes: [Ingress]` only: it denies all ingress except the
ports below and does not restrict egress. Add your own egress policy from the
table above if you need one.

| Value | Default | Ingress rule |
|---|---|---|
| `networkPolicy.apiPort` | 8080 | From namespaces matching `networkPolicy.ingressNamespaceSelector`, or from everywhere when it is empty |
| `networkPolicy.metricsPort` | 8081 | From namespaces matching `networkPolicy.metricsNamespaceSelector`, or from everywhere when it is empty |
| `networkPolicy.webhookMetricsPort` | 8083 | From everywhere; the rule is left out when the value is empty or `0` |
| `networkPolicy.webhookPort` | 9443 | From everywhere. This is the CRD admission webhook server (`--webhook-bind-address`), not the authorization webhook, which is served on `apiPort` |
| `networkPolicy.healthPort` | 8082 | From everywhere |
| `networkPolicy.additionalIngressRules` | `[]` | Appended as given |

The policy has no rule for the dedicated webhook listener
(`server.webhook.listenAddress`). If you enable it, add its port with
`networkPolicy.additionalIngressRules`:

```yaml
networkPolicy:
  enabled: true
  ingressNamespaceSelector:
    kubernetes.io/metadata.name: ingress-nginx
  metricsNamespaceSelector:
    kubernetes.io/metadata.name: monitoring
  additionalIngressRules:
    - ports:
        - port: 8443
          protocol: TCP
```

The admission webhook (9443) and the health port (8082) are open to every
source because the hub kube-apiserver and the kubelet usually connect from the
host network, which a `namespaceSelector` cannot match. NetworkPolicies are
additive, so another policy cannot narrow these rules. To restrict them to a
known range with `ipBlock`, set `networkPolicy.enabled: false` and write one
complete policy of your own that keeps every required flow from the table
above.

Restricting `apiPort` to the ingress controller namespace also blocks target
kube-apiservers or collector Jobs that connect to the pod directly. Send them
through the ingress, or allow their source ranges with
`additionalIngressRules`.
