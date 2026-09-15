<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
SPDX-License-Identifier: Apache-2.0
-->

# Platform security notes

Audit sink configuration is cluster-wide and should be writable only by platform administrators. Sink URLs control where the controller sends audit events, and referenced credentials are read from the controller namespace. Kafka TLS CA, client certificate/private key, and SASL credentials follow the same namespace boundary as webhook credentials.
The packaged Deployment passes its pod namespace to `--breakglass-namespace`, so the audit service and reconciler enforce the deployed controller namespace. Standalone deployments must set this flag explicitly before configuring TLS, SASL, or webhook Secret references.

Webhook diagnostics redact URL userinfo and query strings before writing logs, errors, or sink health status, including nested HTTP transport errors. Use `authSecretRef` for webhook credentials instead of embedding them in a URL. Audit sink endpoints may be internal service URLs when configured by a trusted administrator.

AuditConfig rejects namespace selector exclusions because the general audit event stream cannot resolve labels for every target cluster. Use namespace patterns for exclusions. Reload rejection preserves the previously working configuration, marks the new configuration Ready=False with ReloadFailed, and emits a warning event. Existing selector exclusions must be migrated to patterns before upgrade; on initial startup no prior configuration is available. The lower-level filtered-sink API supports selectors only when its caller supplies labels.

The plain SMTP development path sends recipients through the SMTP envelope and omits a `Bcc` MIME header. The plain SMTP RCPT failure message omits recipient addresses and remote reply text, exposing a stable generic recipient-command failure that covers server rejection and other command failures. Other SMTP errors and the TLS mail-library path can still include server-supplied text. Keep this mode limited to trusted development networks and use TLS for production mail.

The OIDC proxy permits exact endpoint paths and deliberate realm subpaths. Redirect following remains an explicit deployment choice. Changing an identity provider's authority, CA, or Keycloak endpoint invalidates its cached signing keys at the next periodic IDP refresh. That request fails closed and a subsequent request reloads the keys. Concurrent eviction or replacement during refresh cannot return the invalidated snapshot. This is bounded by the existing audience refresh interval, not immediate configuration-watch invalidation.

Kubectl debug operations return a stable forbidden response for Kubernetes backend
denials, without embedding backend object names or internal error details.
