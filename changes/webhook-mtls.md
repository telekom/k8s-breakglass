---
section: Upgrade notes
---

- The SubjectAccessReview webhook can be served on a dedicated mTLS listener,
  `server.webhook.listenAddress`, with its own `clientAuth`/`clientCAFile`.
  Under `clientAuth: require` the kube-apiserver client certificate must name
  the cluster in the request path (DNS SAN, or CN without SANs), else the
  request gets 403; `requireCommonNameMatch: false` is a transitional escape.
  `disableOnMainListener: true` removes the webhook from the main listener.
  Unset `server.webhook` keeps today's behaviour.

- The controller now stops when the HTTP server cannot bind
  `server.listenAddress` (or `server.webhook.listenAddress`) instead of
  logging the error and running without the listener.
