# Breakglass

[![OpenSSF Scorecard Score](https://api.scorecard.dev/projects/github.com/telekom/das-schiff-breakglass/badge)](https://scorecard.dev/viewer/?uri=github.com/telekom/das-schiff-breakglass/badge)

Golang application that allows for short-term elevation of privileges in an emergency situation.

## Overview

Application consist of golang backend and typescript vue frontend client.  
Main breakglass backend functionality is answering webhook authorization HTTP posts from configured clusters based
on permission abstraction that extends existing RBAC `Roles`.  
Breakglass introduces and manages several custom resource Kubernetes objects including `BreakglassSession`, `BreakglassEscalation`, `ClusterConfig`, and `DenyPolicy`.

## Documentation

Comprehensive documentation is available in the [docs/](./docs/) directory:

- **[ClusterConfig](./docs/cluster-config.md)** - Configure and manage tenant clusters
- **[BreakglassEscalation](./docs/breakglass-escalation.md)** - Define escalation policies and approval workflows
- **[BreakglassSession](./docs/breakglass-session.md)** - Manage active privilege escalation sessions
- **[DenyPolicy](./docs/deny-policy.md)** - Create explicit access restrictions
- **[Webhook Setup](./docs/webhook-setup.md)** - Configure Kubernetes authorization webhooks
- **[API Reference](./docs/api-reference.md)** - Complete REST API documentation

## Configuration

App should be configured using config.yaml:

```yaml
server:
  listenAddress: :8080
  tlsCertFile: /some/file.crt # optional
  tlsKeyFile: /some/file.key # optional for https
authorizationserver:
  url: http://127.0.0.1:8080
  jwksEndpoint: "realms/master/protocol/openid-connect/certs" # sample for keycloak
frontend:
  oidcAuthority: http://127.0.0.1:8080/realms/master
  oidcClientID: breakglass-ui
  baseURL: http://localhost:8080
mail:
  host: 127.0.0.1
  port: 1025
  insecureSkipVerify: false
kubernetes:
  context: "" # kubectl config context if empty default will be used
  oidcPrefixes: # List of prefixes to strip from user groups for cluster matching
    - "keycloak:"
    - "oidc:"

```

### OIDC Group Prefix Handling

When users authenticate through OIDC providers like Keycloak, their groups often come with provider-specific prefixes (e.g., `keycloak:admin`, `oidc:developers`). However, cluster RBAC rules typically use clean group names without prefixes (e.g., `admin`, `developers`).

The `oidcPrefixes` configuration allows the breakglass system to automatically strip these prefixes when comparing user groups from the OIDC provider with escalation rules in the cluster.

**Configuration Example:**

```yaml
kubernetes:
  oidcPrefixes:
    - "keycloak:"
    - "oidc:"
    - "ldap:"
```

**How it works:**

1. User authenticates via Keycloak and gets groups: `["keycloak:admin", "keycloak:developers", "system:authenticated"]`
2. Breakglass strips configured prefixes: `["admin", "developers", "system:authenticated"]`
3. These cleaned groups are used to match against escalation rules in `BreakglassEscalation` resources
4. This ensures that escalation rules can use clean group names like `admin` instead of provider-specific names like `keycloak:admin`

**Note:** The first matching prefix is stripped from each group. If no prefixes match, the group name remains unchanged.
See `config.example.yaml` for reference.

## Building Docker image

To build docker image:

```bash
docker build -t breakglass .
```

## Kubernetes Deployment

To deploy `CRD`, `RBAC` and application as `Deployment` configure `./config/default/config.yaml` with proper cluster
related configuration and run:

```bash
make deploy
```

Make sure that the configured authorization server URL and JWKS endpoint are reachable by the *server* process.
Note: the browser-side frontend no longer needs direct access to the authorization server when running with the
embedded API proxy. The server exposes the OIDC discovery/JWKS proxy at `/api/oidc/authority/*` so the frontend will
fetch discovery and JWKS from the API origin (avoids requiring a host-trusted Keycloak certificate for local e2e).

See `config/dev/resources/keycloak.yaml` for the sample Keycloak manifest used by the bundled kind setup script.

### Dev environment

```bash
make deploy_dev
```

Will perform similar deployment as standard `deploy`, but will additionally include deployment of keycloak and mailhog alongside
with services pointing to their open ports. It also includes NodePort type services so that application can be instantly
accessed.

#### Accessing app through docker kind cluster

It was tested for `kind` docker single cluster. <br/>
Assuming your docker container has ip of `172.19.0.2` add following entry to `/etc/hosts`: `172.19.0.2      breakglass-dev`.
Then you should be able to access main breakglass app under: `https://breakglass-dev:30081`, keycloak under: `https://breakglass-dev:30083`
and mailhog under `http://breakglass-dev:30084`.

#### First time configuring Keycloak

Go to `Clients` tab -> Create -> Add client called `breakglass-ui` or same as `breakglass-config.oidcClientID` -> Set
correct `Valid Redirect URIs` and `Web Origins` (for testing and developement setting all `*` will work).

## Configuring webhook on managed clusters

TODO

## Breakglass custom resources

### Session

`BreakglassSession` is used for storing information about permission
extension request and its status regarding approval, rejection or expiration.  <br/>
Sessions are fully managed by breakglass, by provided CRUD REST endpoints.<br/>

### Escalation

`BreglassEscalation` lets breakglass storage (CustomResource) cluster admins define possible transitions for breakglass
sessions. <br/>
Breakglass manager only lists escalations and they should be created manually using other means like `kubectl` tool.  <br/>
For BreakglassSession to be created there must be a corresponding BreaglassEscalation. <br/>
Single escalation defines group that user with specific user/cluster id and currently assigned groups can request for.
It also includes information about possible approvers.

## Creating BreakglassEscalations

## Cluster Configuration

```yaml
apiVersion: apiserver.config.k8s.io/v1beta1
kind: AuthorizationConfiguration
authorizers:
  - type: Node
    name: node
  - type: RBAC
    name: rbac
  - type: Webhook
    name: breakglass
    webhook:
      unauthorizedTTL: 30s
      timeout: 3s
      subjectAccessReviewVersion: v1
      matchConditionSubjectAccessReviewVersion: v1
      failurePolicy: Deny
      connectionInfo:
        type: KubeConfigFile
        kubeConfigFile: /etc/kubernetes/authorization-kubeconfig.yaml
      matchConditions: 
      - expression: "'system:authenticated' in request.groups"
      - expression: "!request.user.startsWith('system:')"
      - expression: "!('system:serviceaccounts' in request.groups)"
```

```yaml
apiVersion: v1
kind: Config
clusters:
  - name: breakglass
    cluster:
      certificate-authority-data: <CA BASE64 encoded>
  server: https://breakglass.mydomain/api/breakglass/webhook/authorize/<clustername>
users:
  - name: kube-apiserver
    user:
      token: dGhpc2lzanVzdGFkdW1teXRva2VuYXN3ZXNob3VsZG5vdG5lZWRvbmVoZXJl # dummy token
current-context: webhook
contexts:
  - context:
      cluster: breakglass
      user: kube-apiserver
    name: webhook
```
