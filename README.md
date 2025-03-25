# Breakglass
Golang application that allows for short-term elevation of privileges in an emergency situation.

## Overview

## Configuration
App should be configured using config.yaml:
```yaml
server:
  listenAddress: :8080
  tlsCertFile: /some/file.crt # optional
  tlsKeyFile: /some/file.key # optional for https
  baseURL: http://breakglass.example.telekom.de
authorizationserver:
  url: http://127.0.0.1:8080
  jwksEndpoint: "realms/master/protocol/openid-connect/certs" # sample for keycloak
frontend:
  oidcAuthority: http://127.0.0.1:8080/realms/master
  oidcClientID: breakglass-ui
  baseURL: http://localhost:5173
mail:
  host: 127.0.0.1
  port: 1025
  insecureSkipVerify: false
kubernetes:
  context: "" # kubectl config context if empty default will be used

```
See `config.example.yaml` for reference.

## Building 
To build docker image:
```bash
docker build -t breakglass .
```
## Deployment
To deploy `CRD`, `RBAC` and application as `Deployment` configure `./config/default/config.yaml` with proper cluster
related configuration and run:
```bash
make deploy
```

### Dev environment:
```bash
make deploy_dev
```
Will perform the same deployment as standard `deploy`, but will additionally include deployment of keycloak and mailhog alongside
with services pointing to their open port. 
