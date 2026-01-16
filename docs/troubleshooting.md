# Troubleshooting Guide

This guide covers common issues and their solutions.

## Session Issues

### User Cannot Request Escalation

**Symptoms:** "No matching escalation found" or "Not authorized"

**Solutions:**

1. Verify escalation exists

```bash
kubectl get breakglassescalation -A
```

2. Verify user group membership - Check token claims

```bash
kubectl auth can-i get pods --as=user@example.com
```

3. Verify cluster name - Ensure session uses correct cluster name

```bash
kubectl get clusterconfig
```

4. Verify escalation scope - Check `allowed.clusters` contains your cluster

```bash
kubectl get breakglassescalation <name> -o yaml | grep -A 5 allowed
```

### Session Request Stuck in Pending

**Symptoms:** Request not being approved or rejected after hours

**Solutions:**

1. Verify approvers exist

```bash
kubectl get breakglassescalation <name> -o yaml | grep -A 5 approvers
```

2. Check OIDC group prefix stripping - See if groups are being mapped correctly

```bash
# Review config.yaml oidcPrefixes setting
cat config.yaml | grep -A 5 "kubernetes:"
```

3. Verify approver can access API

```bash
curl -H "Authorization: Bearer $APPROVER_TOKEN" \
  https://breakglass.example.com/api/breakglass/status
```

4. Check notification service - Verify email is configured for dev/test

```bash
# For dev: curl http://breakglass-dev:30084
# For prod: check configured email service
```

### Session Expired Unexpectedly

**Symptoms:** "Session expired" error within expected duration

**Solutions:**

1. Verify maxValidFor setting

```bash
kubectl get breakglasssession <name> -o yaml | grep -E "maxValidFor|expiresAt"
```

2. Check system clock synchronization

```bash
# On both hub and tenant clusters
date
```

## Webhook Issues

### Webhook Unreachable

**Symptoms:**

```
Error: failed to call webhook: connection refused
```

**Solutions:**

1. Test network connectivity from tenant cluster

```bash
ping breakglass.example.com
telnet breakglass.example.com 443
```

2. Check DNS resolution

```bash
nslookup breakglass.example.com
```

3. Verify firewall rules - Ensure egress from tenant to hub allowed

4. Test webhook endpoint

```bash
curl -k https://breakglass.example.com/api/breakglass/webhook/authorize/my-cluster
```

### Webhook Authentication Fails

**Symptoms:**

```
Error: Unauthorized (401)
```

**Solutions:**

1. Verify webhook token in kubeconfig is valid

```bash
echo $TOKEN | cut -d'.' -f2 | base64 -d | jq .
```

2. Check token expiration

```bash
echo $TOKEN | cut -d'.' -f2 | base64 -d | jq '.exp' | xargs -I{} date -d @{}
```

3. Validate kubeconfig format

```bash
kubectl --kubeconfig=/etc/kubernetes/breakglass-webhook-kubeconfig.yaml cluster-info
```

### Webhook Timeout

**Symptoms:**

```
Error: context deadline exceeded
```

**Solutions:**

1. Increase timeout in authorization config

```yaml
webhook:
  timeout: 5s
  unauthorizedTTL: 30s
```

2. Check network latency

```bash
ping -c 5 breakglass.example.com
```

3. **Check for recursive webhook calls** (multi-cluster OIDC setups only)

If you're using OIDC authentication for spoke clusters, the breakglass manager's OIDC identity may be triggering recursive webhook calls. See [Preventing Recursive Webhook Calls](webhook-setup.md#preventing-recursive-webhook-calls) for the full explanation.

**Quick fix:** Add the OIDC identity to the webhook's matchConditions exclusion:

```yaml
matchConditions:
  # ... existing conditions ...
  - expression: "request.user != 'breakglass-group-sync@service.local'"
```

And grant RBAC permissions to the OIDC identity on spoke clusters. See [RBAC Requirements for OIDC Authentication](cluster-config.md#rbac-requirements-for-oidc-authentication).

## Authorization Issues

### Authorization Always Denied

**Symptoms:** Requests denied despite active session

**Solutions:**

1. Verify session is approved

```bash
kubectl get breakglasssession <name> -o yaml | grep -E "conditions|approved"
```

2. Check DenyPolicy restrictions

```bash
kubectl get denypolicy
kubectl get denypolicy <name> -o yaml
```

3. Verify cluster name matches webhook URL path

4. Test webhook directly

```bash
curl -X POST https://breakglass.example.com/api/breakglass/webhook/authorize/prod-cluster-1 \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "apiVersion": "authorization.k8s.io/v1",
    "kind": "SubjectAccessReview",
    "spec": {
      "user": "test@example.com",
      "resourceAttributes": {
        "verb": "get",
        "resource": "pods"
      }
    }
  }'
```

### ClusterConfig Connection Failed

**Symptoms:** ClusterConfig phase shows "Failed"

**Solutions:**

1. Verify secret exists

```bash
kubectl get secret <secret-name> -n <namespace>
```

2. Verify kubeconfig is valid

```bash
kubectl get secret <secret-name> -n <namespace> \
  -o jsonpath='{.data.kubeconfig}' | base64 -d > /tmp/test.kubeconfig
kubectl --kubeconfig=/tmp/test.kubeconfig cluster-info
```

3. Test cluster access permissions

```bash
kubectl --kubeconfig=/tmp/test.kubeconfig auth can-i '*' '*'
```

## API Issues

### API Returns 500 Error

**Symptoms:** Internal server error on API calls

**Solutions:**

1. Review controller logs

```bash
kubectl logs -n breakglass-system deployment/breakglass-controller -f
```

2. Verify OIDC connectivity

```bash
curl https://keycloak.example.com/realms/master/.well-known/openid-configuration
```

### API Token Rejected

**Symptoms:** "Unauthorized" or "Invalid token"

**Solutions:**

1. Verify token from correct OIDC provider

```bash
echo $TOKEN | cut -d'.' -f2 | base64 -d | jq .
```

2. Check token issuer matches configured URL

3. Verify token groups - Check OIDC prefix stripping

```bash
echo $TOKEN | cut -d'.' -f2 | base64 -d | jq '.groups'
```

### Escalations Not Listed

**Symptoms:** API returns empty escalations

**Solutions:**

1. Verify user groups match escalation allowed groups

```bash
echo $TOKEN | cut -d'.' -f2 | base64 -d | jq '.groups'
kubectl get breakglassescalation -o yaml | grep -A 5 "allowed:"
```

2. Check group prefix stripping is working

## OIDC/Authentication Issues

### OIDC Discovery Fails

**Symptoms:** "Failed to fetch OIDC configuration"

**Solutions:**

1. Verify OIDC authority URL is accessible

```bash
curl https://keycloak.example.com/realms/master/.well-known/openid-configuration
```

2. Check TLS certificates

```bash
openssl s_client -connect keycloak.example.com:443
```

3. Test from breakglass pod

```bash
kubectl exec -it -n breakglass-system deployment/breakglass-controller -- \
  curl https://keycloak.example.com/realms/master/.well-known/openid-configuration
```

### Group Claims Missing

**Symptoms:** Users have no groups in token

**Solutions:**

1. Verify OIDC client has group mapper configured

2. Check Keycloak group mapper settings

3. Decode token to verify groups are included

```bash
echo $TOKEN | cut -d'.' -f2 | base64 -d | jq '.'
```

## ClusterConfig OIDC Authentication Issues

This section covers issues specific to `ClusterConfig` resources using `authType: OIDC` for authenticating to managed clusters.

### ClusterConfig Shows "OIDCDiscoveryFailed"

**Symptoms:** ClusterConfig status shows `Ready=False` with reason `OIDCDiscoveryFailed`

**Solutions:**

1. Verify the issuer URL is correct and accessible

```bash
# Check the ClusterConfig's OIDC issuer URL
kubectl get clusterconfig <name> -o yaml | grep issuerURL

# Test OIDC discovery endpoint
curl -s https://<issuer>/.well-known/openid-configuration | jq .
```

2. If using a private CA, ensure `certificateAuthority` is set in the OIDC config

```yaml
spec:
  oidcAuth:
    issuerURL: https://keycloak.internal.example.com/realms/kubernetes
    certificateAuthority: |
      -----BEGIN CERTIFICATE-----
      ...
      -----END CERTIFICATE-----
```

3. Check controller logs for detailed error

```bash
kubectl logs -n breakglass-system deployment/breakglass-controller | grep -i oidc
```

### ClusterConfig Shows "OIDCTokenFetchFailed"

**Symptoms:** ClusterConfig status shows `Ready=False` with reason `OIDCTokenFetchFailed`

**Solutions:**

1. Verify client credentials are correct

```bash
# Check the client secret exists
kubectl get secret <client-secret-name> -n <namespace>

# Test client credentials flow manually
curl -X POST https://<issuer>/protocol/openid-connect/token \
  -d "grant_type=client_credentials" \
  -d "client_id=<client-id>" \
  -d "client_secret=<client-secret>"
```

2. Verify the OIDC client has:
   - Service accounts enabled
   - Client credentials grant enabled
   - Correct permissions/roles

3. Check if the client is confidential (has a secret)

### ClusterConfig Shows "OIDCRefreshFailed"

**Symptoms:** ClusterConfig initially works but later shows `OIDCRefreshFailed`

**Solutions:**

1. Verify refresh tokens are enabled in the OIDC provider
2. Check token lifetimes are reasonable (not too short)
3. The controller will automatically fall back to re-authentication

### ClusterConfig Shows "SecretMissing" for OIDC

**Symptoms:** ClusterConfig status shows `Ready=False` mentioning OIDC client secret missing

**Solutions:**

1. Verify the secret exists in the correct namespace

```bash
kubectl get secret <name> -n <namespace>
```

2. Verify the secret has the correct key

```bash
kubectl get secret <name> -n <namespace> -o jsonpath='{.data}' | jq
```

3. Common key names are `client-secret` (default) or check your `clientSecretRef.key` setting

### ClusterConfig Using oidcFromIdentityProvider Shows "IdentityProvider not found"

**Symptoms:** ClusterConfig referencing an IdentityProvider fails with "not found" error

**Solutions:**

1. Verify the IdentityProvider exists

```bash
kubectl get identityprovider <name>
```

2. Verify the name matches exactly (case-sensitive)

```bash
# Check the reference in ClusterConfig
kubectl get clusterconfig <name> -o yaml | grep -A 3 oidcFromIdentityProvider
```

### ClusterConfig Using oidcFromIdentityProvider Shows "IdentityProvider is disabled"

**Symptoms:** ClusterConfig fails because referenced IdentityProvider is disabled

**Solutions:**

1. Enable the IdentityProvider

```bash
kubectl patch identityprovider <name> --type=merge -p '{"spec":{"disabled":false}}'
```

2. Or use a different IdentityProvider that is enabled

### Target Cluster Connection Fails with TLS Errors

**Symptoms:** "x509: certificate signed by unknown authority" or similar TLS errors

**Solutions:**

1. Provide the cluster CA certificate

```yaml
spec:
  oidcAuth:
    server: https://api.my-cluster.example.com:6443
    caSecretRef:
      name: cluster-ca-secret
      namespace: breakglass-system
      key: ca.crt
```

2. Or enable TOFU (Trust On First Use) - the controller will automatically trust the first CA it sees

3. As a last resort (NOT for production), use `insecureSkipTLSVerify: true`

### Debugging OIDC Token Issues

**Steps to debug:**

1. Check ClusterConfig status and conditions

```bash
kubectl get clusterconfig <name> -o yaml | grep -A 20 status
```

2. Look at controller logs

```bash
kubectl logs -n breakglass-system deployment/breakglass-controller --since=5m | grep -i "oidc\|token"
```

3. Test token acquisition manually using the configured credentials

4. Verify the target cluster accepts OIDC tokens

```bash
# Use kubectl with OIDC plugin to test
kubectl --server=https://api.cluster.example.com:6443 \
  --token=<oidc-token> \
  auth can-i get pods
```

## Deployment Issues

### Breakglass Pod Fails to Start

**Symptoms:** Pod in CrashLoopBackOff

**Solutions:**

1. Review pod logs

```bash
kubectl logs -n breakglass-system deployment/breakglass-controller
```

2. Check resource availability

```bash
kubectl top nodes
kubectl describe nodes
```

3. Verify ConfigMap and Secret exist

```bash
kubectl get configmap,secret -n breakglass-system
```

### High Memory/CPU Usage

**Symptoms:** Breakglass consuming excessive resources

**Solutions:**

1. Review metrics

```bash
kubectl top pod -n breakglass-system
```

2. Check for stuck reconciliation loops

```bash
kubectl logs -n breakglass-system deployment/breakglass-controller | grep "error"
```

## Performance Issues

### Slow Session Approval

**Symptoms:** Approval endpoint takes > 5 seconds

**Solutions:**

1. Monitor cluster connectivity latency

2. Check webhook authorization latency

```bash
kubectl logs -n breakglass-system deployment/breakglass-controller | \
  grep "authorization duration"
```

3. Optimize ClusterConfig QPS/Burst settings

```yaml
spec:
  qps: 200
  burst: 400
```

## Multi-IDP Issues

### Unknown Issuer Error

**Symptoms:** "Token issued by unknown issuer, please authenticate using one of the configured identity providers"

**Causes:**
- IdentityProvider's `issuer` field doesn't match token's `iss` claim
- Token from unconfigured provider
- Issuer URL has trailing slash mismatch

**Solutions:**

1. Extract the actual issuer from the token

```bash
TOKEN=$(your-token-here)
echo $TOKEN | cut -d'.' -f2 | base64 -d | jq .iss
```

2. Compare with configured IdentityProviders

```bash
kubectl get identityprovider -o yaml | grep -E "name:|issuer:"
```

3. Update the issuer if it doesn't match

```bash
kubectl patch identityprovider <name> -p '{"spec":{"issuer":"https://correct-issuer.example.com"}}'
```

### IDP Selection Screen Not Appearing

**Symptoms:** Only showing direct login, not IDP selector screen

**Causes:**
- Less than 2 IdentityProviders configured
- Only 1 provider has `disabled: false`

**Solutions:**

1. Check how many providers are enabled

```bash
kubectl get identityprovider -o yaml | grep -E "name:|disabled:"
```

2. Create or enable a second provider if needed

```bash
kubectl patch identityprovider <name> -p '{"spec":{"disabled":false}}'
```

### User Can't Access Multi-IDP Escalation

**Symptoms:** "Access denied" even though user has the escalation

**Causes:**
- Escalation restricted to different IDPs
- User's token from different IDP than expected

**Solutions:**

1. Check escalation's allowed IDPs

```bash
kubectl get breakglassescalation <name> -o yaml | grep -A 5 allowedIdentityProviders
```

2. Verify user's token IDP

```bash
TOKEN=$(your-token-here)
echo $TOKEN | cut -d'.' -f2 | base64 -d | jq .iss
```

3. Update escalation to allow user's IDP

```bash
kubectl patch breakglassescalation <name> -p '{"spec":{"allowedIdentityProvidersForRequests":["corp-oidc","keycloak-idp"]}}'
```

### Group Sync Failing for One IDP

**Symptoms:** GroupSyncStatus shows "PartialFailure" or "Failed"

**Causes:**
- IDP connection timeout
- Invalid Keycloak credentials
- Network issues

**Solutions:**

1. Check sync status and errors

```bash
kubectl get breakglassescalation <name> -o yaml | grep -A 10 "groupSync"
```

2. Check IdentityProvider events

```bash
kubectl describe identityprovider <name> | grep -A 5 "Events:"
```

3. Verify IDP is reachable

```bash
kubectl run -it debug --image=curlimages/curl --restart=Never -- \
  curl https://keycloak.example.com/health
```

4. Check credentials and permissions

```bash
kubectl get secret <secret-name> -o yaml
# Verify it has the right clientID and clientSecret
```

## General Debug Commands

View all resources:

```bash
kubectl get breakglassescalation,breakglasssession,clusterconfig,denypolicy -A
```

Check recent events:

```bash
kubectl describe deployment -n breakglass-system breakglass-controller
```

Stream logs with filtering:

```bash
kubectl logs -n breakglass-system deployment/breakglass-controller -f | grep -i error
```

Test OIDC token:

```bash
TOKEN=$(kubectl create token breakglass-webhook-sa -n breakglass-system)
echo $TOKEN | cut -d'.' -f2 | base64 -d | jq .
```

Check API health:

```bash
curl -k https://breakglass.example.com/api/breakglass/health
```

## Getting Help

If issues persist:

1. Collect debug information

```bash
kubectl get all -n breakglass-system -o yaml > debug.yaml
kubectl logs -n breakglass-system deployment/breakglass-controller > logs.txt
```

2. Search GitHub issues for similar problems

3. Review controller logs carefully - most issues are evident there

4. Test connectivity with curl directly

5. Verify all configuration files match requirements

## Related Resources

- [Webhook Setup](./webhook-setup.md) - Webhook configuration
- [Cluster Config](./cluster-config.md) - Cluster connection details
- [API Reference](./api-reference.md) - API endpoints
