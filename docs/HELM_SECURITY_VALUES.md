# Helm Chart Security Context Configuration

## Overview

The Helm chart for breakglass-controller has been updated with security-hardened defaults for:

- Resource requests and limits
- Container security context
- Pod security context

## Values Added

### Resource Configuration

```yaml
manager:
  breakglass:
    resources:
      requests:
        cpu: 100m
        memory: 128Mi
      limits:
        cpu: 500m
        memory: 512Mi
```

**Purpose**: Ensures predictable resource allocation and prevents resource starvation.

- **CPU Requests**: 100m (0.1 core) - baseline allocation
- **CPU Limits**: 500m (0.5 core) - maximum allowed
- **Memory Requests**: 128Mi - baseline allocation
- **Memory Limits**: 512Mi - maximum allowed

### Container Security Context

```yaml
manager:
  breakglass:
    containerSecurityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop:
          - ALL
      readOnlyRootFilesystem: true
      runAsNonRoot: true
```

**Purpose**: Restricts container capabilities and enforces principle of least privilege.

- **allowPrivilegeEscalation: false** - Prevents privilege escalation
- **capabilities.drop: ALL** - Removes all Linux capabilities
- **readOnlyRootFilesystem: true** - Root filesystem is read-only (protects system files)
- **runAsNonRoot: true** - Container must run as non-root user

### Pod Security Context

```yaml
manager:
  podSecurityContext:
    runAsNonRoot: true
    runAsUser: 65532
    fsGroup: 65532
    seccompProfile:
      type: RuntimeDefault
```

**Purpose**: Applies pod-level security policies and user isolation.

- **runAsNonRoot: true** - Pod runs as non-root
- **runAsUser: 65532** - Runs as numeric UID 65532 (nobody user)
- **fsGroup: 65532** - File system group for volume permissions
- **seccompProfile.type: RuntimeDefault** - Uses default seccomp profile (blocks dangerous syscalls)

## Helm Template Usage

The deployment template automatically applies these values:

```yaml
spec:
  containers:
  - name: breakglass
    resources: {{- toYaml .Values.manager.breakglass.resources | nindent 10 }}
    securityContext: {{- toYaml .Values.manager.breakglass.containerSecurityContext | nindent 10 }}
    
  securityContext: {{- toYaml .Values.manager.podSecurityContext | nindent 8 }}
```

## Customization

To customize these values, override them when installing/upgrading:

```bash
# Override resource limits
helm install breakglass ./charts/breakglass-controller \
  --set manager.breakglass.resources.limits.memory=1Gi \
  --set manager.breakglass.resources.limits.cpu=1000m

# Override security context (less restrictive for development)
helm install breakglass ./charts/breakglass-controller \
  --set manager.breakglass.containerSecurityContext.readOnlyRootFilesystem=false

# Or use a custom values file
helm install breakglass ./charts/breakglass-controller \
  -f custom-values.yaml
```

## Custom Values File Example

```yaml
# custom-values.yaml for production
manager:
  replicas: 2
  breakglass:
    resources:
      requests:
        cpu: 250m
        memory: 256Mi
      limits:
        cpu: 1000m
        memory: 1Gi
    containerSecurityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop:
          - ALL
      readOnlyRootFilesystem: true
      runAsNonRoot: true
  podSecurityContext:
    runAsNonRoot: true
    runAsUser: 65532
    fsGroup: 65532
    seccompProfile:
      type: RuntimeDefault
  nodeSelector:
    workload: breakglass
  tolerations:
    - key: breakglass
      operator: Equal
      value: "true"
      effect: NoSchedule
```

## Security Best Practices Applied

1. **Non-root execution** - Container runs as UID 65532 (nobody)
2. **Read-only filesystem** - Prevents unauthorized modifications
3. **No privilege escalation** - Container cannot escalate to root
4. **Minimal capabilities** - All Linux capabilities removed
5. **Seccomp profile** - Restricts system calls
6. **Resource limits** - Prevents resource exhaustion attacks
7. **Pod security context** - File system group isolation

## Deployment Template

File: `charts/breakglass-controller/templates/deployment.yaml`

The template now uses the values:

```yaml
spec:
  containers:
  - image: {{ .Values.manager.breakglass.image.repository }}:{{ .Values.manager.breakglass.image.tag }}
    name: breakglass
    resources: {{- toYaml .Values.manager.breakglass.resources | nindent 10 }}
    securityContext: {{- toYaml .Values.manager.breakglass.containerSecurityContext | nindent 10 }}
    volumeMounts:
    - mountPath: /config/
      name: config
      readOnly: true
    - mountPath: /tmp/k8s-webhook-server/serving-certs
      name: webhook-certs
      readOnly: true
  securityContext: {{- toYaml .Values.manager.podSecurityContext | nindent 8 }}
  serviceAccountName: {{ include "breakglass-controller.serviceAccountName" . }}
```

## Files Modified

- `charts/breakglass-controller/values.yaml` - Added resource and security context values
- `charts/breakglass-controller/templates/deployment.yaml` - Already uses values (no changes needed)

## Verification

To verify the values are correctly applied:

```bash
# Template the chart to see the rendered output
helm template breakglass ./charts/breakglass-controller

# Install with debug to see what's being applied
helm install breakglass ./charts/breakglass-controller --debug --dry-run
```
