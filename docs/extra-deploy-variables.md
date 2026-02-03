# Extra Deploy Variables

ExtraDeployVariables allow template authors to define customizable parameters that users can provide when requesting a debug session. This enables a single template to support multiple use cases with different configurations.

## Overview

Instead of creating many specialized templates (e.g., `netshoot-standard`, `netshoot-host-network`, `netshoot-customer-test`), you can create one unified template with variables that users select at request time:

```yaml
# Before: 6 separate templates
netshoot-standard.yaml
netshoot-host-network.yaml
netshoot-customer-test.yaml
tcpdump-capture.yaml
dns-debug.yaml
network-debug.yaml

# After: 1 unified template with variables
unified-network.yaml  # with networkMode, enableTcpdump, testPurpose variables
```

## Variable Types

### Boolean (`inputType: boolean`)

Simple on/off toggle.

```yaml
- name: enableTcpdump
  displayName: "Enable Packet Capture"
  description: "Add capabilities for tcpdump/packet capture"
  inputType: boolean
  default: false
```

**Usage in templates:**
```yaml
{{- if eq .Vars.enableTcpdump "true" }}
# Conditional content when enabled
{{- end }}
```

### Text (`inputType: text`)

Free-form text input with optional validation.

```yaml
- name: customerName
  displayName: "Customer Name"
  inputType: text
  required: true
  validation:
    minLength: 3
    maxLength: 40
    pattern: "^[a-z0-9][a-z0-9-]*[a-z0-9]$"
    patternError: "Must be lowercase alphanumeric with hyphens"
```

**Usage in templates:**
```yaml
namespace: customer-{{ .Vars.customerName | k8sName }}
```

### Number (`inputType: number`)

Numeric value with optional min/max constraints.

```yaml
- name: ioDepth
  displayName: "IO Depth"
  inputType: number
  default: "32"
  validation:
    min: "1"
    max: "256"
```

**Usage in templates:**
```yaml
--iodepth={{ .Vars.ioDepth }}
```

### Storage Size (`inputType: storageSize`)

Kubernetes quantity format for storage.

```yaml
- name: storageSize
  displayName: "Test Volume Size"
  inputType: storageSize
  default: "10Gi"
  validation:
    minStorage: "1Gi"
    maxStorage: "100Gi"
```

**Usage in templates:**
```yaml
sizeLimit: {{ .Vars.storageSize }}
```

### Select (`inputType: select`)

Single selection from predefined options.

```yaml
- name: networkMode
  displayName: "Network Mode"
  inputType: select
  default: "pod"
  options:
    - value: "pod"
      displayName: "Pod Network (standard)"
    - value: "host"
      displayName: "Host Network (elevated)"
      allowedGroups:  # Restrict this option
        - platform_poweruser
        - schiff-admin
```

**Usage in templates:**
```yaml
{{- if eq .Vars.networkMode "host" }}
hostNetwork: true
{{- end }}
```

### Multi-Select (`inputType: multiSelect`)

Multiple selections from predefined options.

```yaml
- name: capabilities
  displayName: "Capabilities"
  inputType: multiSelect
  options:
    - value: "NET_ADMIN"
    - value: "NET_RAW"
    - value: "SYS_ADMIN"
      allowedGroups: ["schiff-admin"]
  validation:
    minItems: 1
    maxItems: 5
```

**Usage in templates:**
```yaml
capabilities:
  add:
    {{- range $cap := split "," .Vars.capabilities }}
    - {{ $cap }}
    {{- end }}
```

## Access Control with `allowedGroups`

Restrict specific variable values to certain groups. This restriction is enforced both in the frontend UI (users only see options they're allowed to select) and server-side in the API (unauthorized selections are rejected with a 400 Bad Request error).

### Variable-Level Restrictions

Restrict who can use an entire variable:

```yaml
- name: hostNetwork
  displayName: "Host Network Mode"
  inputType: boolean
  allowedGroups:  # Only these groups can set this variable
    - platform_poweruser
    - schiff-admin
```

### Option-Level Restrictions

Restrict specific options within select/multiSelect:

```yaml
- name: accessLevel
  inputType: select
  options:
    - value: "readonly"
      displayName: "Read-Only (anyone)"
    - value: "nsenter"
      displayName: "Namespace Enter"
      allowedGroups:
        - platform_poweruser
    - value: "privileged"
      displayName: "Full Privileged"
      allowedGroups:
        - schiff-admin
        - platform_emergency
```

### Enforcement Behavior

| Location | Behavior |
|----------|----------|
| Frontend | Hides unavailable options from the UI |
| API | Returns `400 Bad Request` with details about which option/variable is restricted |
| Webhook | Admission validation rejects direct `kubectl` creation if user lacks access |

The API error response includes the required groups:

```json
{
  "error": "extraDeployValues validation failed",
  "errors": [
    "test[hostNetwork]: Forbidden: variable \"hostNetwork\" is restricted; requires membership in one of: [platform_poweruser schiff-admin]"
  ]
}
```

## Template Functions

### `yamlQuote`

**CRITICAL: Always use for user-provided values to prevent YAML injection.**

```yaml
# SAFE: User input is properly quoted
label: {{ .Vars.customerName | yamlQuote }}

# UNSAFE: Could break YAML if input contains special chars
label: {{ .Vars.customerName }}
```

The `yamlQuote` function:
- Wraps values in double quotes when needed
- Escapes special characters (`:`, `#`, `\n`, `"`, etc.)
- Handles YAML keywords (`true`, `false`, `null`)

### `yamlSafe`

Sanitizes strings by replacing dangerous characters:

```yaml
# Input: "test:value#comment"
# Output: "test-value-comment"
safe-label: {{ .Vars.userInput | yamlSafe }}
```

### `k8sName`

Converts strings to valid Kubernetes names:

```yaml
# Input: "My Customer Name!"
# Output: "my-customer-name"
namespace: test-{{ .Vars.customerName | k8sName }}
```

### `truncName`

Truncates strings to a maximum length:

```yaml
# Keep within 63 char limit
name: {{ .Session.Name | truncName 50 }}-suffix
```

## Complete Example

### DebugPodTemplate with Variables

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: DebugPodTemplate
metadata:
  name: unified-network
spec:
  displayName: "Unified Network Debug"
  description: "Network debugging with configurable access level"
  
  extraDeployVariables:
    - name: networkMode
      displayName: "Network Mode"
      inputType: select
      default: "pod"
      options:
        - value: "pod"
          displayName: "Pod Network"
        - value: "host"
          displayName: "Host Network"
          allowedGroups: ["platform_poweruser"]
    
    - name: enableCapture
      displayName: "Enable Packet Capture"
      inputType: boolean
      default: false
    
    - name: captureSize
      displayName: "Capture Storage"
      inputType: storageSize
      default: "5Gi"
      validation:
        minStorage: "1Gi"
        maxStorage: "50Gi"

  podTemplateString: |
    apiVersion: v1
    kind: Pod
    metadata:
      labels:
        network-mode: {{ .Vars.networkMode | yamlQuote }}
    spec:
      {{- if eq .Vars.networkMode "host" }}
      hostNetwork: true
      {{- end }}
      containers:
        - name: debug
          image: nicolaka/netshoot:v0.13
          command: ["sleep", "infinity"]
          {{- if eq .Vars.enableCapture "true" }}
          volumeMounts:
            - name: captures
              mountPath: /captures
          {{- end }}
      {{- if eq .Vars.enableCapture "true" }}
      volumes:
        - name: captures
          emptyDir:
            sizeLimit: {{ .Vars.captureSize }}
      {{- end }}
```

### DebugSessionTemplate Using the Pod Template

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: DebugSessionTemplate
metadata:
  name: network-debug
spec:
  displayName: "Network Debug Session"
  mode: workload
  
  podTemplateRef:
    name: unified-network
  
  # Session-level variables (in addition to pod template vars)
  extraDeployVariables:
    - name: severity
      displayName: "Incident Severity"
      inputType: select
      default: "standard"
      options:
        - value: "standard"
          displayName: "Standard (2h max)"
        - value: "incident"
          displayName: "Incident (8h max)"
          allowedGroups: ["platform_poweruser"]
  
  constraints:
    maxDuration: "{{ if eq .Vars.severity \"incident\" }}8h{{ else }}2h{{ end }}"
```

## Security Best Practices

1. **Always use `yamlQuote` for user values:**
   ```yaml
   label: {{ .Vars.userInput | yamlQuote }}
   ```

2. **Use `allowedGroups` for sensitive options:**
   ```yaml
   - value: "privileged"
     allowedGroups: ["schiff-admin"]
   ```

3. **Validate input with patterns:**
   ```yaml
   validation:
     pattern: "^[a-z0-9-]+$"
     patternError: "Only lowercase alphanumeric and hyphens"
   ```

4. **Set reasonable defaults:**
   ```yaml
   default: "pod"  # Least-privilege default
   ```

5. **Use `k8sName` for generated resource names:**
   ```yaml
   name: test-{{ .Vars.customerName | k8sName }}
   ```

## Validation Rules

| Input Type | Validation Options |
|------------|-------------------|
| text | `minLength`, `maxLength`, `pattern`, `patternError` |
| number | `min`, `max` |
| storageSize | `minStorage`, `maxStorage` |
| select | Options list with optional `allowedGroups` |
| multiSelect | Options list + `minItems`, `maxItems` |
| boolean | None (true/false only) |

## See Also

- [Debug Session Templates](./debug-session-template.md)
- [Template Security](./template-security.md)
- [API Reference](./api-reference.md#debug-sessions)
