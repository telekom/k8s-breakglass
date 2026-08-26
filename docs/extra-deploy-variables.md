# Extra Deploy Variables

`DebugSessionTemplate.spec.extraDeployVariables` lets template authors declare
customizable parameters that users may provide as values in
`DebugSession.spec.extraDeployValues` when requesting a debug session. The
template owns the variable names, types, defaults, and constraints. A declared
value can select an administrator-approved variant and change fields that the
template deliberately interpolates. The current renderer also carries
additional request keys into `.vars`; only declared variables are validated and
subject to group restrictions, so templates must not use undeclared values for
sensitive interpolation. Provider admission remains authoritative. This enables
a single template to support multiple use cases with different bounded
configurations.

## Overview

### Binding-level narrowing

`DebugSessionClusterBinding.spec.extraDeployVariables` may narrow variables
defined by the referenced template for a cluster or team. Each entry names an
existing template variable; its `options` list is an allow-list subset,
`validation` may tighten numeric/string bounds or add a regular expression,
`required` and `disabled` may only become stricter, and `default` must satisfy
the resulting policy. Unknown variables/options and attempts to relax a
template bound are rejected. Omitting the field preserves the existing
template-only behavior.

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
{{- if eq .vars.enableTcpdump "true" }}
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
namespace: customer-{{ .vars.customerName | k8sName }}
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
--iodepth={{ .vars.ioDepth }}
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
sizeLimit: {{ .vars.storageSize }}
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
{{- if eq .vars.networkMode "host" }}
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
    {{- range $cap := split "," .vars.capabilities }}
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
| Frontend | Hides unavailable options from the UI and disables debug session creation while visible variable validation errors are present |
| API | Returns `400 Bad Request` with details about which option/variable is restricted |
| Webhook | Admission validation rejects direct `kubectl` creation if user lacks access |

The API error response includes the required groups:

```json
{
  "error": "extraDeployValues validation failed",
  "code": "BAD_REQUEST",
  "details": "test[hostNetwork]: Forbidden: variable \"hostNetwork\" is restricted; requires membership in one of: [platform_poweruser schiff-admin]"
}
```

## YAML injection is blocked during template validation

Both variable builders preserve submitted values and defaults, including line
breaks and document markers. They do not sanitize or emit sanitization warnings.
`ValidateTemplateOutput` checks every template before pod and auxiliary-resource
rendering. Dynamic output must use an approved serializer (`yamlQuote`,
`yamlSafe`, `quote`, or `k8sName`); quoted serializers must occupy a complete YAML
scalar. Raw interpolation, surrounding quotes, and literal fragments around a
quoted serialized value are rejected before rendering.

For example, a value containing `worker-1\nhostNetwork: true` remains one quoted
string when rendered as `{{ .vars.node | yamlQuote }}`. It cannot create a sibling
`hostNetwork` key. The rendered pod still undergoes pod-security validation.

## Template Functions

### `yamlQuote`

Use `yamlQuote` to preserve a user-provided string as one YAML scalar:

```yaml
label: {{ .vars.customerName | yamlQuote }}
```

It always emits a double-quoted string, escaping line breaks and quotes and
preserving values such as `true` or `null` as strings. Do not add another pair
of quotes or concatenate literal text outside the serialized output.

### `yamlSafe`

Sanitizes strings by replacing dangerous characters:

```yaml
# Input: "test:value#comment"
# Output: "test-value-comment"
safe-label: {{ .vars.userInput | yamlSafe }}
```

### `k8sName`

Converts strings to valid Kubernetes names:

```yaml
# Input: "My Customer Name!"
# Output: "my-customer-name"
namespace: test-{{ .vars.customerName | k8sName }}
```

### `truncName`

Truncates strings to a maximum length:

```yaml
# Keep within 63 char limit
name: {{ printf "%s-suffix" (.session.name | truncName 50) | k8sName }}
```

## Complete Example

Start with the current paired CRDs in the
[DebugSession authoring guide](debug-session-authoring.md#minimal-workload-template).
Declare variables in `DebugSessionTemplate.spec.extraDeployVariables`; the pod
uses `DebugPodTemplate.spec.templateString` for dynamic rendering. Duration
constraints are static values, not Go templates. Use separate administrator
session templates when different users need different duration limits.

## Security Best Practices

1. **Always use `yamlQuote` for user values:**
   ```yaml
   label: {{ .vars.userInput | yamlQuote }}
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
   name: test-{{ .vars.customerName | k8sName }}
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

- [Debug Sessions](./debug-session.md)
- [API Reference](./api-reference.md#debug-sessions)
