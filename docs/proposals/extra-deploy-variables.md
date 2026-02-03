# Proposal: ExtraDeploy Variables and Templatable Resources

**Status**: ✅ FULLY IMPLEMENTED  
**Author**: Platform Team  
**Created**: 2026-01-30  
**Target Release**: v0.2.0

## Implementation Status

### ✅ Phase 1-2 Implemented (API Types)

The following API types and fields have been implemented:

1. **ExtraDeployVariable type** (`api/v1alpha1/extra_deploy_types.go`)
   - All input types: `boolean`, `text`, `number`, `storageSize`, `select`, `multiSelect`
   - `SelectOption` for dropdown choices
   - `VariableValidation` for pattern, min/max, length constraints
   - Variable grouping, advanced flags, and access control fields

2. **DebugSessionTemplateSpec additions**:
   - `extraDeployVariables` - Define user-input variables
   - `podTemplateString` - Inline templated pod spec YAML
   - `podOverridesTemplate` - Templated pod overrides

3. **DebugSessionSpec additions**:
   - `extraDeployValues` - User-provided values (map of `apiextensionsv1.JSON`)

4. **AuxiliaryResource additions**:
   - `templateString` - Go template producing multi-doc YAML
   - Made `template` optional (for backward compatibility)

5. **AuxiliaryResourceContext additions**:
   - `Vars` - User-provided values accessible in templates
   - `Now` - Current timestamp
   - `EnabledResources` - List of enabled auxiliary resources

6. **Webhook Validation**:
   - Variable name validation (Go identifiers)
   - Duplicate detection
   - Options required for select/multiSelect
   - Validation rule type checking

### ✅ Phase 3 Implemented (Pod Template Rendering)

1. **Pod Template Rendering** (`pkg/breakglass/debug_session_reconciler.go`)
   - `renderPodTemplateString()` - Renders fully templated pod specs with Go template + Sprig functions
   - `renderPodOverridesTemplate()` - Renders templated pod overrides (image, command, args, env)
   - Template context includes `.Session`, `.Template`, `.Cluster`, `.Namespace`, `.Vars`, and `.Impersonation`

2. **Value Validation** (`api/v1alpha1/extra_deploy_validation.go`)
   - `ValidateExtraDeployValues()` validates user-provided values against template variable definitions
   - Type-specific validation: pattern/length for text, min/max for numbers, size ranges for storage
   - Required field validation, select option validation, multiSelect item count constraints

3. **Comprehensive Tests** (`pkg/breakglass/pod_template_rendering_test.go`, `api/v1alpha1/extra_deploy_validation_test.go`)
   - Tests for pod template rendering, pod overrides rendering
   - Tests for all validation types and edge cases

### ✅ Phase 4 Implemented (Frontend Integration)

1. **TypeScript Types** (`frontend/src/model/debugSession.ts`)
   - `ExtraDeployInputType`, `SelectOption`, `VariableValidation`, `ExtraDeployVariable`
   - `ExtraDeployValues` type for user-provided values
   - Updated `DebugSessionTemplateResponse` and `CreateDebugSessionRequest`

2. **VariableForm Component** (`frontend/src/components/debug-session/VariableForm.vue`)
   - Dynamically renders forms based on template variable definitions
   - Support for all input types: boolean, text, number, storageSize, select, multiSelect
   - Variable grouping by `group` field with collapsible sections
   - Advanced variable toggle (show/hide `advanced: true` variables)
   - Group-based visibility filtering via `allowedGroups` field
   - Client-side validation with inline error messages

3. **DebugSessionCreate Integration** (`frontend/src/views/DebugSessionCreate.vue`)
   - Integrated VariableForm component in Step 2 (Session Details)
   - User groups loaded from auth for variable visibility filtering
   - `extraDeployValues` submitted with session creation request

4. **Unit Tests** (`frontend/tests/unit/variableForm.spec.ts`)
   - Tests for variable visibility filtering
   - Tests for advanced toggle behavior
   - Tests for validation and default value initialization

## Summary

Enable user-provided variables at DebugSession request time that flow into templatable resources. This allows flexible, dynamic resource creation for use cases like storage testing (fio with custom PVCs), network testing with custom configurations, and other scenarios requiring user input.

## Motivation

### Current Limitations

1. **Fixed auxiliary resources**: Templates define static resources that cannot be customized per session
2. **No user input at request time**: Users cannot provide test-specific values (PVC names, sizes, storage classes)
3. **Single resource per definition**: Each `AuxiliaryResource` produces exactly one K8s resource
4. **Static pod templates**: `DebugPodTemplate` and `podOverrides` cannot reference dynamic values

### Use Cases

1. **Storage Testing (fio/kubstr)**
   - User specifies PVC size, storage class, existing PVC name
   - Template creates PVC, ConfigMap with fio job, mounts volumes dynamically

2. **Network Testing**
   - User provides target endpoints, test parameters
   - Template creates test-specific ConfigMaps

3. **Custom Debug Environments**
   - User selects tools/packages to install
   - Template adjusts init containers or environment variables

## Design

### Core Principle: Template Everything

All resource definitions become Go templates with access to a unified render context including user-provided variables.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          DebugSessionTemplate                            │
├─────────────────────────────────────────────────────────────────────────┤
│  extraDeployVariables:     ──► User fills in at request time            │
│    - name: pvcSize                                                       │
│    - name: storageClass                                                  │
│    - name: testName                                                      │
├─────────────────────────────────────────────────────────────────────────┤
│  podTemplateRef: ─────────────► DebugPodTemplate                        │
│    OR                            (can use {{ .Vars.* }})                │
│  podTemplateString: ──────────► Inline templated pod spec               │
├─────────────────────────────────────────────────────────────────────────┤
│  podOverridesTemplate: ───────► Templated pod overrides                 │
│                                  (merged with pod template)              │
├─────────────────────────────────────────────────────────────────────────┤
│  auxiliaryResources:                                                     │
│    - templateString: |        ──► Multi-doc YAML with templating        │
│        apiVersion: v1                                                    │
│        kind: PVC                                                         │
│        ...{{ .Vars.pvcSize }}                                           │
│        ---                                                               │
│        apiVersion: v1                                                    │
│        kind: ConfigMap                                                   │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                            DebugSession                                  │
├─────────────────────────────────────────────────────────────────────────┤
│  extraDeployValues:                                                      │
│    pvcSize: "50Gi"                                                       │
│    storageClass: "csi-cinder-replicated"                                │
│    testName: "customer-xyz"                                              │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         Render Context                                   │
├─────────────────────────────────────────────────────────────────────────┤
│  .Session    - Session metadata (name, namespace, cluster, user, etc.)  │
│  .Target     - Target namespace and cluster info                         │
│  .Template   - Template metadata                                         │
│  .Binding    - Binding info (if used)                                    │
│  .Labels     - Standard breakglass labels                                │
│  .Annotations- Standard breakglass annotations                          │
│  .Vars       - User-provided extraDeployValues ◄── THE KEY ADDITION     │
│  .Now        - Current timestamp                                         │
│  .EnabledResources - List of enabled auxiliary resources                │
└─────────────────────────────────────────────────────────────────────────┘
```

## API Changes

### 1. ExtraDeployVariable Type

New type for defining user-provided variables:

```go
// ExtraDeployVariable defines a user-provided variable for template rendering.
// Variables are available as {{ .Vars.<name> }} in all templates.
type ExtraDeployVariable struct {
    // name is the variable name, used as {{ .Vars.<name> }} in templates.
    // Must be a valid Go identifier (letters, digits, underscores, starting with letter).
    // +required
    // +kubebuilder:validation:Pattern=`^[a-zA-Z][a-zA-Z0-9_]*$`
    // +kubebuilder:validation:MinLength=1
    // +kubebuilder:validation:MaxLength=63
    Name string `json:"name"`

    // displayName is the human-readable label shown in the UI.
    // +optional
    DisplayName string `json:"displayName,omitempty"`

    // description provides help text for the user.
    // +optional
    Description string `json:"description,omitempty"`

    // inputType defines the UI input control and value type.
    // +kubebuilder:validation:Enum=boolean;text;number;storageSize;select;multiSelect
    // +kubebuilder:default="text"
    InputType ExtraDeployInputType `json:"inputType,omitempty"`

    // options provides choices for select/multiSelect input types.
    // Required when inputType is select or multiSelect.
    // +optional
    Options []SelectOption `json:"options,omitempty"`

    // default is the default value if user doesn't provide one.
    // Type must match inputType.
    // +optional
    Default *apiextensionsv1.JSON `json:"default,omitempty"`

    // required indicates this variable must be provided by the user.
    // Variables without defaults are implicitly required.
    // +optional
    Required bool `json:"required,omitempty"`

    // validation defines constraints for the input value.
    // +optional
    Validation *VariableValidation `json:"validation,omitempty"`

    // allowedGroups restricts who can set this variable.
    // If empty, all users with template access can set it.
    // +optional
    AllowedGroups []string `json:"allowedGroups,omitempty"`

    // advanced marks this variable as advanced/expert.
    // Advanced variables may be hidden behind an "Advanced" toggle in UI.
    // +optional
    Advanced bool `json:"advanced,omitempty"`

    // group organizes variables into collapsible sections in the UI.
    // +optional
    Group string `json:"group,omitempty"`
}

// ExtraDeployInputType defines the type of input control.
type ExtraDeployInputType string

const (
    // InputTypeBoolean renders as a checkbox/toggle.
    // Value type: bool
    InputTypeBoolean ExtraDeployInputType = "boolean"

    // InputTypeText renders as a text input field.
    // Value type: string
    InputTypeText ExtraDeployInputType = "text"

    // InputTypeNumber renders as a number input.
    // Value type: float64 (JSON number)
    InputTypeNumber ExtraDeployInputType = "number"

    // InputTypeStorageSize renders as a storage size input (e.g., "10Gi").
    // Value type: string (Kubernetes quantity format)
    InputTypeStorageSize ExtraDeployInputType = "storageSize"

    // InputTypeSelect renders as a single-choice dropdown.
    // Value type: string (one of Options[].Value)
    InputTypeSelect ExtraDeployInputType = "select"

    // InputTypeMultiSelect renders as a multi-choice selector.
    // Value type: []string (subset of Options[].Value)
    InputTypeMultiSelect ExtraDeployInputType = "multiSelect"
)

// SelectOption defines a choice for select/multiSelect inputs.
type SelectOption struct {
    // value is the actual value stored and used in templates.
    // +required
    Value string `json:"value"`

    // displayName is shown in the UI (defaults to value if empty).
    // +optional
    DisplayName string `json:"displayName,omitempty"`

    // description provides additional context shown as tooltip/help.
    // +optional
    Description string `json:"description,omitempty"`

    // disabled prevents this option from being selected.
    // Useful for showing unavailable options.
    // +optional
    Disabled bool `json:"disabled,omitempty"`

    // allowedGroups restricts who can select this option.
    // +optional
    AllowedGroups []string `json:"allowedGroups,omitempty"`
}

// VariableValidation defines validation rules for input values.
type VariableValidation struct {
    // pattern is a regex pattern for text inputs.
    // +optional
    Pattern string `json:"pattern,omitempty"`

    // patternError is a custom error message when pattern fails.
    // +optional
    PatternError string `json:"patternError,omitempty"`

    // minLength is the minimum string length for text inputs.
    // +optional
    MinLength *int `json:"minLength,omitempty"`

    // maxLength is the maximum string length for text inputs.
    // +optional
    MaxLength *int `json:"maxLength,omitempty"`

    // min is the minimum value for number inputs.
    // +optional
    Min *float64 `json:"min,omitempty"`

    // max is the maximum value for number inputs.
    // +optional
    Max *float64 `json:"max,omitempty"`

    // minStorage is the minimum size for storageSize inputs (e.g., "1Gi").
    // +optional
    MinStorage string `json:"minStorage,omitempty"`

    // maxStorage is the maximum size for storageSize inputs (e.g., "1Ti").
    // +optional
    MaxStorage string `json:"maxStorage,omitempty"`

    // minItems is the minimum selections for multiSelect inputs.
    // +optional
    MinItems *int `json:"minItems,omitempty"`

    // maxItems is the maximum selections for multiSelect inputs.
    // +optional
    MaxItems *int `json:"maxItems,omitempty"`
}
```

### 2. DebugSessionTemplateSpec Changes

```go
type DebugSessionTemplateSpec struct {
    // ... existing fields ...

    // extraDeployVariables defines user-provided variables for template rendering.
    // These values are collected from the user at session request time
    // and made available as {{ .Vars.<name> }} in all templates.
    // +optional
    ExtraDeployVariables []ExtraDeployVariable `json:"extraDeployVariables,omitempty"`

    // podTemplateRef references a DebugPodTemplate by name.
    // The referenced template can itself contain {{ .Vars.* }} placeholders.
    // Mutually exclusive with podTemplateString.
    // +optional
    PodTemplateRef *DebugPodTemplateReference `json:"podTemplateRef,omitempty"`

    // podTemplateString is an inline Go template that produces pod spec YAML.
    // Use this for fully dynamic pod specifications.
    // Mutually exclusive with podTemplateRef.
    // +optional
    PodTemplateString string `json:"podTemplateString,omitempty"`

    // podOverridesTemplate is a Go template that produces pod override YAML.
    // Rendered with full context including user variables.
    // The result is merged with podTemplateRef/podTemplateString output.
    // +optional
    PodOverridesTemplate string `json:"podOverridesTemplate,omitempty"`

    // podOverrides is the legacy static pod overrides (not templated).
    // DEPRECATED: Use podOverridesTemplate for new templates.
    // +optional
    PodOverrides *DebugPodOverrides `json:"podOverrides,omitempty"`
}
```

### 3. DebugPodTemplateSpec Changes

```go
type DebugPodTemplateSpec struct {
    // displayName is a human-readable name for this template.
    // +optional
    DisplayName string `json:"displayName,omitempty"`

    // description provides detailed information about what this template does.
    // +optional
    Description string `json:"description,omitempty"`

    // template defines the pod specification as a structured object.
    // Cannot contain template expressions.
    // Mutually exclusive with templateString.
    // +optional
    Template *DebugPodSpec `json:"template,omitempty"`

    // templateString is a Go template that produces pod spec YAML.
    // Supports {{ .Vars.* }} and other context variables.
    // Mutually exclusive with template.
    // +optional
    TemplateString string `json:"templateString,omitempty"`

    // variables defines variables that THIS pod template expects.
    // These are merged with DebugSessionTemplate.extraDeployVariables.
    // Useful for pod templates that require specific inputs.
    // +optional
    Variables []ExtraDeployVariable `json:"variables,omitempty"`
}
```

### 4. AuxiliaryResource Changes

```go
type AuxiliaryResource struct {
    // name is a unique identifier for this auxiliary resource.
    // +required
    Name string `json:"name"`

    // description explains what this resource does.
    // +optional
    Description string `json:"description,omitempty"`

    // category is the resource category for enable/disable logic.
    // +optional
    Category string `json:"category,omitempty"`

    // templateString is a Go template that produces one or more YAML documents.
    // Use `---` separator for multiple resources from one definition.
    // +optional
    TemplateString string `json:"templateString,omitempty"`

    // template is the legacy embedded resource template (raw JSON/YAML).
    // DEPRECATED: Use templateString for new templates.
    // +optional
    Template runtime.RawExtension `json:"template,omitempty"`

    // createBefore specifies if this resource should be created before debug pods.
    // +optional
    // +kubebuilder:default=true
    CreateBefore bool `json:"createBefore,omitempty"`

    // deleteAfter specifies if this resource should be deleted after session ends.
    // +optional
    // +kubebuilder:default=true
    DeleteAfter bool `json:"deleteAfter,omitempty"`

    // failurePolicy determines behavior if resource creation fails.
    // +optional
    // +kubebuilder:default="fail"
    FailurePolicy AuxiliaryResourceFailurePolicy `json:"failurePolicy,omitempty"`
}
```

### 5. DebugSessionSpec Changes

```go
type DebugSessionSpec struct {
    // ... existing fields ...

    // extraDeployValues contains user-provided values for extraDeployVariables.
    // Keys must match variable names defined in the template.
    // Values are validated against the variable's inputType and validation rules.
    // +optional
    ExtraDeployValues map[string]apiextensionsv1.JSON `json:"extraDeployValues,omitempty"`
}
```

### 6. Expanded Render Context

```go
// TemplateRenderContext is the full context available to all templates.
type TemplateRenderContext struct {
    // Session information
    Session struct {
        Name        string `json:"name"`
        Namespace   string `json:"namespace"`
        Cluster     string `json:"cluster"`
        RequestedBy string `json:"requestedBy"`
        ApprovedBy  string `json:"approvedBy,omitempty"`
        Reason      string `json:"reason"`
        ExpiresAt   string `json:"expiresAt"`
    } `json:"session"`

    // Target cluster/namespace information
    Target struct {
        Namespace   string `json:"namespace"`
        ClusterName string `json:"clusterName"`
    } `json:"target"`

    // Template metadata
    Template struct {
        Name        string `json:"name"`
        DisplayName string `json:"displayName,omitempty"`
    } `json:"template"`

    // Binding metadata (if used)
    Binding struct {
        Name      string `json:"name,omitempty"`
        Namespace string `json:"namespace,omitempty"`
    } `json:"binding"`

    // Standard labels to apply to all resources
    Labels map[string]string `json:"labels"`

    // Standard annotations to apply to all resources
    Annotations map[string]string `json:"annotations"`

    // Vars contains user-provided extraDeployValues
    // Access as {{ .Vars.variableName }}
    Vars map[string]interface{} `json:"vars"`

    // Now is the current timestamp for time-based logic
    Now time.Time `json:"now"`

    // EnabledResources lists which auxiliary resources will be deployed
    // Useful for conditional logic based on what else is being deployed
    EnabledResources []string `json:"enabledResources"`
}
```

## Template Functions

All templates have access to [Sprig template functions](http://masterminds.github.io/sprig/) plus custom Breakglass functions:

### Sprig Functions (Highlights)

- **Strings**: `trim`, `upper`, `lower`, `title`, `replace`, `trunc`, `quote`
- **String Lists**: `join`, `split`, `splitList`
- **Math**: `add`, `sub`, `mul`, `div`, `mod`, `max`, `min`
- **Defaults**: `default`, `empty`, `coalesce`, `ternary`
- **Encoding**: `b64enc`, `b64dec`, `toJson`, `fromJson`, `toYaml`
- **Lists**: `list`, `first`, `rest`, `last`, `append`, `prepend`, `has`
- **Dictionaries**: `dict`, `get`, `set`, `hasKey`, `keys`, `values`, `merge`
- **Flow Control**: Go's `if`, `else`, `range`, `with`, `define`, `template`

### Custom Breakglass Functions

```go
// truncName truncates a name to fit K8s 63-char limit while keeping it unique
// Usage: {{ .Session.Name | truncName 20 }}
func truncName(maxLen int, name string) string

// k8sName sanitizes a string to be a valid K8s name
// Usage: {{ .Vars.testName | k8sName }}
func k8sName(s string) string

// parseQuantity parses a K8s quantity string to bytes
// Usage: {{ .Vars.pvcSize | parseQuantity }}
func parseQuantity(s string) int64

// formatQuantity formats bytes as K8s quantity
// Usage: {{ mul .Vars.sizeGi 1073741824 | formatQuantity }}
func formatQuantity(bytes int64) string
```

## Examples

### Example 1: Storage Test Template

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: DebugSessionTemplate
metadata:
  name: storage-test-advanced
  labels:
    breakglass.t-caas.telekom.com/category: storage
    breakglass.t-caas.telekom.com/persona: onboarding
spec:
  displayName: "Storage Performance Test"
  description: "Run fio storage benchmarks with configurable PVCs"
  mode: workload
  workloadType: Deployment
  replicas: 1
  targetNamespace: breakglass-debug

  # ═══════════════════════════════════════════════════════════════════════
  # User-provided variables - these appear as a form in the UI
  # ═══════════════════════════════════════════════════════════════════════
  extraDeployVariables:
    # Basic settings group
    - name: testName
      displayName: "Test Name"
      description: "Identifier for this test (used in resource names)"
      inputType: text
      required: true
      group: basic
      validation:
        pattern: "^[a-z0-9][a-z0-9-]*[a-z0-9]$"
        patternError: "Must be lowercase alphanumeric with hyphens"
        minLength: 3
        maxLength: 20

    # PVC settings group
    - name: createPvc
      displayName: "Create Test PVC"
      description: "Create an ephemeral PVC for testing (deleted after session)"
      inputType: boolean
      default: true
      group: pvc

    - name: pvcSize
      displayName: "PVC Size"
      description: "Size of the test PVC"
      inputType: storageSize
      default: "10Gi"
      group: pvc
      validation:
        minStorage: "1Gi"
        maxStorage: "500Gi"

    - name: storageClass
      displayName: "Storage Class"
      description: "Storage class for the test PVC"
      inputType: text
      default: "csi-cinder-high-speed"
      group: pvc

    - name: accessMode
      displayName: "Access Mode"
      inputType: select
      default: "ReadWriteOnce"
      group: pvc
      options:
        - value: ReadWriteOnce
          displayName: "ReadWriteOnce (RWO)"
          description: "Single node read-write"
        - value: ReadWriteMany
          displayName: "ReadWriteMany (RWX)"
          description: "Multi-node read-write"
        - value: ReadOnlyMany
          displayName: "ReadOnlyMany (ROX)"
          description: "Multi-node read-only"

    # Existing PVC (optional)
    - name: existingPvcName
      displayName: "Existing PVC Name"
      description: "Mount an existing PVC for comparison (leave empty to skip)"
      inputType: text
      required: false
      group: pvc
      advanced: true

    # FIO settings group
    - name: fioTestType
      displayName: "I/O Test Type"
      inputType: select
      default: "randrw"
      group: fio
      options:
        - value: randrw
          displayName: "Random Read/Write"
          description: "Mixed random I/O (database workload)"
        - value: read
          displayName: "Sequential Read"
        - value: write
          displayName: "Sequential Write"
        - value: randread
          displayName: "Random Read (IOPS)"
        - value: randwrite
          displayName: "Random Write (IOPS)"

    - name: fioBlockSize
      displayName: "Block Size"
      inputType: select
      default: "4k"
      group: fio
      options:
        - value: 4k
          displayName: "4K (random I/O)"
        - value: 64k
          displayName: "64K (mixed)"
        - value: 1m
          displayName: "1M (sequential)"

    - name: fioRuntime
      displayName: "Test Duration (seconds)"
      inputType: number
      default: 60
      group: fio
      validation:
        min: 10
        max: 3600

  # ═══════════════════════════════════════════════════════════════════════
  # Pod template - inline templated version
  # ═══════════════════════════════════════════════════════════════════════
  podTemplateString: |
    metadata:
      labels:
        breakglass.t-caas.telekom.com/debug-type: storage
        breakglass.t-caas.telekom.com/test-name: {{ .Vars.testName | quote }}
      annotations:
        breakglass.t-caas.telekom.com/tools: "fio,hdparm,iostat"
    spec:
      automountServiceAccountToken: false
      restartPolicy: Never
      terminationGracePeriodSeconds: 60
      nodeSelector:
        kubernetes.io/os: linux
      containers:
        - name: fio-test
          image: docker.io/library/alpine:3.21
          imagePullPolicy: IfNotPresent
          command:
            - /bin/sh
            - -c
            - |
              apk add --no-cache fio hdparm sysstat util-linux
              echo "=== FIO Storage Test Ready ==="
              echo "Test name: {{ .Vars.testName }}"
              echo "Test type: {{ .Vars.fioTestType }}"
              echo "Block size: {{ .Vars.fioBlockSize }}"
              echo ""
              echo "Run test with: fio /etc/fio/test.fio"
              trap : TERM INT
              sleep infinity & wait
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: false
            runAsNonRoot: true
            runAsUser: 1000
            capabilities:
              drop: ["ALL"]
          resources:
            limits:
              cpu: "2"
              memory: "2Gi"
            requests:
              cpu: "500m"
              memory: "512Mi"
          volumeMounts:
            - name: fio-config
              mountPath: /etc/fio
            {{- if .Vars.createPvc }}
            - name: test-pvc
              mountPath: /data/test
            {{- end }}
            {{- if .Vars.existingPvcName }}
            - name: existing-pvc
              mountPath: /data/existing
            {{- end }}
      volumes:
        - name: fio-config
          configMap:
            name: fio-config-{{ .Vars.testName }}-{{ .Session.Name | trunc 8 }}
        {{- if .Vars.createPvc }}
        - name: test-pvc
          persistentVolumeClaim:
            claimName: fio-pvc-{{ .Vars.testName }}-{{ .Session.Name | trunc 8 }}
        {{- end }}
        {{- if .Vars.existingPvcName }}
        - name: existing-pvc
          persistentVolumeClaim:
            claimName: {{ .Vars.existingPvcName }}
        {{- end }}

  # ═══════════════════════════════════════════════════════════════════════
  # Auxiliary resources - created before/after debug pods
  # ═══════════════════════════════════════════════════════════════════════
  auxiliaryResources:
    - name: test-pvc
      category: storage
      description: "Ephemeral PVC for fio testing"
      createBefore: true
      deleteAfter: true
      failurePolicy: fail
      templateString: |
        {{- if .Vars.createPvc }}
        apiVersion: v1
        kind: PersistentVolumeClaim
        metadata:
          name: fio-pvc-{{ .Vars.testName }}-{{ .Session.Name | trunc 8 }}
          namespace: {{ .Target.Namespace }}
          labels:
            {{- range $k, $v := .Labels }}
            {{ $k }}: {{ $v | quote }}
            {{- end }}
            breakglass.t-caas.telekom.com/test-name: {{ .Vars.testName | quote }}
        spec:
          accessModes:
            - {{ .Vars.accessMode }}
          storageClassName: {{ .Vars.storageClass | quote }}
          resources:
            requests:
              storage: {{ .Vars.pvcSize }}
        {{- end }}

    - name: fio-config
      category: configuration
      description: "FIO job configuration"
      createBefore: true
      deleteAfter: true
      failurePolicy: fail
      templateString: |
        apiVersion: v1
        kind: ConfigMap
        metadata:
          name: fio-config-{{ .Vars.testName }}-{{ .Session.Name | trunc 8 }}
          namespace: {{ .Target.Namespace }}
          labels:
            {{- range $k, $v := .Labels }}
            {{ $k }}: {{ $v | quote }}
            {{- end }}
        data:
          test.fio: |
            [global]
            ioengine=libaio
            direct=1
            bs={{ .Vars.fioBlockSize }}
            size=1G
            runtime={{ .Vars.fioRuntime }}
            time_based=1
            group_reporting=1
            
            [{{ .Vars.fioTestType }}-test]
            rw={{ .Vars.fioTestType }}
            {{- if .Vars.createPvc }}
            directory=/data/test
            {{- else if .Vars.existingPvcName }}
            directory=/data/existing
            {{- else }}
            directory=/tmp
            {{- end }}
            numjobs=4
            iodepth=32

  auxiliaryResourceDefaults:
    storage: true
    configuration: true

  requiredAuxiliaryResourceCategories:
    - configuration

  # ═══════════════════════════════════════════════════════════════════════
  # Access control
  # ═══════════════════════════════════════════════════════════════════════
  allowed:
    groups:
      - onboarding_poweruser
      - onboarding_collaborator
      - platform_poweruser
    clusters:
      - "*"

  approvers:
    groups:
      - onboarding_poweruser
      - platform_poweruser
    autoApproveFor:
      clusters:
        - "dev-*"
        - "tst-*"

  constraints:
    maxDuration: "4h"
    defaultDuration: "1h"
    allowRenewal: true
    maxRenewals: 2

  audit:
    enabled: true
    enableShellHistory: true
```

### Example 2: Reusable Templated DebugPodTemplate

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: DebugPodTemplate
metadata:
  name: netshoot-configurable
spec:
  displayName: "Configurable Netshoot"
  description: "Network debugging with user-configurable endpoints"

  # Variables this pod template expects
  variables:
    - name: targetEndpoint
      displayName: "Target Endpoint"
      description: "Endpoint to test connectivity against"
      inputType: text
      default: "kubernetes.default.svc"

    - name: enableTcpdump
      displayName: "Enable tcpdump"
      inputType: boolean
      default: false

  templateString: |
    metadata:
      labels:
        breakglass.t-caas.telekom.com/debug-type: network
      annotations:
        breakglass.t-caas.telekom.com/target-endpoint: {{ .Vars.targetEndpoint | quote }}
    spec:
      automountServiceAccountToken: false
      restartPolicy: Never
      terminationGracePeriodSeconds: 30
      nodeSelector:
        kubernetes.io/os: linux
      containers:
        - name: netshoot
          image: nicolaka/netshoot:v0.13
          command:
            - /bin/bash
            - -c
            - |
              echo "Target endpoint: {{ .Vars.targetEndpoint }}"
              {{- if .Vars.enableTcpdump }}
              echo "tcpdump enabled - starting capture in background"
              tcpdump -i any -w /tmp/capture.pcap &
              {{- end }}
              trap : TERM INT
              sleep infinity & wait
          securityContext:
            capabilities:
              drop: ["ALL"]
              add: ["NET_ADMIN", "NET_RAW"]
          resources:
            limits:
              cpu: "500m"
              memory: "256Mi"
```

### Example 3: Session Request

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: DebugSession
metadata:
  name: storage-test-20260130-abc
  namespace: breakglass-system
spec:
  cluster: prod-cluster-01
  templateRef: storage-test-advanced
  reason: "Customer XYZ onboarding - storage performance validation"
  requestedBy: user@telekom.de
  validFor: 2h

  # User-provided values
  extraDeployValues:
    testName: "customer-xyz"
    createPvc: true
    pvcSize: "50Gi"
    storageClass: "csi-cinder-replicated"
    accessMode: "ReadWriteOnce"
    existingPvcName: ""
    fioTestType: "randrw"
    fioBlockSize: "4k"
    fioRuntime: 120
```

## Implementation Phases

### Phase 1: Multi-Document Templates (Week 1)

**Goal**: Support multiple K8s resources from single auxiliary resource definition.

**Changes**:
1. Add `templateString` field to `AuxiliaryResource` (alongside `template`)
2. Implement multi-document YAML splitting (`---` separator)
3. If `templateString` is set, use it; otherwise fall back to `template`
4. Add `Vars` to render context (empty map initially)

**Files**:
- `api/v1alpha1/auxiliary_resource_types.go`
- `pkg/breakglass/auxiliary_resource_manager.go`

**Backward Compatibility**: Full - existing templates with `template` field continue working.

### Phase 2: Extra Deploy Variables (Week 2)

**Goal**: Enable user-provided variables at session request time.

**Changes**:
1. Add `ExtraDeployVariable` type and related types
2. Add `extraDeployVariables` to `DebugSessionTemplateSpec`
3. Add `extraDeployValues` to `DebugSessionSpec`
4. Implement variable validation in webhook
5. Populate `Vars` in render context from session values
6. Apply defaults for unset variables

**Files**:
- `api/v1alpha1/extra_deploy_types.go` (new)
- `api/v1alpha1/debug_session_template_types.go`
- `api/v1alpha1/debug_session_types.go`
- `api/v1alpha1/debug_session_webhook.go`
- `api/v1alpha1/debug_session_template_webhook.go`
- `pkg/breakglass/auxiliary_resource_manager.go`

### Phase 3: Templatable Pod Specifications (Week 3)

**Goal**: Make pod templates and overrides support Go templating.

**Changes**:
1. Add `templateString` to `DebugPodTemplateSpec`
2. Add `variables` to `DebugPodTemplateSpec`
3. Add `podTemplateString` to `DebugSessionTemplateSpec`
4. Add `podOverridesTemplate` to `DebugSessionTemplateSpec`
5. Implement pod spec rendering and merging

**Files**:
- `api/v1alpha1/debug_pod_template_types.go`
- `api/v1alpha1/debug_session_template_types.go`
- `pkg/breakglass/debug_session_reconciler.go`
- `pkg/breakglass/pod_template_renderer.go` (new)

### Phase 4: Frontend Integration (Week 4)

**Goal**: Dynamic form generation from variable definitions.

**Changes**:
1. Parse `extraDeployVariables` into form schema
2. Implement input components for each `inputType`
3. Client-side validation
4. Variable grouping and advanced toggle
5. Submit `extraDeployValues` with session request

**Files**:
- `frontend/src/components/debug-session/VariableForm.vue` (new)
- `frontend/src/components/debug-session/inputs/*.vue` (new)
- `frontend/src/composables/useVariableValidation.ts` (new)
- `frontend/src/api/types.ts`

## Migration Guide

### For Template Authors

**Before (static auxiliary resource)**:
```yaml
auxiliaryResources:
  - name: my-pvc
    template:
      apiVersion: v1
      kind: PersistentVolumeClaim
      metadata:
        name: "fixed-name"
      spec:
        resources:
          requests:
            storage: "10Gi"
```

**After (templated with user variable)**:
```yaml
extraDeployVariables:
  - name: pvcSize
    displayName: "PVC Size"
    inputType: storageSize
    default: "10Gi"

auxiliaryResources:
  - name: my-pvc
    templateString: |
      apiVersion: v1
      kind: PersistentVolumeClaim
      metadata:
        name: "pvc-{{ .Session.Name | trunc 8 }}"
      spec:
        resources:
          requests:
            storage: {{ .Vars.pvcSize }}
```

### Deprecation Timeline

| Version | Status |
|---------|--------|
| v0.2.0 | `template` field deprecated, `templateString` recommended |
| v0.3.0 | `template` field removed from new templates (validation warning) |
| v1.0.0 | `template` field removed entirely |

## Future Enhancements

The design explicitly supports these future additions:

1. **Cluster-sourced options**: Add `optionsFrom` field to fetch options from target cluster
   ```yaml
   - name: existingPvc
     inputType: select
     optionsFrom:
       apiVersion: v1
       kind: PersistentVolumeClaim
       namespace: "{{ .Target.Namespace }}"
       labelSelector:
         team: my-team
   ```

2. **Conditional variables**: Show/hide variables based on other values
   ```yaml
   - name: pvcSize
     showIf: "{{ .Vars.createPvc }}"
   ```

3. **Variable dependencies**: Validate cross-variable constraints
   ```yaml
   - name: maxReplicas
     validation:
       min: "{{ .Vars.minReplicas }}"
   ```

## Design Decisions

### Variable Inheritance

When a `DebugPodTemplate` defines `variables`, they are **automatically inherited** by any `DebugSessionTemplate` that references it via `podTemplateRef`. The inheritance works as follows:

1. Variables from `DebugPodTemplate.variables` are merged with `DebugSessionTemplate.extraDeployVariables`
2. If the same variable name exists in both, the `DebugSessionTemplate` definition takes precedence (allows overriding defaults, validation, etc.)
3. The merged variable list is presented to the user in the UI
4. All inherited variables appear in the form, grouped by source

```
┌─────────────────────────────────────────────────────────────────┐
│                    DebugPodTemplate                              │
│  variables:                                                      │
│    - name: targetEndpoint   ──────────────┐                     │
│    - name: enableTcpdump    ──────────────┤                     │
└───────────────────────────────────────────┼─────────────────────┘
                                            │ inherited
                                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                  DebugSessionTemplate                            │
│  podTemplateRef: netshoot-configurable                          │
│  extraDeployVariables:                                           │
│    - name: testName         ──────────────┐                     │
│    - name: enableTcpdump    ──────────────┤ (override default)  │
└───────────────────────────────────────────┼─────────────────────┘
                                            │ merged
                                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                   UI Form (merged)                               │
│  - targetEndpoint  (from pod template)                          │
│  - enableTcpdump   (overridden by session template)             │
│  - testName        (from session template)                      │
└─────────────────────────────────────────────────────────────────┘
```

### Template Validation

Templates are validated at creation time by attempting a **dry-run render** with default sample values. This catches syntax errors and undefined variable references early.

#### Default Sample Values for Validation

The following default values are used when validating templates:

```go
// DefaultValidationContext provides sample values for template validation.
var DefaultValidationContext = TemplateRenderContext{
    Session: SessionContext{
        Name:        "validation-session",
        Namespace:   "breakglass-system",
        Cluster:     "validation-cluster",
        RequestedBy: "validator@example.com",
        ApprovedBy:  "approver@example.com",
        Reason:      "Template validation",
        ExpiresAt:   "2026-01-30T12:00:00Z",
    },
    Target: TargetContext{
        Namespace:   "breakglass-debug",
        ClusterName: "validation-cluster",
    },
    Template: TemplateContext{
        Name:        "validation-template",
        DisplayName: "Validation Template",
    },
    Binding: BindingContext{
        Name:      "validation-binding",
        Namespace: "breakglass-system",
    },
    Labels: map[string]string{
        "app.kubernetes.io/managed-by":          "breakglass",
        "breakglass.t-caas.telekom.com/session": "validation-session",
    },
    Annotations: map[string]string{
        "breakglass.t-caas.telekom.com/created-by": "validator@example.com",
    },
    Vars:             map[string]interface{}{}, // Populated from variable defaults
    Now:              time.Now(),
    EnabledResources: []string{},
}
```

#### Variable Default Values for Validation

When validating, each variable type uses these sample values if no `default` is specified:

| InputType | Sample Value |
|-----------|--------------|
| `boolean` | `false` |
| `text` | `"sample-text"` |
| `number` | `0` |
| `storageSize` | `"1Gi"` |
| `select` | First option's `value`, or `""` if no options |
| `multiSelect` | Empty array `[]` |

#### Validation Process

1. **Syntax check**: Parse template as Go template
2. **Function check**: Verify all referenced functions exist (Sprig + custom)
3. **Render check**: Execute template with default context
4. **YAML check**: Parse rendered output as valid YAML
5. **Multi-doc check**: If `---` separators present, validate each document

Validation errors are returned as webhook validation failures with descriptive messages.

## References

- [Sprig Template Functions](http://masterminds.github.io/sprig/)
- [Go text/template Documentation](https://pkg.go.dev/text/template)
- [Kubernetes Quantity Format](https://kubernetes.io/docs/reference/kubernetes-api/common-definitions/quantity/)
