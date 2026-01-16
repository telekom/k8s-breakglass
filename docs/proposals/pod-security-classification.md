# Pod Security Risk Classification for pod/exec Requests

**Status**: ✅ IMPLEMENTED (January 2026)

## Overview

This proposal introduces a pod security risk classification system that evaluates pod configurations before allowing `pods/exec`, `pods/attach`, and `pods/portforward` operations. High-risk pods (those with elevated privileges) can be blocked or require additional approval based on configurable thresholds.

**Key Decision**: This feature extends the existing `DenyPolicy` CRD rather than introducing a new CRD, since both are fundamentally about denying access based on context.

## Motivation

Current `DenyPolicy` rules operate on resource/verb/namespace attributes but cannot inspect the actual pod specification. A user with `pods/exec` permission could exec into any pod, including those with:
- Host network namespace (`hostNetwork: true`)
- Host PID namespace (`hostPID: true`)
- Host IPC namespace (`hostIPC: true`)
- Privileged containers (`securityContext.privileged: true`)
- Writable hostPath mounts
- Running as root (`runAsUser: 0`)

These pods pose significantly higher blast radius if compromised.

## Design

### Extended `DenyPolicy` CRD

Add a new `podSecurityRules` section to the existing `DenyPolicySpec`:

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: DenyPolicy
metadata:
  name: high-risk-pod-exec-blocking
spec:
  # Existing scope (unchanged)
  appliesTo:
    clusters: ["prod-*"]
    escalationRefs: ["emergency-access"]
  
  # Existing rules (unchanged) - for resource/verb/namespace matching
  rules:
    - verbs: ["delete"]
      apiGroups: [""]
      resources: ["namespaces"]
  
  # NEW: Pod security rules for exec/attach/portforward
  podSecurityRules:
    # Which subresources to evaluate (default: exec, attach, portforward)
    appliesTo:
      subresources: ["exec", "attach", "portforward"]
    
    # Risk factors and their weights (0-100)
    riskFactors:
      hostNetwork: 80
      hostPID: 70
      hostIPC: 50
      privilegedContainer: 90
      hostPathWritable: 60
      hostPathReadOnly: 10
      runAsRoot: 40
      capabilities:
        NET_ADMIN: 50
        SYS_ADMIN: 80
        SYS_PTRACE: 60
    
    # Actions based on cumulative risk score
    thresholds:
      - maxScore: 30
        action: allow
      - maxScore: 70
        action: warn      # Allow but log warning + emit metric
      - maxScore: 100
        action: deny
        reason: "Pod exceeds security risk threshold (score: {{.score}}). Factors: {{.factors}}"
    
    # Alternative: blocklist mode (deny if ANY factor present)
    blockFactors:
      - hostNetwork
      - privilegedContainer
    
    # Exemptions for trusted pods
    exemptions:
      namespaces:
        patterns: ["kube-system", "monitoring"]
      podLabels:
        breakglass.telekom.com/security-exempt: "true"
    
    # Fail mode when pod cannot be fetched
    failMode: "closed"  # "open" or "closed"
```

### API Types Changes

Extend `api/v1alpha1/deny_policy_types.go`:

```go
// DenyPolicySpec defines deny rules applicable to sessions / clusters / tenants.
type DenyPolicySpec struct {
    // appliesTo scopes the policy. Empty means global.
    // +optional
    AppliesTo *DenyPolicyScope `json:"appliesTo,omitempty"`

    // rules are evaluated in order; first matching rule denies.
    Rules []DenyRule `json:"rules,omitempty"`

    // NEW: podSecurityRules evaluates pod specs for exec/attach/portforward requests
    // +optional
    PodSecurityRules *PodSecurityRules `json:"podSecurityRules,omitempty"`

    // precedence (lower wins). If unset defaults to 100.
    // +optional
    Precedence *int32 `json:"precedence,omitempty"`
}

// PodSecurityRules defines risk-based evaluation for pod exec/attach operations
type PodSecurityRules struct {
    // appliesTo specifies which subresources trigger evaluation
    // +optional
    AppliesTo *PodSecurityScope `json:"appliesTo,omitempty"`
    
    // riskFactors assigns weights to dangerous pod configurations
    RiskFactors RiskFactors `json:"riskFactors"`
    
    // thresholds define actions based on cumulative risk score
    Thresholds []RiskThreshold `json:"thresholds"`
    
    // blockFactors immediately deny if ANY listed factor is present (overrides scoring)
    // +optional
    BlockFactors []string `json:"blockFactors,omitempty"`
    
    // exemptions exclude certain pods from evaluation
    // +optional
    Exemptions *PodSecurityExemptions `json:"exemptions,omitempty"`
    
    // failMode determines behavior when pod spec cannot be fetched
    // "open" = allow if fetch fails, "closed" = deny if fetch fails
    // +kubebuilder:validation:Enum=open;closed
    // +kubebuilder:default=closed
    // +optional
    FailMode string `json:"failMode,omitempty"`
}

type PodSecurityScope struct {
    // subresources to evaluate (default: ["exec", "attach", "portforward"])
    // +optional
    Subresources []string `json:"subresources,omitempty"`
}

type RiskFactors struct {
    // +optional
    HostNetwork int `json:"hostNetwork,omitempty"`
    // +optional
    HostPID int `json:"hostPID,omitempty"`
    // +optional
    HostIPC int `json:"hostIPC,omitempty"`
    // +optional
    PrivilegedContainer int `json:"privilegedContainer,omitempty"`
    // +optional
    HostPathWritable int `json:"hostPathWritable,omitempty"`
    // +optional
    HostPathReadOnly int `json:"hostPathReadOnly,omitempty"`
    // +optional
    RunAsRoot int `json:"runAsRoot,omitempty"`
    // capabilities maps Linux capability names to risk scores
    // +optional
    Capabilities map[string]int `json:"capabilities,omitempty"`
}

type RiskThreshold struct {
    // maxScore is the upper bound for this threshold (inclusive)
    MaxScore int `json:"maxScore"`
    // action to take: "allow", "warn", "deny"
    // +kubebuilder:validation:Enum=allow;warn;deny
    Action string `json:"action"`
    // reason is the message returned when action is "deny"
    // Supports templates: {{.score}}, {{.factors}}, {{.pod}}, {{.namespace}}
    // +optional
    Reason string `json:"reason,omitempty"`
}

type PodSecurityExemptions struct {
    // namespaces to skip evaluation for
    // +optional
    Namespaces []string `json:"namespaces,omitempty"`
    // podLabels - pods with ALL these labels are exempt
    // +optional
    PodLabels map[string]string `json:"podLabels,omitempty"`
}
```

### Integration Points

#### 1. Extend Policy Evaluator (`pkg/policy/deny.go`)

```go
// Action now includes pod context for security evaluation
type Action struct {
    Verb        string
    APIGroup    string
    Resource    string
    Namespace   string
    Name        string
    Subresource string
    ClusterID   string
    Tenant      string
    Session     string
    // NEW: Pod spec for security evaluation (populated for exec/attach/portforward)
    Pod         *corev1.Pod
}

// Match now also evaluates podSecurityRules
func (e *Evaluator) Match(ctx context.Context, act Action) (bool, string, error) {
    // ... existing rule matching ...
    
    // NEW: Pod security evaluation for exec/attach/portforward
    if act.Pod != nil && pol.Spec.PodSecurityRules != nil {
        if denied, reason := e.evaluatePodSecurity(act.Pod, pol.Spec.PodSecurityRules, act); denied {
            return true, fmt.Sprintf("%s (pod-security)", pol.Name), nil
        }
    }
    
    return false, "", nil
}

func (e *Evaluator) evaluatePodSecurity(pod *corev1.Pod, rules *PodSecurityRules, act Action) (bool, string) {
    // Check exemptions first
    if rules.Exemptions != nil {
        if contains(rules.Exemptions.Namespaces, pod.Namespace) {
            return false, ""
        }
        if matchesAllLabels(pod.Labels, rules.Exemptions.PodLabels) {
            return false, ""
        }
    }
    
    // Check block factors (immediate deny)
    factors := e.detectRiskFactors(pod)
    for _, blocked := range rules.BlockFactors {
        if contains(factors, blocked) {
            return true, fmt.Sprintf("Blocked factor detected: %s", blocked)
        }
    }
    
    // Calculate risk score
    score := e.calculateRiskScore(pod, rules.RiskFactors)
    
    // Apply thresholds
    for _, t := range rules.Thresholds {
        if score <= t.MaxScore {
            switch t.Action {
            case "deny":
                reason := renderReason(t.Reason, score, factors, pod)
                return true, reason
            case "warn":
                e.log.Warnw("High-risk pod access allowed", 
                    "score", score, "factors", factors, 
                    "pod", pod.Name, "namespace", pod.Namespace)
                metrics.PodSecurityWarning.WithLabelValues(act.ClusterID).Inc()
                return false, ""
            default: // allow
                return false, ""
            }
        }
    }
    
    // Score exceeds all thresholds - deny by default
    return true, fmt.Sprintf("Risk score %d exceeds all thresholds", score)
}
```

#### 2. Webhook Controller Changes (`pkg/webhook/controller.go`)

```go
// In handleAuthorize, when building the Action for deny evaluation:
if sar.Spec.ResourceAttributes != nil {
    ra := sar.Spec.ResourceAttributes
    act := policy.Action{
        Verb:        ra.Verb,
        APIGroup:    ra.Group,
        Resource:    ra.Resource,
        Namespace:   ra.Namespace,
        Name:        ra.Name,
        Subresource: ra.Subresource,
        ClusterID:   clusterName,
        Tenant:      tenant,
    }
    
    // NEW: Fetch pod spec for exec/attach/portforward
    if ra.Resource == "pods" && isExecSubresource(ra.Subresource) && ra.Name != "" {
        pod, err := wc.fetchPodFromCluster(ctx, clusterName, ra.Namespace, ra.Name)
        if err != nil {
            reqLog.Warnw("Failed to fetch pod for security evaluation", "error", err)
            // failMode handling done in evaluator
        } else {
            act.Pod = pod
        }
    }
    
    // Existing deny evaluation now includes pod security
    if denied, pol, derr := wc.denyEval.Match(ctx, act); denied {
        // ... existing deny response logic ...
    }
}

func isExecSubresource(sub string) bool {
    return sub == "exec" || sub == "attach" || sub == "portforward"
}

func (wc *WebhookController) fetchPodFromCluster(ctx context.Context, cluster, namespace, name string) (*corev1.Pod, error) {
    rc, err := wc.ccProvider.GetRESTConfig(ctx, cluster)
    if err != nil {
        return nil, err
    }
    clientset, err := kubernetes.NewForConfig(rc)
    if err != nil {
        return nil, err
    }
    return clientset.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{})
}
```

### Example DenyPolicy Configurations

#### Strict Production Policy
```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: DenyPolicy
metadata:
  name: prod-strict-exec
spec:
  appliesTo:
    clusters: ["prod-*"]
  podSecurityRules:
    riskFactors:
      hostNetwork: 100      # Immediately hits deny threshold
      hostPID: 100
      privilegedContainer: 100
      hostPathWritable: 80
      runAsRoot: 30
      capabilities:
        SYS_ADMIN: 100
        NET_ADMIN: 50
    thresholds:
      - maxScore: 50
        action: allow
      - maxScore: 80
        action: warn
      - maxScore: 100
        action: deny
        reason: "Exec to high-risk pod blocked. Risk score: {{.score}}, factors: {{.factors}}"
    exemptions:
      namespaces:
        patterns: ["kube-system"]
    failMode: "closed"
```

#### Development/Staging Policy (Permissive)
```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: DenyPolicy
metadata:
  name: dev-permissive-exec
spec:
  appliesTo:
    clusters: ["dev-*", "staging-*"]
  podSecurityRules:
    riskFactors:
      hostNetwork: 30
      privilegedContainer: 50
      runAsRoot: 10
    thresholds:
      - maxScore: 100
        action: warn    # Warn on everything, never deny
    failMode: "open"
```

### Metrics

Extend existing metrics:

```go
var (
    PodSecurityEvaluations = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "breakglass_deny_policy_pod_security_evaluations_total",
            Help: "Pod security evaluations by action taken",
        },
        []string{"cluster", "policy", "action"},  // action: allowed, warned, denied
    )
    PodSecurityRiskScore = prometheus.NewHistogramVec(
        prometheus.HistogramOpts{
            Name:    "breakglass_deny_policy_pod_security_risk_score",
            Help:    "Distribution of pod security risk scores",
            Buckets: []float64{10, 30, 50, 70, 90, 100, 150, 200},
        },
        []string{"cluster"},
    )
    PodSecurityFactors = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "breakglass_deny_policy_pod_security_factors_total",
            Help: "Count of detected risk factors",
        },
        []string{"cluster", "factor"},
    )
)
```

## Implementation Steps

1. **Phase 1**: Extend DenyPolicy types
   - Add `PodSecurityRules` to `api/v1alpha1/deny_policy_types.go`
   - `make generate && make manifests`
   - Update validation webhooks

2. **Phase 2**: Extend policy evaluator
   - Add pod security evaluation to `pkg/policy/deny.go`
   - Add `Pod` field to `Action` struct
   - Implement `calculateRiskScore()` and `detectRiskFactors()`

3. **Phase 3**: Webhook integration
   - Add `fetchPodFromCluster()` to webhook controller
   - Populate `act.Pod` for exec/attach/portforward requests

4. **Phase 4**: Metrics, logging, docs
   - Add Prometheus metrics
   - Update `docs/deny-policy.md` with pod security section
   - Add example policies to `config/deny-policy-examples.yaml`

## Design Decisions

1. **Integrated into DenyPolicy**: Pod security rules are part of `DenyPolicy` CRD since both fundamentally deny access. This keeps the policy model simple and allows combining resource rules with pod security rules in a single policy.
2. **Fail mode**: Configurable per policy via `failMode` ("open" or "closed"), defaulting to "closed" for security-sensitive environments.
3. **Independence from PSA/PSS**: This feature is intentionally independent from Kubernetes' built-in PodSecurity admission. PSA operates at pod creation time; our feature operates at exec-time and considers the breakglass session context.
4. **Caching**: Pod specs cached per-request only (not across requests) to balance performance with freshness.
5. **Exemptions**: Support namespace and label-based exemptions for trusted system pods.

## Open Questions

1. **Audit events**: Should we emit Kubernetes audit events when blocking high-risk pods in addition to breakglass logs?
2. ~~**Per-escalation overrides**: Should escalations be able to override/relax pod security rules (e.g., SRE escalation allows exec to privileged pods)?~~ **Resolved**: Yes, implemented via `PodSecurityOverrides` in `BreakglassEscalation`.

## Implementation Status

> **Last Updated:** 2025

This proposal has been **fully implemented**. All core features are available and tested.

### Implemented Features

| Feature | Status | Location |
|---------|--------|----------|
| `PodSecurityRules` type definition | ✅ | `api/v1alpha1/deny_policy_types.go` |
| `RiskFactors` struct | ✅ | `api/v1alpha1/deny_policy_types.go` |
| `RiskThreshold` struct | ✅ | `api/v1alpha1/deny_policy_types.go` |
| `PodSecurityExemptions` struct | ✅ | `api/v1alpha1/deny_policy_types.go` |
| `PodSecurityScope` struct | ✅ | `api/v1alpha1/deny_policy_types.go` |
| Risk score calculation | ✅ | `pkg/policy/pod_security.go` |
| Risk factor detection | ✅ | `pkg/policy/pod_security.go` |
| Block factor evaluation | ✅ | `pkg/policy/pod_security.go` |
| Threshold matching | ✅ | `pkg/policy/pod_security.go` |
| Namespace exemptions | ✅ | `pkg/policy/pod_security.go` |
| Label exemptions | ✅ | `pkg/policy/pod_security.go` |
| Capability scoring | ✅ | `pkg/policy/pod_security.go` |
| Webhook integration | ✅ | `pkg/webhook/controller.go` |
| Pod fetch from cluster | ✅ | `pkg/webhook/controller.go` |
| Fail mode handling | ✅ | `pkg/webhook/controller.go` |
| Test injection (podFetchFn) | ✅ | `pkg/webhook/controller.go` |

### Prometheus Metrics ✅ IMPLEMENTED

| Metric | Type | Status | Location |
|--------|------|--------|----------|
| `breakglass_pod_security_evaluations_total` | Counter | ✅ | `pkg/metrics/metrics.go` |
| `breakglass_pod_security_risk_score` | Histogram | ✅ | `pkg/metrics/metrics.go` |
| `breakglass_pod_security_factors_total` | Counter | ✅ | `pkg/metrics/metrics.go` |
| `breakglass_pod_security_denied_total` | Counter | ✅ | `pkg/metrics/metrics.go` |
| `breakglass_pod_security_warnings_total` | Counter | ✅ | `pkg/metrics/metrics.go` |

Metrics are registered at startup (lines 558-560 in metrics.go) and used in `pkg/policy/deny.go`.

### Test Coverage

| Test Type | Coverage | Location |
|-----------|----------|----------|
| Unit tests | 94.9% | `pkg/policy/pod_security_test.go` |
| Fuzz tests | ✅ | `pkg/policy/fuzz_test.go` |
| E2E tests (SAR flows) | 10 tests | `pkg/api/api_end_to_end_test.go` |

### E2E Test Scenarios

The following end-to-end SAR scenarios are tested:

1. **Risk Score Denial**: Privileged pod blocked when score exceeds threshold
2. **Safe Pod Allowed**: Non-risky pod allowed (score < threshold)
3. **Block Factor Denial**: hostNetwork pod blocked by blockFactors
4. **Namespace Exemption**: kube-system pods allowed despite risk score
5. **Fail Mode Closed**: Request denied when pod fetch fails
6. **Fail Mode Open**: Request allowed when pod fetch fails
7. **Attach Evaluation**: pods/attach triggers security evaluation
8. **Portforward Evaluation**: pods/portforward triggers security evaluation
9. **Subresource Scope**: AppliesTo.subresources filtering works
10. **Escalation Override**: ⏭️ Skipped (webhook wiring pending)

### Documentation

| Document | Status |
|----------|--------|
| DenyPolicy reference | ✅ `docs/deny-policy.md` |
| Example policies | ✅ `config/deny-policy-examples.yaml` |
| E2E test checklist | ✅ `e2e/e2e-todo.md` |

### Remaining Work

✅ **All work items completed!**

1. ~~**Escalation Override Wiring**~~: ✅ IMPLEMENTED. The webhook controller now populates `act.PodSecurityOverrides` from the active session's escalation via `getPodSecurityOverridesFromSessions()` in `pkg/webhook/controller.go` (lines 316-354). The E2E test `TestEndToEndSARPodSecurityWithEscalationOverride` validates this functionality.

2. ~~**Kubernetes Audit Events**~~: ✅ IMPLEMENTED. Pod security audit events are now emitted via `emitPodSecurityAudit()` in `pkg/webhook/controller.go`. The following event types are defined in `pkg/audit/types.go`:
   - `EventPodSecurityEvaluated` - Normal evaluation completed
   - `EventPodSecurityAllowed` - Access allowed after evaluation
   - `EventPodSecurityDenied` - Access denied (critical severity)
   - `EventPodSecurityWarning` - High-risk access allowed with warning
   - `EventPodSecurityOverride` - Escalation override was applied

