package policy

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"text/template"

	telekomv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

// Action represents attributes of an attempted request for deny evaluation.
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
	// Pod is populated for exec/attach/portforward requests to enable security evaluation.
	// If nil and podSecurityRules are configured, behavior depends on failMode.
	Pod *corev1.Pod
	// PodSecurityOverrides contains escalation-level overrides for pod security evaluation.
	// If non-nil, these override the default pod security thresholds/factors.
	PodSecurityOverrides *telekomv1alpha1.PodSecurityOverrides
}

// PodSecurityResult contains the outcome of pod security evaluation.
type PodSecurityResult struct {
	Denied  bool
	Reason  string
	Score   int
	Factors []string
	Action  string // "allow", "warn", "deny"
}

type Evaluator struct {
	c   ctrlclient.Client
	log *zap.SugaredLogger
}

func NewEvaluator(c ctrlclient.Client, log *zap.SugaredLogger) *Evaluator {
	return &Evaluator{c: c, log: log}
}

// Match iterates all DenyPolicies (initial naive implementation). Returns (denied, policyName, error).
func (e *Evaluator) Match(ctx context.Context, act Action) (bool, string, error) {
	list := telekomv1alpha1.DenyPolicyList{}
	if err := e.c.List(ctx, &list); err != nil {
		return false, "", err
	}
	for _, pol := range list.Items {
		if !scopeMatches(pol.Spec.AppliesTo, act) {
			continue
		}
		// Check resource/verb rules first
		for _, r := range pol.Spec.Rules {
			if ruleMatches(r, act) {
				return true, pol.Name, nil
			}
		}
		// Check pod security rules for exec/attach/portforward
		if pol.Spec.PodSecurityRules != nil {
			result := e.evaluatePodSecurity(act, pol.Spec.PodSecurityRules)
			if result.Denied {
				return true, fmt.Sprintf("%s (pod-security: %s)", pol.Name, result.Reason), nil
			}
		}
	}
	return false, "", nil
}

// MatchWithDetails is like Match but also returns pod security evaluation details.
func (e *Evaluator) MatchWithDetails(ctx context.Context, act Action) (denied bool, policyName string, podSecResult *PodSecurityResult, err error) {
	list := telekomv1alpha1.DenyPolicyList{}
	if err := e.c.List(ctx, &list); err != nil {
		return false, "", nil, err
	}
	for _, pol := range list.Items {
		if !scopeMatches(pol.Spec.AppliesTo, act) {
			continue
		}
		// Check resource/verb rules first
		for _, r := range pol.Spec.Rules {
			if ruleMatches(r, act) {
				return true, pol.Name, nil, nil
			}
		}
		// Check pod security rules for exec/attach/portforward
		if pol.Spec.PodSecurityRules != nil {
			result := e.evaluatePodSecurity(act, pol.Spec.PodSecurityRules)
			if result.Denied {
				return true, pol.Name, &result, nil
			}
			if result.Action == "warn" {
				// Return result for metrics/logging even if not denied
				return false, "", &result, nil
			}
		}
	}
	return false, "", nil, nil
}

// evaluatePodSecurity checks if the action should be denied based on pod security rules.
func (e *Evaluator) evaluatePodSecurity(act Action, rules *telekomv1alpha1.PodSecurityRules) PodSecurityResult {
	// Check if this subresource should be evaluated
	if !e.shouldEvaluateSubresource(act.Subresource, rules.AppliesTo) {
		return PodSecurityResult{Denied: false, Action: "allow"}
	}

	// Check if pod is available
	if act.Pod == nil {
		failMode := rules.FailMode
		if failMode == "" {
			failMode = "closed" // default to secure
		}
		if failMode == "closed" {
			return PodSecurityResult{
				Denied: true,
				Reason: "pod spec unavailable for security evaluation (fail-closed)",
				Action: "deny",
			}
		}
		// fail-open: allow without evaluation
		e.log.Warnw("Pod security evaluation skipped: pod spec unavailable (fail-open)",
			"namespace", act.Namespace, "name", act.Name, "cluster", act.ClusterID)
		return PodSecurityResult{Denied: false, Action: "allow"}
	}

	// Check exemptions
	if e.isPodExempt(act.Pod, rules.Exemptions) {
		e.log.Debugw("Pod exempt from security evaluation",
			"pod", act.Pod.Name, "namespace", act.Pod.Namespace)
		return PodSecurityResult{Denied: false, Action: "allow"}
	}

	// Check escalation-level overrides
	overrides := act.PodSecurityOverrides
	if overrides != nil && overrides.Enabled {
		// Check namespace scope for overrides
		if len(overrides.NamespaceScope) > 0 && !contains(overrides.NamespaceScope, act.Pod.Namespace) {
			e.log.Debugw("Pod security overrides not applicable: namespace not in scope",
				"pod", act.Pod.Name, "namespace", act.Pod.Namespace, "allowedNamespaces", overrides.NamespaceScope)
			// Continue with normal evaluation - overrides don't apply to this namespace
			overrides = nil
		}
	}

	// Detect risk factors
	factors := e.detectRiskFactors(act.Pod, rules.RiskFactors)

	// Check block factors (immediate deny if any present, unless exempted by override)
	exemptFactors := make(map[string]bool)
	if overrides != nil && overrides.Enabled {
		for _, f := range overrides.ExemptFactors {
			exemptFactors[f] = true
		}
	}

	for _, blocked := range rules.BlockFactors {
		// Skip if factor is exempted by escalation override
		if exemptFactors[blocked] {
			e.log.Debugw("Blocked factor exempted by escalation override",
				"factor", blocked, "pod", act.Pod.Name)
			continue
		}

		for _, detected := range factors {
			// Match the factor name (before any colon suffix like "privilegedContainer:nginx")
			factorName := detected
			if idx := strings.Index(detected, ":"); idx > 0 {
				factorName = detected[:idx]
			}
			if factorName == blocked {
				return PodSecurityResult{
					Denied:  true,
					Reason:  fmt.Sprintf("blocked security factor detected: %s", detected),
					Score:   0,
					Factors: factors,
					Action:  "deny",
				}
			}
		}
	}

	// Calculate risk score
	score := e.calculateRiskScore(act.Pod, rules.RiskFactors)

	// Check if escalation override allows higher score
	if overrides != nil && overrides.Enabled && overrides.MaxAllowedScore != nil {
		if score <= *overrides.MaxAllowedScore {
			e.log.Infow("Pod access allowed via escalation override",
				"score", score, "maxAllowed", *overrides.MaxAllowedScore,
				"pod", act.Pod.Name, "namespace", act.Pod.Namespace, "factors", factors)
			return PodSecurityResult{
				Denied:  false,
				Score:   score,
				Factors: factors,
				Action:  "allow",
				Reason:  fmt.Sprintf("allowed by escalation override (score %d <= %d)", score, *overrides.MaxAllowedScore),
			}
		}
	}

	// Apply thresholds (evaluated in order)
	for _, t := range rules.Thresholds {
		if score <= t.MaxScore {
			result := PodSecurityResult{
				Score:   score,
				Factors: factors,
				Action:  t.Action,
			}
			switch t.Action {
			case "deny":
				result.Denied = true
				result.Reason = e.renderReason(t.Reason, score, factors, act.Pod)
				if result.Reason == "" {
					result.Reason = fmt.Sprintf("pod security risk score %d exceeds threshold", score)
				}
			case "warn":
				result.Denied = false
				e.log.Warnw("High-risk pod access allowed (warn threshold)",
					"score", score, "factors", factors,
					"pod", act.Pod.Name, "namespace", act.Pod.Namespace, "cluster", act.ClusterID)
			default: // allow
				result.Denied = false
			}
			return result
		}
	}

	// Score exceeds all thresholds - deny by default
	return PodSecurityResult{
		Denied:  true,
		Reason:  fmt.Sprintf("risk score %d exceeds all configured thresholds", score),
		Score:   score,
		Factors: factors,
		Action:  "deny",
	}
}

// shouldEvaluateSubresource checks if the given subresource should trigger pod security evaluation.
func (e *Evaluator) shouldEvaluateSubresource(subresource string, scope *telekomv1alpha1.PodSecurityScope) bool {
	defaultSubresources := []string{"exec", "attach", "portforward"}
	subresources := defaultSubresources
	if scope != nil && len(scope.Subresources) > 0 {
		subresources = scope.Subresources
	}
	for _, s := range subresources {
		if s == subresource {
			return true
		}
	}
	return false
}

// isPodExempt checks if a pod is exempt from security evaluation.
func (e *Evaluator) isPodExempt(pod *corev1.Pod, exemptions *telekomv1alpha1.PodSecurityExemptions) bool {
	if exemptions == nil {
		return false
	}
	// Check namespace exemption
	for _, ns := range exemptions.Namespaces {
		if ns == pod.Namespace {
			return true
		}
	}
	// Check label exemption (all labels must match)
	if len(exemptions.PodLabels) > 0 {
		allMatch := true
		for k, v := range exemptions.PodLabels {
			if pod.Labels[k] != v {
				allMatch = false
				break
			}
		}
		if allMatch {
			return true
		}
	}
	return false
}

// detectRiskFactors returns a list of detected risk factor names.
func (e *Evaluator) detectRiskFactors(pod *corev1.Pod, rf telekomv1alpha1.RiskFactors) []string {
	factors := []string{}

	if pod.Spec.HostNetwork {
		factors = append(factors, "hostNetwork")
	}
	if pod.Spec.HostPID {
		factors = append(factors, "hostPID")
	}
	if pod.Spec.HostIPC {
		factors = append(factors, "hostIPC")
	}

	// Check all containers (including init containers)
	allContainers := append([]corev1.Container{}, pod.Spec.Containers...)
	allContainers = append(allContainers, pod.Spec.InitContainers...)

	for _, c := range allContainers {
		if c.SecurityContext != nil {
			if c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
				factors = append(factors, fmt.Sprintf("privilegedContainer:%s", c.Name))
			}
			if c.SecurityContext.RunAsUser != nil && *c.SecurityContext.RunAsUser == 0 {
				factors = append(factors, fmt.Sprintf("runAsRoot:%s", c.Name))
			}
			// Check capabilities
			if c.SecurityContext.Capabilities != nil {
				for _, cap := range c.SecurityContext.Capabilities.Add {
					if _, ok := rf.Capabilities[string(cap)]; ok {
						factors = append(factors, fmt.Sprintf("capability:%s:%s", cap, c.Name))
					}
				}
			}
		}
	}

	// Check for hostPath volumes
	for _, v := range pod.Spec.Volumes {
		if v.HostPath != nil {
			if e.isHostPathWritable(pod, v.Name) {
				factors = append(factors, fmt.Sprintf("hostPathWritable:%s", v.Name))
			} else {
				factors = append(factors, fmt.Sprintf("hostPathReadOnly:%s", v.Name))
			}
		}
	}

	return factors
}

// calculateRiskScore computes the total risk score based on detected factors.
func (e *Evaluator) calculateRiskScore(pod *corev1.Pod, rf telekomv1alpha1.RiskFactors) int {
	score := 0

	if pod.Spec.HostNetwork && rf.HostNetwork > 0 {
		score += rf.HostNetwork
	}
	if pod.Spec.HostPID && rf.HostPID > 0 {
		score += rf.HostPID
	}
	if pod.Spec.HostIPC && rf.HostIPC > 0 {
		score += rf.HostIPC
	}

	// Check all containers
	allContainers := append([]corev1.Container{}, pod.Spec.Containers...)
	allContainers = append(allContainers, pod.Spec.InitContainers...)

	privilegedCount := 0
	rootCount := 0
	for _, c := range allContainers {
		if c.SecurityContext != nil {
			if c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
				privilegedCount++
			}
			if c.SecurityContext.RunAsUser != nil && *c.SecurityContext.RunAsUser == 0 {
				rootCount++
			}
			// Add capability scores
			if c.SecurityContext.Capabilities != nil {
				for _, cap := range c.SecurityContext.Capabilities.Add {
					if capScore, ok := rf.Capabilities[string(cap)]; ok {
						score += capScore
					}
				}
			}
		}
	}

	// Add privileged container score (once per pod, not per container)
	if privilegedCount > 0 && rf.PrivilegedContainer > 0 {
		score += rf.PrivilegedContainer
	}
	// Add runAsRoot score
	if rootCount > 0 && rf.RunAsRoot > 0 {
		score += rf.RunAsRoot
	}

	// Check hostPath volumes
	for _, v := range pod.Spec.Volumes {
		if v.HostPath != nil {
			if e.isHostPathWritable(pod, v.Name) {
				score += rf.HostPathWritable
			} else {
				score += rf.HostPathReadOnly
			}
		}
	}

	return score
}

// isHostPathWritable checks if a hostPath volume is mounted as writable by any container.
func (e *Evaluator) isHostPathWritable(pod *corev1.Pod, volumeName string) bool {
	allContainers := append([]corev1.Container{}, pod.Spec.Containers...)
	allContainers = append(allContainers, pod.Spec.InitContainers...)

	for _, c := range allContainers {
		for _, vm := range c.VolumeMounts {
			if vm.Name == volumeName {
				// ReadOnly defaults to false if not specified
				if !vm.ReadOnly {
					return true
				}
			}
		}
	}
	return false
}

// renderReason applies template variables to the reason string.
func (e *Evaluator) renderReason(reasonTmpl string, score int, factors []string, pod *corev1.Pod) string {
	if reasonTmpl == "" {
		return ""
	}

	tmpl, err := template.New("reason").Parse(reasonTmpl)
	if err != nil {
		e.log.Warnw("Failed to parse reason template", "error", err, "template", reasonTmpl)
		return reasonTmpl
	}

	data := map[string]interface{}{
		"Score":     score,
		"Factors":   strings.Join(factors, ", "),
		"Pod":       pod.Name,
		"Namespace": pod.Namespace,
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		e.log.Warnw("Failed to render reason template", "error", err)
		return reasonTmpl
	}
	return buf.String()
}

func scopeMatches(s *telekomv1alpha1.DenyPolicyScope, act Action) bool {
	if s == nil {
		return true
	}
	if len(s.Clusters) > 0 && !contains(s.Clusters, act.ClusterID) {
		return false
	}
	if len(s.Tenants) > 0 && !contains(s.Tenants, act.Tenant) {
		return false
	}
	if len(s.Sessions) > 0 && !contains(s.Sessions, act.Session) {
		return false
	}
	return true
}

func ruleMatches(r telekomv1alpha1.DenyRule, act Action) bool {
	if !contains(r.Verbs, act.Verb) {
		return false
	}
	if !contains(r.APIGroups, act.APIGroup) {
		return false
	}
	if !contains(r.Resources, act.Resource) {
		return false
	}
	if len(r.Subresources) > 0 && !contains(r.Subresources, act.Subresource) && !contains(r.Subresources, "*") {
		return false
	}
	if len(r.Namespaces) > 0 && !matchAny(r.Namespaces, act.Namespace) {
		return false
	}
	if len(r.ResourceNames) > 0 && !matchAny(r.ResourceNames, act.Name) {
		return false
	}
	return true
}

func contains(sl []string, v string) bool {
	for _, s := range sl {
		if s == v || s == "*" {
			return true
		}
	}
	return false
}

// matchAny supports shell style * wildcard using filepath.Match
func matchAny(patterns []string, value string) bool {
	for _, p := range patterns {
		if p == "*" {
			return true
		}
		ok, _ := filepath.Match(p, value)
		if ok {
			return true
		}
		if strings.Contains(p, "*") && value == "" {
			continue
		}
	}
	return false
}
