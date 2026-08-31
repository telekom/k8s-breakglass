// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

// Package clustervalidator contains the public, provider-neutral readiness
// contract used by the cluster-validator image. It deliberately uses only
// Kubernetes APIs that are available in every conformant cluster.
package clustervalidator

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/version"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/kubernetes"
)

const (
	// ReportAPIVersion is the stable report contract version. Consumers should
	// reject unknown versions rather than guessing at field meanings.
	ReportAPIVersion = "cluster-validator.telekom.com/v1alpha1"
	ReportKind       = "ClusterValidationReport"
	ModeOneTime      = "one-time"
	ModePostUpgrade  = "post-upgrade"
	StatusReady      = "ready"
	StatusNotReady   = "not-ready"
	StatusError      = "error"
)

// CheckResult is intentionally a small, stable object. Check names and the
// order of checks are part of the report contract; messages are for humans.
type CheckResult struct {
	Name    string `json:"name"`
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
}

// Report is emitted for both one-time validation and post-upgrade readiness.
// The report contains no timestamps by default, making it reproducible for a
// fixed cluster state. Set IncludeTimestamp in Options when an audit timestamp
// is required; the optional field does not change the contract's semantics.
type Report struct {
	APIVersion  string        `json:"apiVersion"`
	Kind        string        `json:"kind"`
	Mode        string        `json:"mode"`
	Status      string        `json:"status"`
	Checks      []CheckResult `json:"checks"`
	GeneratedAt string        `json:"generatedAt,omitempty"`
}

// Check is the extension point for downstream distributions. A downstream
// binary can pass additional public or private checks to NewValidator without
// changing this report contract. The upstream image ships no provider-specific
// check and never assumes internal services, namespaces, or CRDs.
type Check interface {
	Name() string
	Run(context.Context, ReadOnlyClient, ReadOnlyDiscovery) CheckResult
}

// ReadOnlyClient is the deliberately narrow Kubernetes client exposed to
// checks. It cannot create, update, patch, or delete cluster resources.
// Validator.Validate accepts a normal client only so callers can use the
// standard client-go setup; checks receive this facade instead.
type ReadOnlyClient interface {
	ListNodes(context.Context, metav1.ListOptions) (*corev1.NodeList, error)
	ListNamespaces(context.Context, metav1.ListOptions) (*corev1.NamespaceList, error)
	ListPods(context.Context, metav1.ListOptions) (*corev1.PodList, error)
}

// ReadOnlyDiscovery exposes only the discovery calls used by built-in checks.
// In particular, it intentionally does not expose RESTClient(), which would
// let an extension issue arbitrary mutating HTTP requests.
type ReadOnlyDiscovery interface {
	ServerGroups() (*metav1.APIGroupList, error)
	ServerVersion() (*version.Info, error)
}

type readOnlyClient struct{ client kubernetes.Interface }

// PodIdentity identifies the validator pod running the check. Both fields are
// required before a pod can be excluded from the readiness result; this keeps
// a missing or mismatched Downward API value fail-safe.
type PodIdentity struct {
	Name      string
	Namespace string
}

type validatorClient struct {
	readOnlyClient
	selfPod PodIdentity
}

// podPageReader is implemented by the validator facade so the built-in pod
// check can stop after the first unhealthy page. It is deliberately private:
// extensions continue to use the stable ListPods method and do not need to
// understand Kubernetes continuation tokens.
type podPageReader interface {
	ListPodsPage(context.Context, metav1.ListOptions) (*corev1.PodList, error)
}

type readOnlyDiscovery struct{ client discovery.DiscoveryInterface }

func (d readOnlyDiscovery) ServerGroups() (*metav1.APIGroupList, error) {
	return d.client.ServerGroups()
}

func (d readOnlyDiscovery) ServerVersion() (*version.Info, error) {
	return d.client.ServerVersion()
}

func (c readOnlyClient) ListNodes(ctx context.Context, opts metav1.ListOptions) (*corev1.NodeList, error) {
	return c.client.CoreV1().Nodes().List(ctx, opts)
}

func (c readOnlyClient) ListNamespaces(ctx context.Context, opts metav1.ListOptions) (*corev1.NamespaceList, error) {
	return c.client.CoreV1().Namespaces().List(ctx, opts)
}

func (c readOnlyClient) ListPods(ctx context.Context, opts metav1.ListOptions) (*corev1.PodList, error) {
	return c.client.CoreV1().Pods(metav1.NamespaceAll).List(ctx, opts)
}

func (c validatorClient) ListPods(ctx context.Context, opts metav1.ListOptions) (*corev1.PodList, error) {
	if opts.Limit == 0 || opts.Limit > podListPageSize {
		opts.Limit = podListPageSize
	}
	result := &corev1.PodList{}
	for {
		pods, err := c.ListPodsPage(ctx, opts)
		if err != nil {
			return nil, err
		}
		result.ResourceVersion = pods.ResourceVersion
		result.Items = append(result.Items, pods.Items...)
		if pods.Continue == "" {
			return result, nil
		}
		opts.Continue = pods.Continue
	}
}

// ListPodsPage lists one bounded page and removes only the exact validator
// pod when both identity values are present. A partial identity is fail-safe
// and excludes nothing.
func (c validatorClient) ListPodsPage(ctx context.Context, opts metav1.ListOptions) (*corev1.PodList, error) {
	pods, err := c.readOnlyClient.ListPods(ctx, opts)
	if err != nil {
		return nil, err
	}
	if c.selfPod.Name == "" || c.selfPod.Namespace == "" {
		return pods, nil
	}
	filtered := pods.DeepCopy()
	kept := make([]corev1.Pod, 0, len(filtered.Items))
	for _, pod := range filtered.Items {
		if pod.Name == c.selfPod.Name && pod.Namespace == c.selfPod.Namespace {
			continue
		}
		kept = append(kept, pod)
	}
	filtered.Items = kept
	return filtered, nil
}

const podListPageSize int64 = 100

// Validator executes checks serially, then sorts results by name. Serial
// execution keeps API load predictable and deterministic across runs.
type Validator struct {
	checks []Check
}

// NewValidator constructs a validator with the supplied checks.
func NewValidator(checks ...Check) *Validator {
	return &Validator{checks: append([]Check(nil), checks...)}
}

// Validate runs all checks and returns a report for mode. A check must return
// StatusReady or StatusNotReady; unknown values are normalized to error.
func (v *Validator) Validate(ctx context.Context, client kubernetes.Interface, discoveryClient discovery.DiscoveryInterface, mode string, includeTimestamp bool) Report {
	return v.ValidateWithPodIdentity(ctx, client, discoveryClient, mode, includeTimestamp, PodIdentity{})
}

// ValidateWithPodIdentity runs checks while excluding exactly the current
// validator pod from the built-in pod readiness check. The identity is
// intentionally passed through the read-only facade so extensions see the
// same pod view as built-in checks. An incomplete identity excludes nothing.
func (v *Validator) ValidateWithPodIdentity(ctx context.Context, client kubernetes.Interface, discoveryClient discovery.DiscoveryInterface, mode string, includeTimestamp bool, selfPod PodIdentity) Report {
	readOnlyClient := validatorClient{readOnlyClient: readOnlyClient{client: client}, selfPod: selfPod}
	readOnlyDiscovery := readOnlyDiscovery{client: discoveryClient}
	results := make([]CheckResult, 0, len(v.checks))
	for _, check := range v.checks {
		result := check.Run(ctx, readOnlyClient, readOnlyDiscovery)
		result.Name = strings.TrimSpace(check.Name())
		if result.Name == "" {
			result.Name = "unnamed"
		}
		if result.Status != StatusReady && result.Status != StatusNotReady {
			result.Status = StatusError
			if result.Message == "" {
				result.Message = "check returned an invalid status"
			}
		}
		results = append(results, result)
	}
	sort.SliceStable(results, func(i, j int) bool { return results[i].Name < results[j].Name })

	status := StatusReady
	for _, result := range results {
		if result.Status == StatusError {
			status = StatusError
			break
		}
		if result.Status != StatusReady {
			status = StatusNotReady
		}
	}
	if mode != ModeOneTime && mode != ModePostUpgrade {
		status = StatusError
		results = append(results, CheckResult{Name: "configuration", Status: StatusError, Message: "mode must be one-time or post-upgrade"})
		sort.SliceStable(results, func(i, j int) bool { return results[i].Name < results[j].Name })
	}

	report := Report{APIVersion: ReportAPIVersion, Kind: ReportKind, Mode: mode, Status: status, Checks: results}
	if includeTimestamp {
		report.GeneratedAt = time.Now().UTC().Format(time.RFC3339)
	}
	return report
}

// MarshalReport returns canonical indented JSON with exactly one trailing
// newline for shell and artifact usage.
func MarshalReport(report Report) ([]byte, error) {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal validation report: %w", err)
	}
	return append(data, '\n'), nil
}

// BuiltinChecks returns only provider-neutral checks. The returned slice is
// safe for callers to append custom checks to before constructing a Validator.
func BuiltinChecks(skipPods bool) []Check {
	checks := []Check{apiServerCheck{}, discoveryCheck{}, nodesCheck{}, namespacesCheck{}}
	if !skipPods {
		checks = append(checks, podsCheck{})
	}
	return checks
}

type apiServerCheck struct{}

func (apiServerCheck) Name() string { return "api-server" }

func (apiServerCheck) Run(ctx context.Context, _ ReadOnlyClient, client ReadOnlyDiscovery) CheckResult {
	version, err := client.ServerVersion()
	if err != nil {
		return CheckResult{Name: "api-server", Status: StatusNotReady, Message: "Kubernetes API server is unreachable"}
	}
	return CheckResult{Name: "api-server", Status: StatusReady, Message: "Kubernetes " + version.GitVersion}
}

type discoveryCheck struct{}

func (discoveryCheck) Name() string { return "api-discovery" }

func (discoveryCheck) Run(ctx context.Context, _ ReadOnlyClient, client ReadOnlyDiscovery) CheckResult {
	_, err := client.ServerGroups()
	if err != nil {
		return CheckResult{Name: "api-discovery", Status: StatusNotReady, Message: "Kubernetes API discovery failed"}
	}
	return CheckResult{Name: "api-discovery", Status: StatusReady, Message: "Kubernetes API discovery succeeded"}
}

type nodesCheck struct{}

func (nodesCheck) Name() string { return "nodes-ready" }

func (nodesCheck) Run(ctx context.Context, client ReadOnlyClient, _ ReadOnlyDiscovery) CheckResult {
	nodes, err := client.ListNodes(ctx, metav1.ListOptions{})
	if err != nil {
		return CheckResult{Name: "nodes-ready", Status: StatusNotReady, Message: "could not list nodes"}
	}
	if len(nodes.Items) == 0 {
		return CheckResult{Name: "nodes-ready", Status: StatusNotReady, Message: "cluster has no nodes"}
	}
	for _, node := range nodes.Items {
		ready := false
		for _, condition := range node.Status.Conditions {
			if condition.Type == corev1.NodeReady {
				ready = condition.Status == corev1.ConditionTrue
				break
			}
		}
		if !ready {
			return CheckResult{Name: "nodes-ready", Status: StatusNotReady, Message: "one or more nodes are not Ready"}
		}
	}
	return CheckResult{Name: "nodes-ready", Status: StatusReady, Message: fmt.Sprintf("%d node(s) Ready", len(nodes.Items))}
}

type namespacesCheck struct{}

func (namespacesCheck) Name() string { return "namespaces-healthy" }

func (namespacesCheck) Run(ctx context.Context, client ReadOnlyClient, _ ReadOnlyDiscovery) CheckResult {
	namespaces, err := client.ListNamespaces(ctx, metav1.ListOptions{})
	if err != nil {
		return CheckResult{Name: "namespaces-healthy", Status: StatusNotReady, Message: "could not list namespaces"}
	}
	for _, namespace := range namespaces.Items {
		if namespace.DeletionTimestamp != nil || namespace.Status.Phase == corev1.NamespaceTerminating {
			return CheckResult{Name: "namespaces-healthy", Status: StatusNotReady, Message: "one or more namespaces are terminating"}
		}
	}
	return CheckResult{Name: "namespaces-healthy", Status: StatusReady, Message: fmt.Sprintf("%d namespace(s) active", len(namespaces.Items))}
}

type podsCheck struct{}

func (podsCheck) Name() string { return "pods-ready" }

func (podsCheck) Run(ctx context.Context, client ReadOnlyClient, _ ReadOnlyDiscovery) CheckResult {
	if paged, ok := client.(podPageReader); ok {
		return runPagedPodsCheck(ctx, paged)
	}
	pods, err := client.ListPods(ctx, metav1.ListOptions{})
	if err != nil {
		return CheckResult{Name: "pods-ready", Status: StatusNotReady, Message: "could not list pods"}
	}
	active := 0
	for _, pod := range pods.Items {
		if pod.Status.Phase == corev1.PodSucceeded {
			continue
		}
		active++
		if pod.DeletionTimestamp != nil || pod.Status.Phase != corev1.PodRunning || !podReady(pod) {
			return CheckResult{Name: "pods-ready", Status: StatusNotReady, Message: "one or more active pods are not Ready"}
		}
	}
	return CheckResult{Name: "pods-ready", Status: StatusReady, Message: fmt.Sprintf("%d active pod(s) Ready", active)}
}

func runPagedPodsCheck(ctx context.Context, client podPageReader) CheckResult {
	options := metav1.ListOptions{Limit: podListPageSize}
	active := 0
	for {
		pods, err := client.ListPodsPage(ctx, options)
		if err != nil {
			return CheckResult{Name: "pods-ready", Status: StatusNotReady, Message: "could not list pods"}
		}
		for _, pod := range pods.Items {
			if pod.Status.Phase == corev1.PodSucceeded {
				continue
			}
			active++
			if pod.DeletionTimestamp != nil || pod.Status.Phase != corev1.PodRunning || !podReady(pod) {
				return CheckResult{Name: "pods-ready", Status: StatusNotReady, Message: "one or more active pods are not Ready"}
			}
		}
		if pods.Continue == "" {
			return CheckResult{Name: "pods-ready", Status: StatusReady, Message: fmt.Sprintf("%d active pod(s) Ready", active)}
		}
		options.Continue = pods.Continue
	}
}

func podReady(pod corev1.Pod) bool {
	for _, condition := range pod.Status.Conditions {
		if condition.Type == corev1.PodReady {
			return condition.Status == corev1.ConditionTrue
		}
	}
	return false
}
