// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package clustervalidator

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/version"
	"k8s.io/client-go/discovery"
	discoveryfake "k8s.io/client-go/discovery/fake"
	"k8s.io/client-go/kubernetes"
	k8sfake "k8s.io/client-go/kubernetes/fake"
)

type fakeDiscovery struct{ *discoveryfake.FakeDiscovery }

func (f fakeDiscovery) ServerVersion() (*version.Info, error) {
	return &version.Info{GitVersion: "v1.36.4"}, nil
}

func (f fakeDiscovery) ServerGroups() (*metav1.APIGroupList, error) {
	return &metav1.APIGroupList{}, nil
}

func readyClient() (kubernetes.Interface, discovery.DiscoveryInterface) {
	client := k8sfake.NewSimpleClientset(
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-a"}, Status: corev1.NodeStatus{Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}}}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "default"}, Status: corev1.NamespaceStatus{Phase: corev1.NamespaceActive}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "default"}, Status: corev1.PodStatus{Phase: corev1.PodRunning, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}}},
	)
	return client, fakeDiscovery{FakeDiscovery: &discoveryfake.FakeDiscovery{}}
}

func TestValidateIsStableAndSorted(t *testing.T) {
	client, discoveryClient := readyClient()
	validator := NewValidator(BuiltinChecks(false)...)
	report := validator.Validate(context.Background(), client, discoveryClient, ModeOneTime, false)

	require.Equal(t, ReportAPIVersion, report.APIVersion)
	require.Equal(t, ReportKind, report.Kind)
	require.Equal(t, ModeOneTime, report.Mode)
	require.Equal(t, StatusReady, report.Status)
	require.Equal(t, []string{"api-discovery", "api-server", "namespaces-healthy", "nodes-ready", "pods-ready"}, checkNames(report.Checks))
	require.Empty(t, report.GeneratedAt)

	first, err := MarshalReport(report)
	require.NoError(t, err)
	second, err := MarshalReport(report)
	require.NoError(t, err)
	require.Equal(t, first, second)
}

func TestValidateReportsPostUpgradeAndFailure(t *testing.T) {
	client, discoveryClient := readyClient()
	err := client.CoreV1().Nodes().Delete(context.Background(), "node-a", metav1.DeleteOptions{})
	require.NoError(t, err)

	report := NewValidator(BuiltinChecks(true)...).Validate(context.Background(), client, discoveryClient, ModePostUpgrade, false)
	require.Equal(t, ModePostUpgrade, report.Mode)
	require.Equal(t, StatusNotReady, report.Status)
	require.Contains(t, report.Checks, CheckResult{Name: "nodes-ready", Status: StatusNotReady, Message: "cluster has no nodes"})
}

func TestPodsCheckExcludesExactCurrentPod(t *testing.T) {
	client := k8sfake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "validator", Namespace: "validator-system"},
			Status:     corev1.PodStatus{Phase: corev1.PodPending},
		},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "default"},
			Status: corev1.PodStatus{
				Phase:      corev1.PodRunning,
				Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}},
			},
		},
	)

	result := runPodsCheckWithIdentity(t, client, PodIdentity{Name: "validator", Namespace: "validator-system"})

	require.Equal(t, CheckResult{Name: "pods-ready", Status: StatusReady, Message: "1 active pod(s) Ready"}, result)
}

func TestPodsCheckFailsForUnrelatedUnreadyPod(t *testing.T) {
	client := k8sfake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "validator", Namespace: "validator-system"},
			Status:     corev1.PodStatus{Phase: corev1.PodPending},
		},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "unready-app", Namespace: "default"},
			Status:     corev1.PodStatus{Phase: corev1.PodPending},
		},
	)

	result := runPodsCheckWithIdentity(t, client, PodIdentity{Name: "validator", Namespace: "validator-system"})

	require.Equal(t, StatusNotReady, result.Status)
	require.Contains(t, result.Message, "active pods are not Ready")
}

func TestPodsCheckFailsSafeForIncompleteOrMismatchedIdentity(t *testing.T) {
	identities := map[string]PodIdentity{
		"missing name":      {Namespace: "validator-system"},
		"missing namespace": {Name: "validator"},
		"mismatched name":   {Name: "other-validator", Namespace: "validator-system"},
		"mismatched namespace": {
			Name: "validator", Namespace: "other-system",
		},
	}

	for name, identity := range identities {
		t.Run(name, func(t *testing.T) {
			client := k8sfake.NewSimpleClientset(&corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "validator", Namespace: "validator-system"},
				Status:     corev1.PodStatus{Phase: corev1.PodPending},
			})
			result := runPodsCheckWithIdentity(t, client, identity)
			require.Equal(t, StatusNotReady, result.Status)
		})
	}
}

func runPodsCheckWithIdentity(t *testing.T, client kubernetes.Interface, identity PodIdentity) CheckResult {
	t.Helper()
	report := NewValidator(podsCheck{}).ValidateWithPodIdentity(
		context.Background(), client, nil, ModeOneTime, false, identity,
	)
	require.Len(t, report.Checks, 1)
	return report.Checks[0]
}

func TestInvalidModeIsError(t *testing.T) {
	client, discoveryClient := readyClient()
	report := NewValidator().Validate(context.Background(), client, discoveryClient, "internal", false)
	require.Equal(t, StatusError, report.Status)
	require.Contains(t, report.Checks, CheckResult{Name: "configuration", Status: StatusError, Message: "mode must be one-time or post-upgrade"})
}

func TestCustomChecksAreAnExtensionPoint(t *testing.T) {
	client, discoveryClient := readyClient()
	custom := customCheck{}
	report := NewValidator(custom).Validate(context.Background(), client, discoveryClient, ModeOneTime, false)
	require.Equal(t, CheckResult{Name: "custom", Status: StatusReady, Message: "extension"}, report.Checks[0])
}

func TestInvalidCustomStatusIsReportError(t *testing.T) {
	client, discoveryClient := readyClient()
	report := NewValidator(invalidCheck{}).Validate(context.Background(), client, discoveryClient, ModeOneTime, false)
	require.Equal(t, StatusError, report.Status)
	require.Equal(t, StatusError, report.Checks[0].Status)
}

type customCheck struct{}

func (customCheck) Name() string { return "custom" }
func (customCheck) Run(context.Context, ReadOnlyClient, ReadOnlyDiscovery) CheckResult {
	return CheckResult{Name: "spoofed", Status: StatusReady, Message: "extension"}
}

type invalidCheck struct{}

func (invalidCheck) Name() string { return "invalid" }
func (invalidCheck) Run(context.Context, ReadOnlyClient, ReadOnlyDiscovery) CheckResult {
	return CheckResult{Name: "ignored", Status: "unknown"}
}

func checkNames(results []CheckResult) []string {
	names := make([]string, 0, len(results))
	for _, result := range results {
		names = append(names, result.Name)
	}
	return names
}
