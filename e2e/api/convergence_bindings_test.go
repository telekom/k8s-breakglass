//go:build e2e_convergence

// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
	corev1 "k8s.io/api/core/v1"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"
)

func TestConvergenceBindingHelmRelease(t *testing.T) {
	s := helpers.SetupTest(t, helpers.WithTimeout(18*time.Minute))
	ctx := s.Ctx
	ns := helpers.GenerateUniqueName("convergence")
	s.CreateResource(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}})
	chart := filepath.Join("..", "fixtures", "convergence-bindings")
	tmp := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		out, err := exec.CommandContext(ctx, args[0], args[1:]...).CombinedOutput()
		require.NoError(t, err, "%v: %s", args, out)
	}
	var values struct {
		Resources []map[string]interface{} `json:"resources"`
	}
	data, err := os.ReadFile(filepath.Join(chart, "values.yaml"))
	require.NoError(t, err)
	require.NoError(t, yaml.Unmarshal(data, &values))
	templates := map[string]string{}
	bindingNames := []string{}
	for _, obj := range values.Resources {
		u := &unstructured.Unstructured{Object: obj}
		old := u.GetName()
		// Cluster-scoped fixtures must be unique per test run.
		switch u.GetKind() {
		case "DebugPodTemplate", "DebugSessionTemplate", "IdentityProvider", "MailProvider", "AuditConfig":
			u.SetName(ns + "-" + old)
		}
		switch u.GetKind() {
		case "DebugSessionTemplate":
			templates[old] = u.GetName()
			if ref, found, _ := unstructured.NestedString(obj, "spec", "podTemplateRef", "name"); found {
				require.NoError(t, unstructured.SetNestedField(obj, ns+"-"+ref, "spec", "podTemplateRef", "name"))
			}
		case "DebugSessionClusterBinding":
			u.SetNamespace(ns)
			ref, _, err := unstructured.NestedString(obj, "spec", "templateRef", "name")
			require.NoError(t, err)
			require.NoError(t, unstructured.SetNestedField(obj, ns+"-"+ref, "spec", "templateRef", "name"))
			require.NoError(t, unstructured.SetNestedField(obj, ns, "spec", "clusterSelector", "matchLabels", "e2e-convergence"))
			bindingNames = append(bindingNames, u.GetName())
		}
	}
	// The chart owns cluster-scoped templates, so uninstall it before deleting its namespace.
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		out, err := exec.CommandContext(cleanupCtx, "helm", "uninstall", "bindings", "-n", ns, "--ignore-not-found", "--wait", "--timeout=90s").CombinedOutput()
		assert.NoError(t, err, "uninstall fixture: %s", out)
	})
	// A real source-controller serves the packaged chart to a real helm-controller.
	run("helm", "package", chart, "--destination", tmp)
	run("helm", "repo", "index", tmp)
	archive, err := os.ReadFile(filepath.Join(tmp, "convergence-bindings-0.1.0.tgz"))
	require.NoError(t, err)
	index, err := os.ReadFile(filepath.Join(tmp, "index.yaml"))
	require.NoError(t, err)
	s.CreateResource(&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "chart", Namespace: ns}, BinaryData: map[string][]byte{"convergence-bindings-0.1.0.tgz": archive, "index.yaml": index}})
	chartServer := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "chart", Namespace: ns, Labels: map[string]string{"app": "chart"}}, Spec: corev1.PodSpec{
		AutomountServiceAccountToken: ptr.To(false), SecurityContext: &corev1.PodSecurityContext{RunAsNonRoot: ptr.To(true), RunAsUser: ptr.To[int64](65532), SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}},
		Containers: []corev1.Container{{Name: "http", Image: "python:3.11-slim", ImagePullPolicy: corev1.PullIfNotPresent, Command: []string{"python3", "-m", "http.server", "8080", "--directory", "/chart"}, Env: []corev1.EnvVar{{Name: "PYTHONDONTWRITEBYTECODE", Value: "1"}}, SecurityContext: &corev1.SecurityContext{AllowPrivilegeEscalation: ptr.To(false), ReadOnlyRootFilesystem: ptr.To(true), Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}}}, VolumeMounts: []corev1.VolumeMount{{Name: "chart", MountPath: "/chart", ReadOnly: true}}}},
		Volumes:    []corev1.Volume{{Name: "chart", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: "chart"}}}}},
	}}
	s.CreateResource(chartServer)
	s.CreateResource(&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "chart", Namespace: ns}, Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "chart"}, Ports: []corev1.ServicePort{{Port: 8080}}}})
	require.Eventually(t, func() bool {
		var pod corev1.Pod
		if s.Client.Get(ctx, client.ObjectKeyFromObject(chartServer), &pod) != nil {
			return false
		}
		for _, condition := range pod.Status.Conditions {
			if condition.Type == corev1.PodReady {
				return condition.Status == corev1.ConditionTrue
			}
		}
		return false
	}, time.Minute, time.Second, "chart server must become ready")
	repo := &unstructured.Unstructured{Object: map[string]interface{}{"apiVersion": "source.toolkit.fluxcd.io/v1", "kind": "HelmRepository", "metadata": map[string]interface{}{"name": "chart", "namespace": ns}, "spec": map[string]interface{}{"interval": "1m", "url": "http://chart." + ns + ".svc:8080"}}}
	s.CreateResource(repo)
	raw, err := json.Marshal(values)
	require.NoError(t, err)
	var valueMap map[string]interface{}
	require.NoError(t, json.Unmarshal(raw, &valueMap))
	release := &unstructured.Unstructured{Object: map[string]interface{}{"apiVersion": "helm.toolkit.fluxcd.io/v2", "kind": "HelmRelease", "metadata": map[string]interface{}{"name": "platform-debug-session-bindings-release", "namespace": ns}, "spec": map[string]interface{}{
		"interval": "1m", "timeout": "5m", "releaseName": "bindings",
		"chart":  map[string]interface{}{"spec": map[string]interface{}{"chart": "convergence-bindings", "version": "0.1.0", "sourceRef": map[string]interface{}{"kind": "HelmRepository", "name": "chart"}}},
		"values": valueMap,
	}}}
	s.CreateResource(release)
	waitRelease := func() {
		t.Helper()
		require.Eventually(t, func() bool {
			if s.Client.Get(ctx, client.ObjectKeyFromObject(release), release) != nil {
				return false
			}
			conditions, _, _ := unstructured.NestedSlice(release.Object, "status", "conditions")
			for _, v := range conditions {
				c := v.(map[string]interface{})
				if c["type"] == "Ready" && c["status"] == "True" {
					gen, _, _ := unstructured.NestedInt64(release.Object, "status", "observedGeneration")
					return gen == release.GetGeneration()
				}
			}
			return false
		}, 6*time.Minute, time.Second, "HelmRelease must become Ready without disableWait: %v", release.Object["status"])
	}
	waitRelease()
	expectDisabledConfiguration := func() {
		t.Helper()
		require.EventuallyWithT(t, func(c *assert.CollectT) {
			var idp breakglassv1alpha1.IdentityProvider
			if assert.NoError(c, s.Client.Get(ctx, client.ObjectKey{Name: ns + "-convergence-disabled-idp"}, &idp)) {
				ready := apimeta.FindStatusCondition(idp.Status.Conditions, string(breakglassv1alpha1.IdentityProviderConditionReady))
				if assert.NotNil(c, ready) {
					assert.Equal(c, metav1.ConditionTrue, ready.Status)
					assert.Equal(c, "Disabled", ready.Reason)
				}
				assert.Nil(c, apimeta.FindStatusCondition(idp.Status.Conditions, string(breakglassv1alpha1.IdentityProviderConditionGroupSyncHealthy)))
			}
			var mail breakglassv1alpha1.MailProvider
			if assert.NoError(c, s.Client.Get(ctx, client.ObjectKey{Name: ns + "-convergence-disabled-mail"}, &mail)) {
				ready := apimeta.FindStatusCondition(mail.Status.Conditions, string(breakglassv1alpha1.MailProviderConditionReady))
				if assert.NotNil(c, ready) {
					assert.Equal(c, metav1.ConditionTrue, ready.Status)
					assert.Equal(c, "Disabled", ready.Reason)
				}
			}
			var audit breakglassv1alpha1.AuditConfig
			if assert.NoError(c, s.Client.Get(ctx, client.ObjectKey{Name: ns + "-convergence-disabled-audit"}, &audit)) {
				ready := apimeta.FindStatusCondition(audit.Status.Conditions, "Ready")
				if assert.NotNil(c, ready) {
					assert.Equal(c, metav1.ConditionTrue, ready.Status)
					assert.Equal(c, "AuditingDisabled", ready.Reason)
				}
				assert.Empty(c, audit.Status.ActiveSinks)
			}
		}, 45*time.Second, time.Second)
	}
	expectBindings := func(clusters map[string]string, productionHub bool) {
		t.Helper()
		require.EventuallyWithT(t, func(c *assert.CollectT) {
			for _, name := range bindingNames {
				if productionHub && strings.HasSuffix(name, "-nonprd") {
					continue
				}
				var b breakglassv1alpha1.DebugSessionClusterBinding
				if err := s.Client.Get(ctx, client.ObjectKey{Name: name, Namespace: ns}, &b); err != nil {
					assert.NoError(c, err)
					continue
				}
				assert.True(c, apimeta.IsStatusConditionTrue(b.Status.Conditions, "Ready"), name)
				assert.Equal(c, b.Generation, b.Status.ObservedGeneration, name)
				expected := []string{}
				for cluster, stage := range clusters {
					nonprd := stage == "dev" || stage == "ref" || stage == "tst"
					if productionHub || strings.Contains(name, "etcd-") || strings.HasSuffix(name, "-nonprd") == nonprd {
						expected = append(expected, cluster)
					}
				}
				actual := []string{}
				for _, ref := range b.Status.ResolvedClusters {
					actual = append(actual, ref.Name)
					assert.True(c, ref.Ready, name)
				}
				assert.ElementsMatch(c, expected, actual, name)
			}
		}, 45*time.Second, time.Second)
	}
	expectBindings(nil, false)
	expectDisabledConfiguration()
	// ClusterConfig is namespaced. The shared fixture creates the source cluster
	// in "default", while this test creates its own copies in s.Namespace.
	var sourceList breakglassv1alpha1.ClusterConfigList
	require.NoError(t, s.Client.List(ctx, &sourceList))
	var source *breakglassv1alpha1.ClusterConfig
	for i := range sourceList.Items {
		if sourceList.Items[i].Name == s.Cluster {
			source = &sourceList.Items[i]
			break
		}
	}
	require.NotNil(t, source, "source ClusterConfig %q not found", s.Cluster)
	createCluster := func(name, stage string) *breakglassv1alpha1.ClusterConfig {
		t.Helper()
		cc := &breakglassv1alpha1.ClusterConfig{ObjectMeta: metav1.ObjectMeta{Name: ns + "-" + name, Namespace: s.Namespace, Labels: map[string]string{
			"e2e-convergence": ns, "app.kubernetes.io/name": "escalation-config", "breakglass.t-caas.telekom.com/debug-sessions-enabled": "true",
			"breakglass.t-caas.telekom.com/platform-diagnostics": "true", "breakglass.t-caas.telekom.com/platform-node-diagnostics": "true", "breakglass.t-caas.telekom.com/emergency-node-diagnostics": "true",
		}}, Spec: *source.Spec.DeepCopy()}
		if stage != "" {
			cc.Labels["breakglass.t-caas.telekom.com/stage"] = stage
		}
		s.CreateResource(cc)
		require.Eventually(t, func() bool {
			return s.Client.Get(ctx, client.ObjectKeyFromObject(cc), cc) == nil && apimeta.IsStatusConditionTrue(cc.Status.Conditions, "Ready")
		}, time.Minute, time.Second)
		return cc
	}
	target := createCluster("target", "dev")
	expectBindings(map[string]string{target.Name: "dev"}, false)
	for _, stage := range []string{"ref", "tst", "prd", "unknown", ""} {
		require.NoError(t, s.Client.Get(ctx, client.ObjectKeyFromObject(target), target))
		if stage == "" {
			delete(target.Labels, "breakglass.t-caas.telekom.com/stage")
		} else {
			target.Labels["breakglass.t-caas.telekom.com/stage"] = stage
		}
		require.NoError(t, s.Client.Update(ctx, target))
		expectBindings(map[string]string{target.Name: stage}, false)
	}
	nonprd := createCluster("nonprd", "tst")
	expectBindings(map[string]string{target.Name: "", nonprd.Name: "tst"}, false)
	// The real OIDC requester is also an approver. Only the nonproduction binding permits self-approval.
	requester := helpers.NewAPIClientWithAuth(s.TC.OIDCProvider().GetTokenForUser(t, ctx, helpers.TestUsers.ApproverOps))
	for _, tc := range []struct {
		cluster string
		self    bool
	}{{nonprd.Name, true}, {target.Name, false}} {
		session, err := requester.CreateDebugSession(ctx, t, helpers.DebugSessionRequest{TemplateRef: templates["convergence-platform-diagnostics"], Cluster: tc.cluster, Reason: "E2E incident: verify convergence target-stage approval policy", RequestedDuration: "5m"})
		require.NoError(t, err)
		s.Cleanup.Add(session)
		helpers.WaitForDebugSessionState(t, ctx, s.Client, session.Name, session.Namespace, breakglassv1alpha1.DebugSessionStatePendingApproval, helpers.WaitForStateTimeout)
		err = requester.ApproveDebugSession(ctx, t, session.Name, "E2E diagnostic approval")
		if tc.self {
			require.NoError(t, err)
		} else {
			require.ErrorContains(t, err, "403")
		}
		require.NoError(t, requester.TerminateDebugSession(ctx, t, session.Name))
	}
	// Removing capability labels clears every previously matched target while the release stays healthy.
	for _, cc := range []*breakglassv1alpha1.ClusterConfig{target, nonprd} {
		require.NoError(t, s.Client.Get(ctx, client.ObjectKeyFromObject(cc), cc))
		cc.Labels["breakglass.t-caas.telekom.com/debug-sessions-enabled"] = "false"
		require.NoError(t, s.Client.Update(ctx, cc))
	}
	expectBindings(nil, false)
	_, err = requester.CreateDebugSession(ctx, t, helpers.DebugSessionRequest{TemplateRef: templates["convergence-platform-diagnostics"], Cluster: target.Name, Reason: "E2E incident: empty binding must not grant access"})
	require.Error(t, err)
	// Production hubs deploy only the blocked variant without a stage restriction.
	filtered := []interface{}{}
	for _, obj := range values.Resources {
		u := &unstructured.Unstructured{Object: obj}
		if u.GetKind() == "DebugSessionClusterBinding" {
			if strings.HasSuffix(u.GetName(), "-nonprd") {
				continue
			}
			unstructured.RemoveNestedField(obj, "spec", "clusterSelector", "matchExpressions")
		}
		filtered = append(filtered, obj)
	}
	require.NoError(t, s.Client.Get(ctx, client.ObjectKeyFromObject(release), release))
	require.NoError(t, unstructured.SetNestedSlice(release.Object, filtered, "spec", "values", "resources"))
	require.NoError(t, s.Client.Update(ctx, release))
	waitRelease()
	require.NoError(t, s.Client.Get(ctx, client.ObjectKeyFromObject(nonprd), nonprd))
	nonprd.Labels["breakglass.t-caas.telekom.com/debug-sessions-enabled"] = "true"
	require.NoError(t, s.Client.Update(ctx, nonprd))
	expectBindings(map[string]string{nonprd.Name: "tst"}, true)
	expectDisabledConfiguration()
	// Suspend Flux before the cleanup uninstalls its release.
	require.NoError(t, unstructured.SetNestedField(release.Object, true, "spec", "suspend"))
	require.NoError(t, s.Client.Update(ctx, release))
}
