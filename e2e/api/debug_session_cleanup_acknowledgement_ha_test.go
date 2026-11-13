//go:build e2e_ha

// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// Must match pkg/breakglass/debug (test-only fault injection).
	holdClaimEnv = "BREAKGLASS_E2E_HOLD_CLEANUP_ACKNOWLEDGEMENT_CLAIM"
	holdClaimLog = "e2e fault injection: holding cleanup acknowledgement claim"

	residualFinalizer       = "e2e.breakglass.t-caas.telekom.com/hold"
	acknowledgementWebhook  = "debugsessioncleanupacknowledgement.validation.breakglass.t-caas.telekom.com"
	retentionFinalizer      = "breakglass.t-caas.telekom.com/cleanup-acknowledgement-retention"
	webhookPropagationGrace = 40 * time.Second // controller margin (30s) plus skew
)

// TestDebugSessionCleanupAcknowledgementHA runs two controller replicas,
// kills the replica holding the claim on an Applied acknowledgement while it
// is Processing, restarts the API server, and proves the acknowledgement is
// still applied, completed and audited exactly once, and that its retention
// finalizer is kept while the session lives and released after.
func TestDebugSessionCleanupAcknowledgementHA(t *testing.T) {
	s := helpers.SetupTest(t, helpers.WithLongTimeout())
	ctx := s.Ctx
	suffix := helpers.GenerateUniqueName("ack-ha")
	ackName := suffix + "-ack"

	// Two replicas; the first claimant of ackName stalls after claiming it.
	updateController(t, s, func(d *appsv1.Deployment) {
		d.Spec.Replicas = ptr.To[int32](2)
		c := &d.Spec.Template.Spec.Containers[0]
		c.Env = append(slices.DeleteFunc(slices.Clone(c.Env), func(e corev1.EnvVar) bool { return e.Name == holdClaimEnv }),
			corev1.EnvVar{Name: holdClaimEnv, Value: ackName})
	})
	kube, err := kubernetes.NewForConfig(helpers.GetConfig(t))
	require.NoError(t, err)

	// A session whose cleanup fails: its auxiliary ConfigMap carries a
	// finalizer the controller cannot remove, so the UID stays present.
	requester := helpers.TestUsers.PlatformIdentityRequester
	template := &breakglassv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: suffix},
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			DisplayName:     "Cleanup acknowledgement HA",
			Mode:            breakglassv1alpha1.DebugSessionModeKubectlDebug,
			TargetNamespace: "breakglass-debug",
			KubectlDebug: &breakglassv1alpha1.KubectlDebugConfig{
				EphemeralContainers: &breakglassv1alpha1.EphemeralContainersConfig{Enabled: true, AllowedImages: []string{"busybox:*"}, RequireNonRoot: true},
			},
			AllowedPodOperations: &breakglassv1alpha1.AllowedPodOperations{Exec: ptr.To(true)},
			Allowed:              &breakglassv1alpha1.DebugSessionAllowed{Clusters: []string{s.Cluster}, Groups: requester.Groups},
			Approvers:            &breakglassv1alpha1.DebugSessionApprovers{AutoApproveFor: &breakglassv1alpha1.AutoApproveConfig{Clusters: []string{s.Cluster}}},
			Constraints:          &breakglassv1alpha1.DebugSessionConstraints{MaxDuration: "20m", DefaultDuration: "10m"},
			AuxiliaryResources: []breakglassv1alpha1.AuxiliaryResource{{
				Name: "residual", Category: "residual", CreateBefore: ptr.To(true), DeleteAfter: ptr.To(true),
				TemplateString: `apiVersion: v1
kind: ConfigMap
metadata:
  name: {{ .session.name }}-residual
  namespace: breakglass-debug
  finalizers:
  - ` + residualFinalizer + `
data:
  purpose: cleanup-acknowledgement-ha
`,
			}},
			RequiredAuxiliaryResourceCategories: []string{"residual"},
		},
	}
	require.NoError(t, s.CreateResource(template))

	api := s.TC.ClientForUser(requester)
	var session *breakglassv1alpha1.DebugSession
	require.Eventually(t, func() bool {
		created, err := api.CreateDebugSession(ctx, t, helpers.DebugSessionRequest{
			TemplateRef: template.Name, Cluster: s.Cluster, RequestedDuration: "10m", Reason: "cleanup acknowledgement HA",
		})
		if err != nil {
			t.Logf("create debug session: %v", err)
			return false
		}
		session = created
		return true
	}, helpers.WaitForStateTimeout, 2*time.Second)
	sessionKey := client.ObjectKeyFromObject(session)
	residual := client.ObjectKey{Namespace: "breakglass-debug", Name: session.Name + "-residual"}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		releaseResidual(cleanupCtx, s.Client, residual)
		_ = s.Client.Delete(cleanupCtx, &breakglassv1alpha1.DebugSession{ObjectMeta: metav1.ObjectMeta{Name: sessionKey.Name, Namespace: sessionKey.Namespace}})
	})
	helpers.WaitForDebugSessionState(t, ctx, s.Client, session.Name, session.Namespace, breakglassv1alpha1.DebugSessionStateActive, helpers.WaitForStateTimeout)
	require.NoError(t, api.TerminateDebugSession(ctx, t, session.Name))

	var identities []breakglassv1alpha1.CleanupAcknowledgedIdentity
	require.Eventually(t, func() bool {
		current := &breakglassv1alpha1.DebugSession{}
		if s.Client.Get(ctx, sessionKey, current) != nil || !cleanupFailed(current) {
			return false
		}
		session = current
		identities = nil
		for _, status := range current.Status.AuxiliaryResourceStatuses {
			if !status.Deleted && status.UID != "" {
				identities = append(identities, breakglassv1alpha1.CleanupAcknowledgedIdentity{
					APIVersion: status.APIVersion, Kind: status.Kind, Namespace: status.Namespace, Name: status.ResourceName, UID: status.UID,
				})
			}
		}
		return len(identities) == 1
	}, 5*time.Minute, 2*time.Second, "cleanup must fail with the held ConfigMap as the only residual")
	require.Equal(t, residual.Name, identities[0].Name)

	// An operator independent of the session acknowledges the residual.
	operator := "e2e-operator-" + suffix
	role := &rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: suffix + "-ack"}, Rules: []rbacv1.PolicyRule{{
		APIGroups: []string{breakglassv1alpha1.GroupVersion.Group}, Resources: []string{"debugsessioncleanupacknowledgements"}, Verbs: []string{"create"},
	}}}
	binding := &rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: suffix + "-ack"},
		RoleRef:  rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: role.Name},
		Subjects: []rbacv1.Subject{{APIGroup: rbacv1.GroupName, Kind: rbacv1.UserKind, Name: operator}}}
	require.NoError(t, s.CreateResource(role))
	require.NoError(t, s.CreateResource(binding))
	cfg, err := clientcmd.BuildConfigFromFlags("", helpers.GetKubeconfig())
	require.NoError(t, err)
	cfg.Impersonate.UserName, cfg.Impersonate.Groups = operator, []string{"system:authenticated"}
	asOperator, err := client.New(cfg, client.Options{Scheme: s.Client.Scheme()})
	require.NoError(t, err)

	// The controller accepts acknowledgedBy only for objects created after the
	// verifying webhook configuration last changed plus a margin.
	waitForWebhookPropagation(t, ctx, s.Client)

	ack := &breakglassv1alpha1.DebugSessionCleanupAcknowledgement{
		ObjectMeta: metav1.ObjectMeta{Name: ackName, Namespace: sessionKey.Namespace},
		Spec: breakglassv1alpha1.DebugSessionCleanupAcknowledgementSpec{
			SessionName: sessionKey.Name, SessionUID: string(session.UID), AcknowledgedBy: operator,
			Reason: "e2e: residual verified", Identities: identities,
		},
	}
	ackKey := client.ObjectKeyFromObject(ack)
	require.Eventually(t, func() bool {
		if err := asOperator.Create(ctx, ack.DeepCopy()); err != nil && !apierrors.IsAlreadyExists(err) {
			t.Logf("operator create: %v", err)
			return false
		}
		return true
	}, time.Minute, 2*time.Second, "RBAC propagation")

	// The first claimant stalls in Processing; find it by its log line.
	var holder string
	require.Eventually(t, func() bool {
		holder = podLogging(ctx, t, kube, holdClaimLog, ackName)
		return holder != ""
	}, 3*time.Minute, 2*time.Second, "a replica must claim the acknowledgement")
	claimed := &breakglassv1alpha1.DebugSessionCleanupAcknowledgement{}
	require.NoError(t, s.Client.Get(ctx, ackKey, claimed))
	require.Equal(t, breakglassv1alpha1.CleanupAcknowledgementProcessing, claimed.Status.Phase)
	require.NotNil(t, claimed.Status.ClaimedAt)
	firstClaim := claimed.Status.ClaimedAt.Time
	t.Logf("claim holder %s claimed %s at %s", holder, ackName, firstClaim)

	// Kill the claim holder, then restart the API server.
	var controllerNamespace string
	require.NoError(t, func() error {
		pods, err := controllerPods(ctx, s.Client)
		for _, p := range pods {
			if p.Name == holder {
				controllerNamespace = p.Namespace
			}
		}
		return err
	}())
	require.NoError(t, kube.CoreV1().Pods(controllerNamespace).Delete(ctx, holder, metav1.DeleteOptions{GracePeriodSeconds: ptr.To[int64](0)}))
	restartKindAPIServer(t, ctx, kube)

	// Another replica takes the claim over after its timeout and applies it.
	var done *breakglassv1alpha1.DebugSessionCleanupAcknowledgement
	require.Eventually(t, func() bool {
		current := &breakglassv1alpha1.DebugSessionCleanupAcknowledgement{}
		if s.Client.Get(ctx, ackKey, current) != nil {
			return false
		}
		done = current
		return current.Status.Phase == breakglassv1alpha1.CleanupAcknowledgementApplied && current.Status.CompletedAt != nil
	}, 10*time.Minute, 2*time.Second, "the acknowledgement must be applied and completed after the takeover")
	require.NotNil(t, done.Status.ClaimedAt)
	assert.True(t, done.Status.ClaimedAt.After(firstClaim), "a surviving replica took the claim over")
	assert.False(t, podExists(ctx, kube, controllerNamespace, holder), "the claim holder is gone")
	completedAt := done.Status.CompletedAt.Time

	isEvent := func(e helpers.ReceivedAuditEvent, eventType string) bool {
		return e.Type == eventType && e.Target.Name == sessionKey.Name && e.Target.Namespace == sessionKey.Namespace
	}
	countEvents := func() (applied, recovered int) {
		events, err := helpers.AuditEvents(ctx)
		if err != nil {
			t.Logf("audit receiver: %v", err)
			return -1, -1
		}
		for _, e := range events {
			if isEvent(e, "debug_session.cleanup_acknowledged") && e.Details["acknowledgement"] == ackName && e.Details["applied"] == true {
				applied++
			}
			if isEvent(e, "debug_session.cleanup_recovered") {
				recovered++
			}
		}
		return applied, recovered
	}
	require.Eventually(t, func() bool {
		applied, recovered := countEvents()
		return applied >= 1 && recovered >= 1
	}, 2*time.Minute, 2*time.Second, "the Applied outcome and the recovery must be audited")
	// Give stragglers time, then require exactly one of each.
	time.Sleep(30 * time.Second)
	var applied, recovered int
	require.Eventually(t, func() bool {
		applied, recovered = countEvents()
		return applied >= 0
	}, time.Minute, 2*time.Second)
	assert.Equal(t, 1, applied, "exactly one Applied cleanup_acknowledged event")
	assert.Equal(t, 1, recovered, "exactly one cleanup_recovered event")

	// Exactly one Applied processing, completed once.
	require.NoError(t, s.Client.Get(ctx, ackKey, done))
	assert.Equal(t, breakglassv1alpha1.CleanupAcknowledgementApplied, done.Status.Phase)
	require.NotNil(t, done.Status.CompletedAt)
	assert.True(t, done.Status.CompletedAt.Time.Equal(completedAt), "completedAt is written once")
	current := &breakglassv1alpha1.DebugSession{}
	require.NoError(t, s.Client.Get(ctx, sessionKey, current))
	records := 0
	for _, record := range current.Status.CleanupAcknowledgements {
		if record.UID == string(done.UID) {
			records++
		}
	}
	assert.Equal(t, 1, records, "the session records the acknowledgement once")
	assert.False(t, cleanupFailed(current), "the acknowledged residual is retired")

	// The retention finalizer holds the evidence while the session lives.
	require.Contains(t, done.Finalizers, retentionFinalizer)
	require.NoError(t, s.Client.Delete(ctx, done))
	time.Sleep(10 * time.Second)
	held := &breakglassv1alpha1.DebugSessionCleanupAcknowledgement{}
	require.NoError(t, s.Client.Get(ctx, ackKey, held), "the finalizer keeps a deleted acknowledgement while its session lives")
	assert.NotNil(t, held.DeletionTimestamp)

	// Once the session is gone, the finalizer is released.
	releaseResidual(ctx, s.Client, residual)
	require.NoError(t, s.Client.Delete(ctx, current))
	require.Eventually(t, func() bool {
		return apierrors.IsNotFound(s.Client.Get(ctx, sessionKey, &breakglassv1alpha1.DebugSession{}))
	}, 5*time.Minute, 2*time.Second, "the session must be deleted")
	require.Eventually(t, func() bool {
		return apierrors.IsNotFound(s.Client.Get(ctx, ackKey, &breakglassv1alpha1.DebugSessionCleanupAcknowledgement{}))
	}, 3*time.Minute, 2*time.Second, "the retention finalizer must be released once the session is gone")
}

func cleanupFailed(ds *breakglassv1alpha1.DebugSession) bool {
	condition := ds.GetCondition(string(breakglassv1alpha1.DebugSessionConditionCleanupFailed))
	return condition != nil && condition.Status == metav1.ConditionTrue
}

// releaseResidual removes the test finalizer from the held ConfigMap.
func releaseResidual(ctx context.Context, c client.Client, key client.ObjectKey) {
	cm := &corev1.ConfigMap{}
	if c.Get(ctx, key, cm) != nil {
		return
	}
	base := cm.DeepCopy()
	cm.Finalizers = slices.DeleteFunc(cm.Finalizers, func(f string) bool { return f == residualFinalizer })
	_ = c.Patch(ctx, cm, client.MergeFrom(base))
}

// waitForWebhookPropagation waits until the acknowledgement webhook
// configuration has been unchanged for longer than the controller's margin.
func waitForWebhookPropagation(t *testing.T, ctx context.Context, c client.Client) {
	t.Helper()
	var configs admissionregistrationv1.ValidatingWebhookConfigurationList
	require.NoError(t, c.List(ctx, &configs))
	var since time.Time
	for _, config := range configs.Items {
		if !slices.ContainsFunc(config.Webhooks, func(w admissionregistrationv1.ValidatingWebhook) bool { return w.Name == acknowledgementWebhook }) {
			continue
		}
		since = config.CreationTimestamp.Time
		for _, entry := range config.ManagedFields {
			if entry.Time != nil && entry.Time.After(since) {
				since = entry.Time.Time
			}
		}
	}
	require.False(t, since.IsZero(), "the acknowledgement webhook must be configured")
	if wait := time.Until(since.Add(webhookPropagationGrace)); wait > 0 {
		t.Logf("waiting %s for the acknowledgement webhook to be verifiably enforced", wait)
		time.Sleep(wait)
	}
}

func controllerPods(ctx context.Context, c client.Client) ([]corev1.Pod, error) {
	var pods corev1.PodList
	err := c.List(ctx, &pods, client.MatchingLabels{"app": "breakglass"})
	return pods.Items, err
}

// podLogging returns the controller pod whose log contains both strings.
func podLogging(ctx context.Context, t *testing.T, kube kubernetes.Interface, want ...string) string {
	pods, err := kube.CoreV1().Pods("").List(ctx, metav1.ListOptions{LabelSelector: "app=breakglass"})
	if err != nil {
		t.Logf("list controller pods: %v", err)
		return ""
	}
	for _, p := range pods.Items {
		logs, err := kube.CoreV1().Pods(p.Namespace).GetLogs(p.Name, &corev1.PodLogOptions{Container: p.Spec.Containers[0].Name}).DoRaw(ctx)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(logs), "\n") {
			if !slices.ContainsFunc(want, func(w string) bool { return !strings.Contains(line, w) }) {
				return p.Name
			}
		}
	}
	return ""
}

func podExists(ctx context.Context, kube kubernetes.Interface, namespace, name string) bool {
	_, err := kube.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{})
	return err == nil
}

// restartKindAPIServer stops the kube-apiserver container of the Kind control
// plane and waits until the kubelet has restarted it and it is ready again.
func restartKindAPIServer(t *testing.T, ctx context.Context, kube kubernetes.Interface) {
	t.Helper()
	cluster := os.Getenv("KIND_CLUSTER_NAME")
	if cluster == "" {
		cluster = "breakglass-hub"
	}
	node := cluster + "-control-plane"
	crictl := func(args ...string) (string, error) {
		out, err := exec.CommandContext(ctx, "docker", append([]string{"exec", node, "crictl", "--runtime-endpoint", "unix:///run/containerd/containerd.sock"}, args...)...).CombinedOutput()
		return strings.TrimSpace(string(out)), err
	}
	before, err := crictl("ps", "--name", "kube-apiserver", "-q")
	require.NoError(t, err, before)
	ids := strings.Fields(before)
	require.Len(t, ids, 1, "expected one running kube-apiserver on %s", node)
	out, err := crictl("stop", ids[0])
	require.NoError(t, err, out)
	t.Logf("stopped kube-apiserver container %s on %s", ids[0], node)
	require.Eventually(t, func() bool {
		after, err := crictl("ps", "--name", "kube-apiserver", "-q")
		if err != nil || after == "" || after == ids[0] {
			return false
		}
		raw, err := kube.Discovery().RESTClient().Get().AbsPath("/readyz").DoRaw(ctx)
		return err == nil && string(raw) == "ok"
	}, 3*time.Minute, 2*time.Second, "the API server must come back")
}
