// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/audit"
	"github.com/telekom/k8s-breakglass/pkg/cluster"
	"go.uber.org/zap"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// TestHotfixKind runs the hotfix stages end to end on a disposable Kind
// cluster: the HTTP request and approval handlers, the controller, the real
// executor image and real node changes. Only OIDC middleware and audit
// delivery are in-process fixtures. Run hack/hotfix-controller-kind.sh.
func TestHotfixKind(t *testing.T) {
	kubeconfig := os.Getenv("HOTFIX_KIND_KUBECONFIG")
	if kubeconfig == "" {
		t.Skip("run hack/hotfix-controller-kind.sh for the disposable Kind proof")
	}
	t.Setenv("BREAKGLASS_DISABLE_LOOPBACK_REWRITE", "true")
	nodeName, image := os.Getenv("HOTFIX_KIND_NODE"), os.Getenv("HOTFIX_KIND_IMAGE")
	containerID, schedulerImage := os.Getenv("HOTFIX_KIND_CONTAINER_ID"), os.Getenv("HOTFIX_KIND_SCHEDULER_IMAGE")
	require.Regexp(t, "^[0-9a-f]{64}$", containerID)
	require.True(t, strings.HasPrefix(nodeName, "hotfix-proof-") && strings.HasSuffix(nodeName, "-control-plane"))
	require.Contains(t, image, "@sha256:")
	require.Contains(t, schedulerImage, "@sha256:")
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Minute)
	defer cancel()
	cfg, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	require.NoError(t, err)
	hub, err := client.New(cfg, client.Options{Scheme: Scheme})
	require.NoError(t, err)
	node := &corev1.Node{}
	require.NoError(t, hub.Get(ctx, client.ObjectKey{Name: nodeName}, node))
	const namespace = "hotfix-proof-hub"
	require.NoError(t, hub.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}))
	raw, err := os.ReadFile(kubeconfig)
	require.NoError(t, err)
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "spoke-kubeconfig", Namespace: namespace}, Data: map[string][]byte{"value": raw}}
	require.NoError(t, hub.Create(ctx, secret))
	cc := &breakglassv1alpha1.ClusterConfig{ObjectMeta: metav1.ObjectMeta{Name: "hotfix-spoke", Namespace: namespace},
		Spec: breakglassv1alpha1.ClusterConfigSpec{KubeconfigSecretRef: &breakglassv1alpha1.SecretKeyReference{Name: secret.Name, Namespace: namespace}}}
	require.NoError(t, hub.Create(ctx, cc))
	cc.Status.Conditions = []metav1.Condition{{Type: "Ready", Status: metav1.ConditionTrue, Reason: "DisposableKindProof", LastTransitionTime: metav1.Now()}}
	cc.Status.ObservedGeneration = cc.Generation
	require.NoError(t, hub.Status().Update(ctx, cc))
	provider := cluster.NewClientProvider(hub, zap.NewNop().Sugar())
	controller := NewDebugSessionController(zap.NewExample().Sugar(), hub, provider).WithAPIReader(hub)
	sink := &maintenanceAuditCaptureSink{}
	manager := audit.NewManager(sink, audit.ManagerConfig{QueueSize: 64, WorkerCount: 1}, zap.NewNop())
	t.Cleanup(func() { _ = manager.Close() })
	controller.WithAuditManager(manager)
	api := NewDebugSessionAPIController(zap.NewNop().Sugar(), hub, provider, nil).WithAPIReader(hub)
	router := gin.New()
	actor := "approver@example.com"
	router.Use(func(c *gin.Context) {
		c.Set("legacy_identity_allowed", true)
		c.Set("username", actor)
		c.Set("email", actor)
		c.Set("groups", []string{})
		c.Next()
	})
	require.NoError(t, api.Register(router.Group("/debugSessions")))

	template := &breakglassv1alpha1.DebugSessionTemplate{ObjectMeta: metav1.ObjectMeta{Name: "platform-hotfix"},
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			TargetNamespace:   breakglassv1alpha1.NodeMaintenanceNamespace,
			BlockSelfApproval: ptr.To(true),
			Allowed:           &breakglassv1alpha1.DebugSessionAllowed{Users: []string{"requester@example.com", "approver@example.com"}, Clusters: []string{cc.Name}},
			Approvers:         &breakglassv1alpha1.DebugSessionApprovers{Users: []string{"approver@example.com", "requester@example.com"}},
			Constraints:       &breakglassv1alpha1.DebugSessionConstraints{MaxDuration: "1h", DefaultDuration: "1h"},
			Hotfix: &breakglassv1alpha1.DebugSessionHotfix{ExecutorImage: image, MinSoakSeconds: 1, NodeDeadlineSeconds: 600,
				PayloadTypes: []breakglassv1alpha1.HotfixPayloadType{breakglassv1alpha1.HotfixPayloadNodeFile, breakglassv1alpha1.HotfixPayloadStaticPodImage},
				AllowedPaths: []string{"/etc/hotfix-proof/"}, StaticPods: []breakglassv1alpha1.HotfixStaticPod{"kube-scheduler"}},
		}}
	require.NoError(t, hub.Create(ctx, template))

	request := func(hotfix *breakglassv1alpha1.DebugSessionHotfixRequest) *breakglassv1alpha1.DebugSession {
		t.Helper()
		body, err := json.Marshal(CreateDebugSessionRequest{TemplateRef: template.Name, Cluster: cc.Name, RequestedDuration: "1h",
			Reason: "Disposable platform hotfix proof", Hotfix: hotfix})
		require.NoError(t, err)
		actor = "requester@example.com"
		httpRequest := httptest.NewRequest(http.MethodPost, "/debugSessions", bytes.NewReader(body))
		httpRequest.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, httpRequest)
		require.Equal(t, http.StatusCreated, response.Code, response.Body.String())
		var created DebugSessionDetailResponse
		require.NoError(t, json.Unmarshal(response.Body.Bytes(), &created))
		return &created.DebugSession
	}
	approve := func(session *breakglassv1alpha1.DebugSession, who string, expected int) {
		t.Helper()
		actor = who
		response := httptest.NewRecorder()
		router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/debugSessions/"+session.Name+"/approve?namespace="+namespace, nil))
		require.Equal(t, expected, response.Code, response.Body.String())
	}
	// run requests, proves self-approval is refused, approves and reconciles to the end.
	run := func(hotfix *breakglassv1alpha1.DebugSessionHotfixRequest) *breakglassv1alpha1.DebugSession {
		t.Helper()
		session := request(hotfix)
		_, err := controller.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(session)})
		require.NoError(t, err)
		approve(session, "requester@example.com", http.StatusForbidden)
		approve(session, "approver@example.com", http.StatusOK)
		deadline := time.Now().Add(10 * time.Minute)
		for time.Now().Before(deadline) {
			result, err := controller.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(session)})
			require.NoError(t, hub.Get(ctx, client.ObjectKeyFromObject(session), session))
			if err != nil {
				t.Logf("reconcile: %v", err)
			}
			switch session.Status.State {
			case breakglassv1alpha1.DebugSessionStateTerminated, breakglassv1alpha1.DebugSessionStateFailed, breakglassv1alpha1.DebugSessionStateExpired:
				// One more pass releases cleanup state.
				_, _ = controller.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(session)})
				return session
			}
			time.Sleep(min(max(result.RequeueAfter, 500*time.Millisecond), 3*time.Second))
		}
		t.Fatalf("session %s did not finish: %s", session.Name, session.Status.Message)
		return nil
	}
	nodeExec := func(args ...string) string {
		t.Helper()
		output, err := exec.CommandContext(ctx, "docker", append([]string{"exec", containerID}, args...)...).CombinedOutput()
		require.NoError(t, err, string(output))
		return string(output)
	}
	noExecutorsOrLeases := func() {
		t.Helper()
		pods := &corev1.PodList{}
		require.NoError(t, hub.List(ctx, pods, client.InNamespace(breakglassv1alpha1.NodeMaintenanceNamespace)))
		require.Empty(t, pods.Items)
		leases := &coordinationv1.LeaseList{}
		require.NoError(t, hub.List(ctx, leases, client.InNamespace(breakglassv1alpha1.NodeMaintenanceNamespace)))
		require.Empty(t, leases.Items)
	}
	lifecycle := func(t *testing.T, payload *breakglassv1alpha1.HotfixPayload, applied, original func()) {
		plan := run(&breakglassv1alpha1.DebugSessionHotfixRequest{Stage: breakglassv1alpha1.HotfixStagePlan, Payload: payload,
			Nodes: &breakglassv1alpha1.HotfixNodeSelection{Names: []string{nodeName}}, FixedIn: "next node image"})
		require.Equal(t, breakglassv1alpha1.DebugSessionStateTerminated, plan.Status.State, plan.Status.Message)
		require.Len(t, plan.Status.Hotfix.Plan.Diffs, 1)
		diffs, _ := json.MarshalIndent(plan.Status.Hotfix.Plan.Diffs, "", "  ")
		t.Logf("reviewed diffs: %s", diffs)
		original()
		noExecutorsOrLeases()

		apply := run(&breakglassv1alpha1.DebugSessionHotfixRequest{Stage: breakglassv1alpha1.HotfixStageApply,
			PlanRef: plan.Name, PlanHash: plan.Status.Hotfix.PlanHash})
		require.Equal(t, breakglassv1alpha1.DebugSessionStateTerminated, apply.Status.State, apply.Status.Message)
		applied()
		noExecutorsOrLeases()
		record := &breakglassv1alpha1.HotfixRecord{}
		require.NoError(t, hub.Get(ctx, client.ObjectKey{Namespace: namespace, Name: apply.Status.Hotfix.RecordName}, record))
		require.Equal(t, breakglassv1alpha1.HotfixNodeApplied, record.Status.Nodes[0].State)
		require.NoError(t, hub.Get(ctx, client.ObjectKey{Name: nodeName}, node))
		require.Contains(t, node.Annotations, hotfixAnnotationKey(record.Name))

		rollback := run(&breakglassv1alpha1.DebugSessionHotfixRequest{Stage: breakglassv1alpha1.HotfixStageRollback, RecordName: record.Name})
		require.Equal(t, breakglassv1alpha1.DebugSessionStateTerminated, rollback.Status.State, rollback.Status.Message)
		original()
		noExecutorsOrLeases()
		require.NoError(t, hub.Get(ctx, client.ObjectKeyFromObject(record), record))
		require.True(t, meta.IsStatusConditionTrue(record.Status.Conditions, string(breakglassv1alpha1.HotfixRecordConditionClosed)))
	}

	t.Run("node-file sed", func(t *testing.T) {
		const file = "/etc/hotfix-proof/app.conf"
		lifecycle(t, &breakglassv1alpha1.HotfixPayload{Type: breakglassv1alpha1.HotfixPayloadNodeFile,
			File: &breakglassv1alpha1.HotfixFilePayload{Path: file, Mode: breakglassv1alpha1.HotfixFileSed, SedExpressions: []string{"s/^mode = old$/mode = new/"}}},
			func() { require.Equal(t, "mode = new\nkeep = yes\n", nodeExec("cat", file)) },
			func() { require.Equal(t, "mode = old\nkeep = yes\n", nodeExec("cat", file)) })
	})

	t.Run("static-pod-image kube-scheduler", func(t *testing.T) {
		manifest := nodeExec("cat", "/etc/kubernetes/manifests/kube-scheduler.yaml")
		// The pinned image has the same content as the running one, so a
		// new container ID is what proves kubelet restarted the Pod.
		schedulerContainer := func() string {
			output, err := exec.CommandContext(ctx, "docker", "exec", containerID, "crictl", "ps", "--name", "^kube-scheduler$", "--state", "running", "-q").Output()
			if err != nil {
				return ""
			}
			return strings.TrimSpace(string(output))
		}
		previous := schedulerContainer()
		require.NotEmpty(t, previous)
		rolledBack := false
		restarted := func() {
			require.Eventually(t, func() bool {
				current := schedulerContainer()
				return current != "" && current != previous && !strings.Contains(current, "\n")
			}, 2*time.Minute, 2*time.Second, "kube-scheduler restarted")
			previous = schedulerContainer()
		}
		lifecycle(t, &breakglassv1alpha1.HotfixPayload{Type: breakglassv1alpha1.HotfixPayloadStaticPodImage,
			Image: &breakglassv1alpha1.HotfixImagePayload{StaticPod: "kube-scheduler", Image: schedulerImage}},
			func() {
				require.Contains(t, nodeExec("cat", "/etc/kubernetes/manifests/kube-scheduler.yaml"), "image: "+schedulerImage)
				restarted()
				require.Contains(t, nodeExec("crictl", "inspect", previous), schedulerImage[strings.LastIndex(schedulerImage, "@")+1:])
			},
			func() {
				require.Equal(t, manifest, nodeExec("cat", "/etc/kubernetes/manifests/kube-scheduler.yaml"))
				if rolledBack {
					restarted() // the rollback restarts it with the original reference
				}
				rolledBack = true // the next call follows the rollback
			})
	})

	types := map[audit.EventType]bool{}
	for _, event := range sink.Events() {
		types[event.Type] = true
	}
	for _, want := range []audit.EventType{audit.EventDebugSessionHotfixIntent, audit.EventDebugSessionHotfixNodeIntent,
		audit.EventDebugSessionHotfixNodeResult, audit.EventDebugSessionHotfixResult} {
		require.True(t, types[want], want)
	}
}
