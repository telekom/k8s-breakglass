// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"bytes"
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
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// kindNetnsState prints the tc filters of eth0 and the links of a network
// namespace on the Kind node: the Pod's when podUID is set, else the Node's.
const kindNetnsState = `uid=$1
pid=1
if [ -n "$uid" ]; then
	alt=$(printf '%s' "$uid" | tr - _)
	pid=$(grep -l -e "pod$uid" -e "pod$alt" /proc/[0-9]*/cgroup 2>/dev/null | head -1 | cut -d/ -f3)
	[ -n "$pid" ] || { echo NETNS-GONE; exit 0; }
fi
for hook in ingress egress; do nsenter -t "$pid" -n tc filter show dev eth0 "$hook"; done
nsenter -t "$pid" -n ip -o link show`

// kindKillAgent SIGKILLs the mirror agent, which cannot trap it: its tc
// filters and mirror device stay behind like after a crash.
const kindKillAgent = `for dir in /proc/[0-9]*; do
	if [ "$(tr '\0' '\n' <"$dir/cmdline" 2>/dev/null | tail -2 | paste -sd' ')" = "traffic-mirror attach" ]; then
		kill -9 "${dir#/proc/}"
		exit 0
	fi
done
exit 1`

// TestTrafficMirrorKind is a composed proof on a real Kind cluster: HTTP
// request, independent approval, controller-created mirror Pod, real tc
// mirred mirroring into the session capture container, controller restart,
// expiry, a crashed agent, and verified removal of every tc filter and mirror
// device. Run it with hack/traffic-mirror-kind.sh.
func TestTrafficMirrorKind(t *testing.T) {
	kubeconfig := os.Getenv("TRAFFIC_MIRROR_KIND_KUBECONFIG")
	if kubeconfig == "" {
		t.Skip("run hack/traffic-mirror-kind.sh for the disposable Kind proof")
	}
	t.Setenv("BREAKGLASS_DISABLE_LOOPBACK_REWRITE", "true")
	nodeID, image := os.Getenv("TRAFFIC_MIRROR_KIND_CONTAINER_ID"), os.Getenv("TRAFFIC_MIRROR_KIND_IMAGE")
	require.Regexp(t, "^[0-9a-f]{64}$", nodeID)
	require.Contains(t, image, "@sha256:")
	ctx := t.Context()
	cfg, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	require.NoError(t, err)
	hub, err := client.New(cfg, client.Options{Scheme: Scheme})
	require.NoError(t, err)
	clientset, err := kubernetes.NewForConfig(cfg)
	require.NoError(t, err)
	nodes := &corev1.NodeList{}
	require.NoError(t, hub.List(ctx, nodes))
	require.Len(t, nodes.Items, 1)
	nodeName := nodes.Items[0].Name

	const namespace, workloads = "traffic-mirror-hub", "mirror-proof"
	require.NoError(t, hub.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}))
	require.NoError(t, hub.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: workloads}}))
	shell := func(name, app, script string) *corev1.Pod {
		return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: workloads, Labels: map[string]string{"app": app}},
			Spec: corev1.PodSpec{AutomountServiceAccountToken: ptr.To(false), TerminationGracePeriodSeconds: ptr.To(int64(1)),
				Containers: []corev1.Container{{Name: "main", Image: image, Command: []string{"/bin/sh", "-c", script}}}}}
	}
	server := "while true; do printf 'HTTP/1.1 204 No Content\\r\\nContent-Length: 0\\r\\n\\r\\n' | nc -l -p 8080 -q 1 >/dev/null 2>&1; done"
	for _, pod := range []*corev1.Pod{shell("target", "target", server), shell("decoy", "decoy", server)} {
		require.NoError(t, hub.Create(ctx, pod))
	}
	podIP := func(name string) string {
		pod := &corev1.Pod{}
		require.Eventually(t, func() bool {
			return hub.Get(ctx, client.ObjectKey{Namespace: workloads, Name: name}, pod) == nil && pod.Status.Phase == corev1.PodRunning && pod.Status.PodIP != ""
		}, 3*time.Minute, time.Second, "workload %s did not start", name)
		return pod.Status.PodIP
	}
	targetIP, decoyIP := podIP("target"), podIP("decoy")
	traffic := "while true; do curl -s -m 1 http://" + targetIP + ":8080/ >/dev/null; curl -s -m 1 http://" + decoyIP + ":8080/ >/dev/null; sleep 0.2; done"
	require.NoError(t, hub.Create(ctx, shell("client", "client", traffic)))
	podIP("client")
	target := &corev1.Pod{}
	require.NoError(t, hub.Get(ctx, client.ObjectKey{Namespace: workloads, Name: "target"}, target))

	raw, err := os.ReadFile(kubeconfig)
	require.NoError(t, err)
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "spoke-kubeconfig", Namespace: namespace}, Data: map[string][]byte{"value": raw}}
	require.NoError(t, hub.Create(ctx, secret))
	cc := &breakglassv1alpha1.ClusterConfig{ObjectMeta: metav1.ObjectMeta{Name: "mirror-spoke", Namespace: namespace},
		Spec: breakglassv1alpha1.ClusterConfigSpec{KubeconfigSecretRef: &breakglassv1alpha1.SecretKeyReference{Name: secret.Name, Namespace: namespace}}}
	require.NoError(t, hub.Create(ctx, cc))
	cc.Status.Conditions = []metav1.Condition{{Type: "Ready", Status: metav1.ConditionTrue, Reason: "DisposableKindProof", LastTransitionTime: metav1.Now()}}
	cc.Status.ObservedGeneration = cc.Generation
	require.NoError(t, hub.Status().Update(ctx, cc))

	provider := cluster.NewClientProvider(hub, zap.NewNop().Sugar())
	sink := &maintenanceAuditCaptureSink{}
	manager := audit.NewManager(sink, audit.ManagerConfig{QueueSize: 16, WorkerCount: 1}, zap.NewNop())
	t.Cleanup(func() { _ = manager.Close() })
	newController := func() *DebugSessionController {
		return NewDebugSessionController(zap.NewExample().Sugar(), hub, provider).WithAPIReader(hub).WithAuditManager(manager)
	}
	controller := newController()
	api := NewDebugSessionAPIController(zap.NewNop().Sugar(), hub, provider, nil).WithAPIReader(hub)
	router := gin.New()
	actor := "requester@example.com"
	router.Use(func(c *gin.Context) {
		c.Set("legacy_identity_allowed", true)
		c.Set("username", actor)
		c.Set("email", actor)
		c.Set("groups", []string{})
		c.Next()
	})
	require.NoError(t, api.Register(router.Group("/debugSessions")))
	call := func(as, method, path string, body []byte, expected int) []byte {
		t.Helper()
		actor = as
		request := httptest.NewRequest(method, path, bytes.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		require.Equal(t, expected, response.Code, response.Body.String())
		return response.Body.Bytes()
	}
	reconcile := func(session *breakglassv1alpha1.DebugSession) {
		t.Helper()
		_, _ = controller.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(session)})
		require.NoError(t, hub.Get(ctx, client.ObjectKeyFromObject(session), session))
	}
	netns := func(podUID string) string {
		t.Helper()
		output, err := exec.CommandContext(ctx, "docker", "exec", nodeID, "sh", "-c", kindNetnsState, "netns", podUID).CombinedOutput()
		require.NoError(t, err, string(output))
		return string(output)
	}
	captureLog := func(session *breakglassv1alpha1.DebugSession) string {
		raw, err := clientset.CoreV1().Pods(breakglassv1alpha1.NodeMaintenanceNamespace).
			GetLogs(session.Status.TrafficMirror.OperationID, &corev1.PodLogOptions{Container: "capture"}).DoRaw(ctx)
		if err != nil {
			return ""
		}
		return string(raw)
	}
	template := func(name, filter string, source breakglassv1alpha1.TrafficMirrorSource, maxDuration string) {
		require.NoError(t, hub.Create(ctx, &breakglassv1alpha1.DebugSessionTemplate{ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
				TargetNamespace: breakglassv1alpha1.NodeMaintenanceNamespace,
				Allowed:         &breakglassv1alpha1.DebugSessionAllowed{Users: []string{"requester@example.com"}, Clusters: []string{cc.Name}},
				Approvers:       &breakglassv1alpha1.DebugSessionApprovers{Users: []string{"approver@example.com"}},
				Constraints:     &breakglassv1alpha1.DebugSessionConstraints{MaxDuration: maxDuration, DefaultDuration: maxDuration},
				TrafficMirror: &breakglassv1alpha1.DebugSessionTrafficMirror{Image: image, Filter: filter, SnapLength: 128,
					AllowedSources: []breakglassv1alpha1.TrafficMirrorSource{source}},
			}}))
	}
	request := func(templateName, duration string, source breakglassv1alpha1.TrafficMirrorRequest, expected int) *breakglassv1alpha1.DebugSession {
		t.Helper()
		body, err := json.Marshal(CreateDebugSessionRequest{TemplateRef: templateName, Cluster: cc.Name, RequestedDuration: duration,
			Reason: "Disposable traffic mirror proof", TrafficMirror: &source})
		require.NoError(t, err)
		response := call("requester@example.com", http.MethodPost, "/debugSessions", body, expected)
		if expected != http.StatusCreated {
			return nil
		}
		var created DebugSessionDetailResponse
		require.NoError(t, json.Unmarshal(response, &created))
		session := &created.DebugSession
		reconcile(session)
		require.Equal(t, breakglassv1alpha1.DebugSessionStatePendingApproval, session.Status.State, session.Status.Message)
		require.Nil(t, session.Status.TrafficMirror, "nothing runs before approval")
		call("requester@example.com", http.MethodPost, "/debugSessions/"+session.Name+"/approve?namespace="+session.Namespace, nil, http.StatusForbidden)
		call("approver@example.com", http.MethodPost, "/debugSessions/"+session.Name+"/approve?namespace="+session.Namespace, nil, http.StatusOK)
		require.NoError(t, hub.Get(ctx, client.ObjectKeyFromObject(session), session))
		reconcile(session)
		require.Equal(t, breakglassv1alpha1.DebugSessionStateActive, session.Status.State, session.Status.Message)
		require.Eventually(t, func() bool {
			reconcile(session)
			return session.Status.State != breakglassv1alpha1.DebugSessionStateActive ||
				session.Status.TrafficMirror.State == breakglassv1alpha1.TrafficMirrorStateMirroring
		}, 3*time.Minute, 2*time.Second, "the mirror never attached")
		require.Equal(t, breakglassv1alpha1.DebugSessionStateActive, session.Status.State, session.Status.Message)
		return session
	}
	requireMirrored := func(session *breakglassv1alpha1.DebugSession, needle string) {
		t.Helper()
		require.Eventually(t, func() bool { return strings.Contains(captureLog(session), needle) }, time.Minute, time.Second,
			"the capture container never saw %q", needle)
	}
	requireCleaned := func(session *breakglassv1alpha1.DebugSession, podUID string) {
		t.Helper()
		require.Eventually(t, func() bool {
			reconcile(session)
			return session.Status.TrafficMirror.Released
		}, 3*time.Minute, 2*time.Second, "cleanup never verified the teardown: %s", session.Status.Message)
		require.True(t, session.Status.TrafficMirror.TeardownVerified)
		cookie, _, veth := trafficMirrorTuple(session.Status.TrafficMirror.OperationID)
		state := netns(podUID)
		require.NotContains(t, state, cookie, "no tc filter of the session remains")
		require.NotContains(t, state, veth, "no mirror device remains")
		require.NotContains(t, state, "mirred")
		pods := &corev1.PodList{}
		require.NoError(t, hub.List(ctx, pods, client.InNamespace(breakglassv1alpha1.NodeMaintenanceNamespace)))
		require.Empty(t, pods.Items, "mirror and teardown Pods are gone")
	}
	requireActiveState := func(session *breakglassv1alpha1.DebugSession, podUID string) {
		t.Helper()
		cookie, _, veth := trafficMirrorTuple(session.Status.TrafficMirror.OperationID)
		state := netns(podUID)
		require.Contains(t, state, "cookie "+cookie)
		require.Contains(t, state, veth)
	}
	eventCount := func(session *breakglassv1alpha1.DebugSession, eventType audit.EventType) int {
		count := 0
		for _, event := range sink.Events() {
			if event.Type == eventType && event.Details["sessionUID"] == string(session.UID) {
				count++
			}
		}
		return count
	}

	template("mirror-pod", "tcp port 8080", breakglassv1alpha1.TrafficMirrorSource{
		Pod: &breakglassv1alpha1.TrafficMirrorPodSource{Namespace: workloads, MatchLabels: map[string]string{"app": "target"}}, Interfaces: []string{"eth0"}}, "10m")
	template("mirror-node", "tcp port 6443", breakglassv1alpha1.TrafficMirrorSource{
		Node: &breakglassv1alpha1.TrafficMirrorNodeSource{}, Interfaces: []string{"eth0"}}, "1m")
	podSource := breakglassv1alpha1.TrafficMirrorRequest{PodNamespace: workloads, PodName: "target", Interface: "eth0"}

	t.Run("allowlist is enforced", func(t *testing.T) {
		request("mirror-pod", "10m", breakglassv1alpha1.TrafficMirrorRequest{PodNamespace: workloads, PodName: "decoy", Interface: "eth0"}, http.StatusBadRequest)
		request("mirror-pod", "10m", breakglassv1alpha1.TrafficMirrorRequest{PodNamespace: workloads, PodName: "target", Interface: "lo"}, http.StatusBadRequest)
		request("mirror-pod", "10m", breakglassv1alpha1.TrafficMirrorRequest{NodeName: nodeName, Interface: "eth0"}, http.StatusBadRequest)
	})

	t.Run("pod mirror survives a controller restart and is removed on terminate", func(t *testing.T) {
		session := request("mirror-pod", "10m", podSource, http.StatusCreated)
		require.Equal(t, string(target.UID), session.Spec.TrafficMirror.PodUID)
		requireMirrored(session, targetIP+".8080")
		require.NotContains(t, captureLog(session), decoyIP+".8080", "only the target's interface is mirrored")
		requireActiveState(session, string(target.UID))
		require.Len(t, session.Status.AllowedPods, 1)
		require.True(t, *session.Status.AllowedPodOperations.Logs)
		require.False(t, *session.Status.AllowedPodOperations.Exec)
		call("requester@example.com", http.MethodPost, "/debugSessions/"+session.Name+"/renew?namespace="+session.Namespace, []byte(`{"extendBy":"5m"}`), http.StatusBadRequest)

		controller = newController() // controller restart mid-session
		reconcile(session)
		require.Equal(t, breakglassv1alpha1.TrafficMirrorStateMirroring, session.Status.TrafficMirror.State)
		call("requester@example.com", http.MethodPost, "/debugSessions/"+session.Name+"/terminate?namespace="+session.Namespace, nil, http.StatusOK)
		requireCleaned(session, string(target.UID))
		require.Equal(t, 1, eventCount(session, audit.EventDebugSessionTrafficMirrorStarted))
		require.Equal(t, 1, eventCount(session, audit.EventDebugSessionTrafficMirrorStopped))
	})

	t.Run("node mirror is removed at expiry", func(t *testing.T) {
		session := request("mirror-node", "1m", breakglassv1alpha1.TrafficMirrorRequest{NodeName: nodeName, Interface: "eth0"}, http.StatusCreated)
		requireMirrored(session, ".6443")
		requireActiveState(session, "")
		require.Eventually(t, func() bool {
			reconcile(session)
			return session.Status.State != breakglassv1alpha1.DebugSessionStateActive
		}, 2*time.Minute, 5*time.Second, "the hard deadline expires the session")
		require.Equal(t, breakglassv1alpha1.DebugSessionStateExpired, session.Status.State)
		controller = newController()
		requireCleaned(session, "")
	})

	t.Run("a killed agent leaves state that cleanup removes", func(t *testing.T) {
		session := request("mirror-pod", "10m", podSource, http.StatusCreated)
		requireMirrored(session, targetIP+".8080")
		output, err := exec.CommandContext(ctx, "docker", "exec", nodeID, "sh", "-c", kindKillAgent).CombinedOutput()
		require.NoError(t, err, string(output))
		require.Eventually(t, func() bool {
			pod := &corev1.Pod{}
			if hub.Get(ctx, client.ObjectKey{Namespace: breakglassv1alpha1.NodeMaintenanceNamespace, Name: session.Status.TrafficMirror.OperationID}, pod) != nil {
				return false
			}
			return trafficMirrorFailure(pod) != ""
		}, time.Minute, time.Second)
		requireActiveState(session, string(target.UID)) // SIGKILL ran no trap: the filters are still attached
		controller = newController()
		reconcile(session)
		require.Equal(t, breakglassv1alpha1.DebugSessionStateFailed, session.Status.State, session.Status.Message)
		requireCleaned(session, string(target.UID))
		require.Equal(t, 1, eventCount(session, audit.EventDebugSessionTrafficMirrorFailed))
		require.Equal(t, 1, eventCount(session, audit.EventDebugSessionTrafficMirrorStopped))
	})
}
