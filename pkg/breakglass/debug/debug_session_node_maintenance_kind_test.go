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
	batchv1 "k8s.io/api/batch/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// This composed proof uses a real Kind API server, the approval HTTP handler,
// controller and immutable helper image. Only OIDC middleware/audit delivery
// are in-process test fixtures; kernel mutations and Lease arbitration are real.
func TestNodeMaintenanceKind(t *testing.T) {
	kubeconfig := os.Getenv("NODE_MAINTENANCE_KIND_KUBECONFIG")
	if kubeconfig == "" {
		t.Skip("run hack/node-maintenance-controller-kind.sh for the disposable Kind proof")
	}
	t.Setenv("BREAKGLASS_DISABLE_LOOPBACK_REWRITE", "true")
	nodeName, image := os.Getenv("NODE_MAINTENANCE_KIND_NODE"), os.Getenv("NODE_MAINTENANCE_KIND_IMAGE")
	containerID := os.Getenv("NODE_MAINTENANCE_KIND_CONTAINER_ID")
	actionFilter := os.Getenv("NODE_MAINTENANCE_KIND_ACTION")
	require.Contains(t, []string{"", "neighbor", "fdb", "kexec"}, actionFilter)
	require.Regexp(t, "^[0-9a-f]{64}$", containerID)
	require.True(t, strings.HasPrefix(nodeName, "node-maintenance-proof-") && strings.HasSuffix(nodeName, "-control-plane"))
	require.Contains(t, image, "@sha256:")
	ctx, cancel := context.WithTimeout(t.Context(), 12*time.Minute)
	defer cancel()
	cfg, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	require.NoError(t, err)
	hub, err := client.New(cfg, client.Options{Scheme: Scheme})
	require.NoError(t, err)
	node := &corev1.Node{}
	require.NoError(t, hub.Get(ctx, client.ObjectKey{Name: nodeName}, node))
	const namespace = "maintenance-proof-hub"
	require.NoError(t, hub.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}))
	raw, err := os.ReadFile(kubeconfig)
	require.NoError(t, err)
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "spoke-kubeconfig", Namespace: namespace}, Data: map[string][]byte{"value": raw}}
	require.NoError(t, hub.Create(ctx, secret))
	cc := &breakglassv1alpha1.ClusterConfig{ObjectMeta: metav1.ObjectMeta{Name: "maintenance-spoke", Namespace: namespace},
		Spec: breakglassv1alpha1.ClusterConfigSpec{KubeconfigSecretRef: &breakglassv1alpha1.SecretKeyReference{Name: secret.Name, Namespace: namespace}}}
	require.NoError(t, hub.Create(ctx, cc))
	cc.Status.Conditions = []metav1.Condition{{Type: "Ready", Status: metav1.ConditionTrue, Reason: "DisposableKindProof", LastTransitionTime: metav1.Now()}}
	cc.Status.ObservedGeneration = cc.Generation
	require.NoError(t, hub.Status().Update(ctx, cc))
	provider := cluster.NewClientProvider(hub, zap.NewNop().Sugar())
	controller := NewDebugSessionController(zap.NewExample().Sugar(), hub, provider).WithAPIReader(hub)
	sink := &maintenanceAuditCaptureSink{}
	manager := audit.NewManager(sink, audit.ManagerConfig{QueueSize: 8, WorkerCount: 1}, zap.NewNop())
	t.Cleanup(func() { _ = manager.Close() })
	controller.WithAuditManager(manager)
	api := NewDebugSessionAPIController(zap.NewNop().Sugar(), hub, provider, nil).WithAPIReader(hub)
	router := gin.New()
	approver := "approver@example.com"
	router.Use(func(c *gin.Context) {
		c.Set("legacy_identity_allowed", true)
		c.Set("username", approver)
		c.Set("email", approver)
		c.Set("groups", []string{})
		c.Next()
	})
	require.NoError(t, api.Register(router.Group("/debugSessions")))
	approve := func(session *breakglassv1alpha1.DebugSession, expectedStatus int) {
		t.Helper()
		request := httptest.NewRequest(http.MethodPost, "/debugSessions/"+session.Name+"/approve?namespace="+namespace, nil)
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		require.Equal(t, expectedStatus, response.Code, response.Body.String())
		require.NoError(t, hub.Get(ctx, client.ObjectKeyFromObject(session), session))
	}
	reconcile := func(session *breakglassv1alpha1.DebugSession) {
		t.Helper()
		_, err := controller.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(session)})
		require.NoError(t, err)
		require.NoError(t, hub.Get(ctx, client.ObjectKeyFromObject(session), session))
	}
	dockerJSON := func(args ...string) []map[string]interface{} {
		t.Helper()
		output, err := exec.CommandContext(ctx, "docker", append([]string{"exec", containerID}, args...)...).CombinedOutput()
		require.NoError(t, err, string(output))
		var records []map[string]interface{}
		require.NoError(t, json.Unmarshal(output, &records))
		return records
	}
	neighborMACs := func(device string) map[string]string {
		t.Helper()
		macs := map[string]string{}
		for _, entry := range dockerJSON("ip", "-j", "neigh", "show", "dev", device) {
			address, _ := entry["dst"].(string)
			macs[address], _ = entry["lladdr"].(string)
		}
		return macs
	}
	for _, tc := range []struct {
		name   string
		lane   string
		action string
		dryRun bool
		// focused cases prove one executor property without repeating the
		// contention, cancellation and expiry lifecycle of the full lanes.
		focused bool
		target  breakglassv1alpha1.NodeMaintenanceTarget
		kexec   *breakglassv1alpha1.NodeMaintenanceKexec
		// helperFails expects the fixed helper to reject its pinned inputs.
		helperFails bool
	}{
		// The preview runs first so the stale fixture entry is still present.
		{"preview", "neighbor", "neighbor-replace", true, true, breakglassv1alpha1.NodeMaintenanceTarget{Interface: "bg1551n", NeighborAddress: "192.0.2.2", EntryMAC: "02:00:00:00:00:02"}, nil, false},
		{"neighbor", "neighbor", "neighbor-replace", false, false, breakglassv1alpha1.NodeMaintenanceTarget{Interface: "bg1551n", NeighborAddress: "192.0.2.2", EntryMAC: "02:00:00:00:00:02"}, nil, false},
		{"vrf", "neighbor", "neighbor-replace", false, true, breakglassv1alpha1.NodeMaintenanceTarget{Interface: "bg1551v", VRF: "bg1551vrf", NeighborAddress: "198.51.100.2", EntryMAC: "02:00:00:00:00:02"}, nil, false},
		{"fdb", "fdb", "bridge-fdb-replace", false, false, breakglassv1alpha1.NodeMaintenanceTarget{Interface: "bg1551a", Bridge: "bg1551br", EntryMAC: "02:00:00:00:00:02", VLAN: ptr.To(int32(100))}, nil, false},
		// The single Kind Node is the control plane: validation reads the
		// pinned bundle without privilege, a wrong digest fails closed, and
		// a reboot request for that Node is refused before any cordon.
		{"kexec-validate", "kexec", breakglassv1alpha1.NodeMaintenanceActionKexecRecovery, true, true, breakglassv1alpha1.NodeMaintenanceTarget{}, kindKexec(""), false},
		{"kexec-digest-mismatch", "kexec", breakglassv1alpha1.NodeMaintenanceActionKexecRecovery, true, true, breakglassv1alpha1.NodeMaintenanceTarget{}, kindKexec(strings.Repeat("0", 64)), true},
		{"kexec-control-plane", "kexec", breakglassv1alpha1.NodeMaintenanceActionKexecRecovery, false, true, breakglassv1alpha1.NodeMaintenanceTarget{}, kindKexec(""), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if actionFilter != "" && actionFilter != tc.lane {
				t.Skip("the other exact repair action runs in its independent CI lane")
			}
			if actionFilter == "" && tc.lane == "kexec" {
				t.Skip("kexec cases need the recovery bundle staged by the kexec lane")
			}
			if tc.lane == "kexec" {
				require.NotNil(t, tc.kexec, "the kexec lane must stage NODE_MAINTENANCE_KIND_KEXEC_SHA256")
			}
			tc.target.TargetNode, tc.target.TargetNodeUID = nodeName, string(node.UID)
			maxDuration := "5m"
			if tc.kexec != nil {
				maxDuration = "10m"
			}
			template := &breakglassv1alpha1.DebugSessionTemplate{ObjectMeta: metav1.ObjectMeta{Name: "maintenance-" + tc.name},
				Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
					TargetNamespace: breakglassv1alpha1.NodeMaintenanceNamespace,
					Allowed:         &breakglassv1alpha1.DebugSessionAllowed{Users: []string{"requester@example.com"}, Clusters: []string{cc.Name}},
					Approvers:       &breakglassv1alpha1.DebugSessionApprovers{Users: []string{"approver@example.com"}},
					Constraints:     &breakglassv1alpha1.DebugSessionConstraints{MaxDuration: maxDuration, DefaultDuration: "5m"},
					NodeMaintenance: &breakglassv1alpha1.DebugSessionNodeMaintenance{Action: tc.action, Image: image, DryRun: tc.dryRun,
						AllowedTargets: []breakglassv1alpha1.NodeMaintenanceTarget{tc.target}, Kexec: tc.kexec},
				}}
			require.NoError(t, hub.Create(ctx, template))
			rejection := ""
			requestSession := func(target breakglassv1alpha1.NodeMaintenanceTarget, duration string, expectedStatus int, overrides ...func(*CreateDebugSessionRequest)) *breakglassv1alpha1.DebugSession {
				t.Helper()
				input := CreateDebugSessionRequest{
					TemplateRef: template.Name, Cluster: cc.Name, RequestedDuration: duration,
					Reason: "Disposable exact-tuple acceptance proof", NodeMaintenance: &target,
				}
				for _, override := range overrides {
					override(&input)
				}
				body, err := json.Marshal(input)
				require.NoError(t, err)
				previousActor := approver
				approver = "requester@example.com"
				request := httptest.NewRequest(http.MethodPost, "/debugSessions", bytes.NewReader(body))
				request.Header.Set("Content-Type", "application/json")
				response := httptest.NewRecorder()
				router.ServeHTTP(response, request)
				approver = previousActor
				require.Equal(t, expectedStatus, response.Code, response.Body.String())
				if expectedStatus != http.StatusCreated {
					rejection = response.Body.String()
					return nil
				}
				var created DebugSessionDetailResponse
				require.NoError(t, json.Unmarshal(response.Body.Bytes(), &created))
				require.NotEmpty(t, created.Name)
				return &created.DebugSession
			}
			createSession := func(name string, target breakglassv1alpha1.NodeMaintenanceTarget) *breakglassv1alpha1.DebugSession {
				t.Helper()
				duration := "5m"
				if name == "expiry" {
					duration = "60s"
				}
				session := requestSession(target, duration, http.StatusCreated)
				reconcile(session)
				return session
			}
			if tc.kexec != nil && !tc.dryRun {
				requestSession(tc.target, "5m", http.StatusBadRequest)
				require.Contains(t, rejection, "control-plane")
				live := &corev1.Node{}
				require.NoError(t, hub.Get(ctx, client.ObjectKey{Name: nodeName}, live))
				require.False(t, live.Spec.Unschedulable, "a refused kexec never cordons")
				require.NotContains(t, live.Annotations, maintenanceCordonAnnotation)
				return
			}
			if tc.focused {
				session := createSession("approved", tc.target)
				approver = "requester@example.com"
				approve(session, http.StatusForbidden)
				approver = "approver@example.com"
				approve(session, http.StatusOK)
				reconcile(session)
				require.Equal(t, breakglassv1alpha1.DebugSessionStateActive, session.Status.State, session.Status.Message)
				key := client.ObjectKey{Namespace: breakglassv1alpha1.NodeMaintenanceNamespace, Name: session.Status.NodeMaintenance.OperationID}
				pod := &corev1.Pod{}
				require.Eventually(t, func() bool {
					if err := hub.Get(ctx, key, pod); err != nil {
						return false
					}
					if tc.helperFails {
						return pod.Status.Phase == corev1.PodFailed
					}
					if pod.Status.Phase == corev1.PodFailed {
						t.Fatalf("fixed helper failed: %#v", pod.Status.ContainerStatuses)
					}
					return pod.Status.Phase == corev1.PodSucceeded
				}, 90*time.Second, time.Second)
				expected := "succeeded"
				if tc.kexec != nil {
					container := pod.Spec.Containers[0]
					require.Empty(t, container.SecurityContext.Capabilities.Add, "validation runs without SYS_BOOT")
					require.False(t, pod.Spec.HostPID)
					live := &corev1.Node{}
					require.NoError(t, hub.Get(ctx, client.ObjectKey{Name: nodeName}, live))
					require.False(t, live.Spec.Unschedulable, "validation never cordons")
					require.Equal(t, node.Status.NodeInfo.BootID, live.Status.NodeInfo.BootID, "validation never reboots")
					if tc.helperFails {
						expected = "failed"
					}
				} else if tc.dryRun {
					require.Empty(t, pod.Spec.Containers[0].SecurityContext.Capabilities.Add, "a preview runs without NET_ADMIN")
					require.Equal(t, "02:00:00:00:00:03", neighborMACs("bg1551n")["192.0.2.2"], "a preview never changes the entry")
				} else {
					macs := neighborMACs(tc.target.Interface)
					require.Equal(t, tc.target.EntryMAC, macs["198.51.100.2"], "exact VRF neighbour repaired")
					require.Equal(t, "02:00:00:00:00:09", macs["198.51.100.9"], "VRF decoy unchanged")
				}
				reconcile(session)
				require.Equal(t, expected, session.Status.NodeMaintenance.Result)
				require.True(t, session.Status.NodeMaintenance.ResultAudited)
				require.Eventually(t, func() bool {
					err := controller.cleanupResources(ctx, session)
					return err == nil && session.Status.NodeMaintenance.Released
				}, 90*time.Second, time.Second)
				return
			}
			mismatched := *tc.target.DeepCopy()
			mismatched.TargetNodeUID = "replacement-uid"
			requestSession(mismatched, "5m", http.StatusBadRequest)
			// Even a stale UID explicitly in the operator allowlist fails the live fence.
			template.Spec.NodeMaintenance.AllowedTargets = append(template.Spec.NodeMaintenance.AllowedTargets, mismatched)
			require.NoError(t, hub.Update(ctx, template))
			requestSession(mismatched, "5m", http.StatusBadRequest)
			requestSession(tc.target, "5m", http.StatusBadRequest, func(input *CreateDebugSessionRequest) {
				input.SelectedSchedulingOption = "discarded-generic-override"
			})
			unproven := &breakglassv1alpha1.DebugSession{
				ObjectMeta: metav1.ObjectMeta{Name: "unproven-" + tc.name, Namespace: namespace},
				Spec: breakglassv1alpha1.DebugSessionSpec{
					Cluster: cc.Name, TemplateRef: template.Name, RequestedBy: "requester@example.com",
					RequestedDuration: "5m", NodeMaintenance: &tc.target,
				},
			}
			require.NoError(t, hub.Create(ctx, unproven))
			reconcile(unproven)
			require.Equal(t, breakglassv1alpha1.DebugSessionStateFailed, unproven.Status.State)
			require.Nil(t, unproven.Status.NodeMaintenance)
			mismatched = *tc.target.DeepCopy()
			mismatched.EntryMAC = "02:00:00:00:00:99"
			requestSession(mismatched, "5m", http.StatusBadRequest)
			first := createSession("approved", tc.target)
			require.Equal(t, breakglassv1alpha1.DebugSessionStatePendingApproval, first.Status.State, first.Status.Message)
			require.Error(t, controller.deployMaintenance(ctx, first), "unapproved requests cannot create an executor")
			approver = "requester@example.com"
			approve(first, http.StatusForbidden)
			approver = "approver@example.com"
			approve(first, http.StatusOK)
			reconcile(first)
			require.Equal(t, breakglassv1alpha1.DebugSessionStateActive, first.Status.State, first.Status.Message)
			job := &batchv1.Job{}
			require.NoError(t, hub.Get(ctx, client.ObjectKey{
				Namespace: breakglassv1alpha1.NodeMaintenanceNamespace, Name: first.Status.NodeMaintenance.OperationID,
			}, job))
			require.Equal(t, maintenanceJobManager, *job.Spec.ManagedBy)
			require.True(t, matchesMaintenanceJob(first, job))
			second := createSession("concurrent", tc.target)
			approve(second, http.StatusOK)
			reconcile(second)
			require.Equal(t, breakglassv1alpha1.DebugSessionStatePendingApproval, second.Status.State)
			require.Contains(t, second.Status.Message, "exclusive")
			require.Empty(t, second.Status.NodeMaintenance.PodUID)
			require.Eventually(t, func() bool {
				pod := &corev1.Pod{}
				if err := hub.Get(ctx, client.ObjectKey{Namespace: breakglassv1alpha1.NodeMaintenanceNamespace, Name: first.Status.NodeMaintenance.OperationID}, pod); err != nil {
					return false
				}
				if pod.Status.Phase == corev1.PodFailed {
					t.Fatalf("fixed helper failed: %#v", pod.Status.ContainerStatuses)
				}
				return pod.Status.Phase == corev1.PodSucceeded
			}, 90*time.Second, time.Second)
			if tc.action == "neighbor-replace" {
				macs := neighborMACs("bg1551n")
				require.Equal(t, tc.target.EntryMAC, macs["192.0.2.2"])
				require.Equal(t, "02:00:00:00:00:09", macs["192.0.2.9"])
			} else {
				entries := dockerJSON("bridge", "-j", "fdb", "show", "br", "bg1551br")
				found, decoy := false, false
				for _, entry := range entries {
					found = found || entry["mac"] == tc.target.EntryMAC && entry["ifname"] == tc.target.Interface && entry["vlan"] == float64(100)
					decoy = decoy || entry["mac"] == "02:00:00:00:00:09" && entry["ifname"] == "bg1551b" && entry["vlan"] == float64(101)
				}
				require.True(t, found, "exact FDB tuple repaired: %#v", entries)
				require.True(t, decoy, "MAC/port/VLAN decoy unchanged: %#v", entries)
			}
			reconcile(first)
			require.Equal(t, "succeeded", first.Status.NodeMaintenance.Result)
			require.True(t, first.Status.NodeMaintenance.ResultAudited)
			require.Eventually(t, func() bool {
				err := controller.cleanupResources(ctx, first)
				return err == nil && first.Status.NodeMaintenance.Released
			}, 90*time.Second, time.Second)
			require.GreaterOrEqual(t, len(sink.Events()), 2)
			// Once cleanup proves absence, the already-approved contender can run.
			reconcile(second)
			require.Equal(t, breakglassv1alpha1.DebugSessionStateActive, second.Status.State)
			approver = "requester@example.com"
			request := httptest.NewRequest(http.MethodPost, "/debugSessions/"+second.Name+"/terminate?namespace="+namespace, nil)
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			require.Equal(t, http.StatusOK, response.Code, response.Body.String())
			require.NoError(t, hub.Get(ctx, client.ObjectKeyFromObject(second), second))
			approver = "approver@example.com"
			require.Eventually(t, func() bool {
				_, err := controller.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(second)})
				if err != nil || hub.Get(ctx, client.ObjectKeyFromObject(second), second) != nil {
					return false
				}
				return second.Status.NodeMaintenance.Released
			}, 90*time.Second, time.Second)
			require.True(t, apierrors.IsNotFound(hub.Get(ctx, client.ObjectKey{
				Namespace: breakglassv1alpha1.NodeMaintenanceNamespace, Name: second.Status.NodeMaintenance.OperationID,
			}, &batchv1.Job{})))
			// Expiry uses the real clock and original immutable execution deadline.
			expiring := createSession("expiry", tc.target)
			approve(expiring, http.StatusOK)
			reconcile(expiring)
			require.Equal(t, breakglassv1alpha1.DebugSessionStateActive, expiring.Status.State)
			time.Sleep(time.Until(expiring.Status.ExpiresAt.Time) + time.Millisecond)
			require.Eventually(t, func() bool {
				_, err := controller.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(expiring)})
				if err != nil || hub.Get(ctx, client.ObjectKeyFromObject(expiring), expiring) != nil {
					return false
				}
				return expiring.Status.NodeMaintenance.Released
			}, 90*time.Second, time.Second)
			require.Equal(t, breakglassv1alpha1.DebugSessionStateExpired, expiring.Status.State)
			require.True(t, expiring.Status.NodeMaintenance.ResultAudited)
			for _, object := range []client.Object{&corev1.Pod{}, &batchv1.Job{}} {
				require.True(t, apierrors.IsNotFound(hub.Get(ctx, client.ObjectKey{
					Namespace: breakglassv1alpha1.NodeMaintenanceNamespace, Name: expiring.Status.NodeMaintenance.OperationID,
				}, object)))
			}
			require.True(t, apierrors.IsNotFound(hub.Get(ctx, client.ObjectKey{
				Namespace: breakglassv1alpha1.NodeMaintenanceNamespace, Name: maintenanceIdentity(nodeName),
			}, &coordinationv1.Lease{})))
		})
	}
}

// kindKexec pins the disposable recovery bundle that the kexec lane stages on
// the Kind node. An explicit kernel digest replaces the staged one.
func kindKexec(kernel string) *breakglassv1alpha1.NodeMaintenanceKexec {
	digests := strings.Split(os.Getenv("NODE_MAINTENANCE_KIND_KEXEC_SHA256"), ",")
	if len(digests) != 3 {
		return nil
	}
	if kernel == "" {
		kernel = digests[0]
	}
	return &breakglassv1alpha1.NodeMaintenanceKexec{Profile: "kind-recovery", HostPath: "/var/lib/bg1551-recovery",
		KernelSHA256: kernel, InitrdSHA256: digests[1], CmdlineSHA256: digests[2], DrainTimeoutSeconds: 30}
}
