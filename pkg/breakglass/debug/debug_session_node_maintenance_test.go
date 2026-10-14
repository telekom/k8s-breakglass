// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/audit"
	"github.com/telekom/k8s-breakglass/pkg/breakglass"
	"go.uber.org/zap"
	batchv1 "k8s.io/api/batch/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

type maintenanceAuditCaptureSink struct {
	cleanupAuditCaptureSink
}

func (s *maintenanceAuditCaptureSink) SupportsSynchronousDelivery() bool { return true }

func TestNodeMaintenanceStrictTypedRequest(t *testing.T) {
	for _, body := range []string{
		`{"templateRef":"repair","cluster":"spoke","nodeMaintenance":{"targetNode":"node-a","command":"flush"}}`,
		`{"templateRef":"repair","cluster":"spoke","nodeMaintenance":{"targetNode":"node-a","vlan":"100"}}`,
		`{"templateRef":"repair","cluster":"spoke","nodeMaintenance":{"targetNode":"node-a","vlan":1.5}}`,
	} {
		var request CreateDebugSessionRequest
		require.Error(t, decodeDebugJSONStrict(strings.NewReader(body), &request))
	}
}

func TestNodeMaintenanceAPIRejectsRawOverridesBeforeNormalization(t *testing.T) {
	c, ds, _, _ := maintenanceFixture(t)
	template := &breakglassv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: "repair"}, Spec: *ds.Status.ResolvedTemplate,
	}
	require.NoError(t, c.client.Create(t.Context(), template))
	api := NewDebugSessionAPIController(zap.NewNop().Sugar(), c.client, nil, nil)
	router := gin.New()
	router.Use(func(ctx *gin.Context) {
		ctx.Set("legacy_identity_allowed", true)
		ctx.Set("username", "requester")
		ctx.Set("email", "requester")
		ctx.Next()
	})
	require.NoError(t, api.Register(router.Group("/debugSessions")))
	for _, override := range []string{
		`"selectedSchedulingOption":"ignored-option"`,
		`"nodeSelector":{"example.com/node":"other"}`,
		`"extraDeployValues":{"arbitrary":"command"}`,
		`"invitedParticipants":["other"]`,
	} {
		request := httptest.NewRequest(http.MethodPost, "/debugSessions",
			strings.NewReader(`{"templateRef":"repair","cluster":"spoke",`+override+`}`))
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		require.Equal(t, http.StatusBadRequest, response.Code, response.Body.String())
		require.Contains(t, response.Body.String(), "only typed tuple parameters")
	}
}

func TestNodeMaintenanceCleanupRecoversUnpersistedLeaseUID(t *testing.T) {
	c, ds, spoke, _ := maintenanceFixture(t)
	require.NoError(t, c.deployMaintenance(t.Context(), ds))
	pod := &corev1.Pod{}
	require.NoError(t, spoke.Get(t.Context(), client.ObjectKey{
		Name: ds.Status.NodeMaintenance.OperationID, Namespace: breakglassv1alpha1.NodeMaintenanceNamespace,
	}, pod))
	require.NoError(t, spoke.Delete(t.Context(), pod))
	lease := &coordinationv1.Lease{}
	key := client.ObjectKey{Name: maintenanceIdentity(ds.Spec.NodeMaintenance.TargetNode), Namespace: breakglassv1alpha1.NodeMaintenanceNamespace}
	require.NoError(t, spoke.Get(t.Context(), key, lease))
	lease.Finalizers = []string{"example.com/pending-cleanup"}
	require.NoError(t, spoke.Update(t.Context(), lease))
	require.NoError(t, c.patchMaintenanceStatus(t.Context(), ds, func(status *breakglassv1alpha1.NodeMaintenanceStatus) {
		status.LeaseUID = ""
	}))
	require.ErrorContains(t, c.cleanupMaintenance(t.Context(), ds), "Lease deletion is pending")
	require.False(t, ds.Status.NodeMaintenance.Released)
	require.NoError(t, spoke.Get(t.Context(), key, lease))
}

func maintenanceFixture(t *testing.T) (*DebugSessionController, *breakglassv1alpha1.DebugSession, client.Client, *maintenanceAuditCaptureSink) {
	t.Helper()
	controller, ds, _, _ := newDeploymentFenceFixture(t)
	target := breakglassv1alpha1.NodeMaintenanceTarget{TargetNode: "node-a", TargetNodeUID: "node-uid", Interface: "eth0", EntryMAC: "02:00:00:00:00:02", NeighborAddress: "192.0.2.2"}
	ds.Spec.NodeMaintenance = &target
	require.NoError(t, controller.client.Update(t.Context(), ds))
	profile := breakglassv1alpha1.DebugSessionTemplateSpec{
		TargetNamespace: breakglassv1alpha1.NodeMaintenanceNamespace,
		Approvers:       &breakglassv1alpha1.DebugSessionApprovers{Users: []string{"approver"}},
		Constraints:     &breakglassv1alpha1.DebugSessionConstraints{MaxDuration: "5m"},
		NodeMaintenance: &breakglassv1alpha1.DebugSessionNodeMaintenance{Action: "neighbor-replace",
			Image: "registry.example/node-maintenance@sha256:" + strings.Repeat("a", 64), AllowedTargets: []breakglassv1alpha1.NodeMaintenanceTarget{target}},
	}
	now := metav1.Now()
	ds.Status.ResolvedTemplate = &profile
	ds.Status.ResolvedTemplateIdentityCaptured = true
	ds.Status.AuthenticatedUserGroupsCaptured = true
	ds.Status.Approval = &breakglassv1alpha1.DebugSessionApproval{Required: true, ApprovedBy: "approver", ApprovedByIdentityProvider: "keycloak", ApprovedAt: &now}
	require.NoError(t, controller.client.Status().Update(t.Context(), ds))
	spoke := fake.NewClientBuilder().WithScheme(Scheme).
		WithObjects(&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-a", UID: "node-uid"},
			Status: corev1.NodeStatus{Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}}}},
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: breakglassv1alpha1.NodeMaintenanceNamespace, UID: "namespace-uid"}}).
		WithStatusSubresource(&corev1.Pod{}, &batchv1.Job{}, &corev1.Node{}).
		WithInterceptorFuncs(interceptor.Funcs{Create: func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			obj.SetUID(types.UID("uid-" + obj.GetName()))
			return cl.Create(ctx, obj, opts...)
		}}).Build()
	controller.targetClientFactory = func(_ *rest.Config) (client.Client, error) { return spoke, nil }
	sink := &maintenanceAuditCaptureSink{}
	manager := audit.NewManager(sink, audit.ManagerConfig{QueueSize: 8, WorkerCount: 1}, zap.NewNop())
	t.Cleanup(func() { _ = manager.Close() })
	controller.WithAuditManager(manager)
	return controller, ds, spoke, sink
}

func TestNodeMaintenanceApprovedExecutionAndCleanup(t *testing.T) {
	c, ds, spoke, sink := maintenanceFixture(t)
	require.NoError(t, c.deployMaintenance(t.Context(), ds))
	require.NotEmpty(t, ds.Status.NodeMaintenance.PodUID)
	require.NotEmpty(t, ds.Status.NodeMaintenance.JobUID)
	pod := &corev1.Pod{}
	key := client.ObjectKey{Name: ds.Status.NodeMaintenance.OperationID, Namespace: breakglassv1alpha1.NodeMaintenanceNamespace}
	require.NoError(t, spoke.Get(t.Context(), key, pod))
	require.True(t, matchesMaintenancePod(ds, pod))
	job := &batchv1.Job{}
	require.NoError(t, spoke.Get(t.Context(), key, job))
	require.Equal(t, maintenanceJobManager, *job.Spec.ManagedBy)
	require.True(t, matchesMaintenanceJob(ds, job))
	require.Equal(t, job.UID, metav1.GetControllerOf(pod).UID)
	require.Contains(t, pod.Spec.Containers[0].Args, "192.0.2.2")
	require.Len(t, sink.Events(), 1)
	require.Equal(t, maintenanceTuple(ds.Status.ResolvedTemplate.NodeMaintenance, ds.Spec.NodeMaintenance), sink.Events()[0].Details["tuple"])
	require.NoError(t, c.deployMaintenance(t.Context(), ds), "reconcile must reuse the same Pod, never replay")
	require.Len(t, sink.Events(), 1)
	pod.Status.Phase = corev1.PodSucceeded
	require.NoError(t, spoke.Status().Update(t.Context(), pod))
	_, err := c.handleMaintenanceActive(t.Context(), ds)
	require.NoError(t, err)
	require.Equal(t, breakglassv1alpha1.DebugSessionStateTerminated, ds.Status.State)
	require.Equal(t, "succeeded", ds.Status.NodeMaintenance.Result)
	require.True(t, ds.Status.NodeMaintenance.ResultAudited)
	require.Len(t, sink.Events(), 2)
	require.Equal(t, "succeeded", sink.Events()[1].Details["result"])
	require.NoError(t, c.cleanupMaintenance(t.Context(), ds))
	require.True(t, ds.Status.NodeMaintenance.Released)
	require.True(t, apierrors.IsNotFound(spoke.Get(t.Context(), key, &corev1.Pod{})))
	require.True(t, apierrors.IsNotFound(spoke.Get(t.Context(), key, &batchv1.Job{})))
	require.True(t, apierrors.IsNotFound(spoke.Get(t.Context(), client.ObjectKey{Namespace: key.Namespace, Name: maintenanceIdentity("node-a")}, &coordinationv1.Lease{})))
}

func TestNodeMaintenanceRejectsUnapprovedAndMismatchedRequests(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*breakglassv1alpha1.DebugSession)
	}{
		{"unapproved", func(ds *breakglassv1alpha1.DebugSession) { ds.Status.Approval.ApprovedAt = nil }},
		{"unproven requester", func(ds *breakglassv1alpha1.DebugSession) { ds.Status.AuthenticatedUserGroupsCaptured = false }},
		{"self approved", func(ds *breakglassv1alpha1.DebugSession) { ds.Status.Approval.ApprovedBy = ds.Spec.RequestedBy }},
		{"wrong provider", func(ds *breakglassv1alpha1.DebugSession) { ds.Status.Approval.ApprovedByIdentityProvider = "other" }},
		{"wrong tuple", func(ds *breakglassv1alpha1.DebugSession) { ds.Spec.NodeMaintenance.Interface = "other" }},
		{"replaced node uid", func(ds *breakglassv1alpha1.DebugSession) { ds.Spec.NodeMaintenance.TargetNodeUID = "replacement" }},
		{"arbitrary input", func(ds *breakglassv1alpha1.DebugSession) { ds.Spec.NodeSelector = map[string]string{"node": "*"} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, ds, spoke, sink := maintenanceFixture(t)
			tc.mutate(ds)
			require.Error(t, c.deployMaintenance(t.Context(), ds))
			var pods corev1.PodList
			require.NoError(t, spoke.List(t.Context(), &pods))
			require.Empty(t, pods.Items)
			require.Empty(t, sink.Events())
		})
	}
}

func TestNodeMaintenanceFinalFenceRejectsLiveChanges(t *testing.T) {
	for _, change := range []string{"approval", "node", "namespace"} {
		t.Run(change, func(t *testing.T) {
			c, ds, spoke, _ := maintenanceFixture(t)
			changed := false
			c.beforeDebugTargetWrite = func(_ string) {
				if changed {
					return
				}
				changed = true
				switch change {
				case "approval":
					live := &breakglassv1alpha1.DebugSession{}
					require.NoError(t, c.client.Get(t.Context(), client.ObjectKeyFromObject(ds), live))
					live.Status.Approval.ApprovedAt = nil
					require.NoError(t, c.client.Status().Update(t.Context(), live))
				case "node":
					node := &corev1.Node{}
					require.NoError(t, spoke.Get(t.Context(), client.ObjectKey{Name: "node-a"}, node))
					node.UID = "replacement"
					require.NoError(t, spoke.Update(t.Context(), node))
				case "namespace":
					namespace := &corev1.Namespace{}
					require.NoError(t, spoke.Get(t.Context(), client.ObjectKey{Name: breakglassv1alpha1.NodeMaintenanceNamespace}, namespace))
					namespace.UID = "replacement"
					require.NoError(t, spoke.Update(t.Context(), namespace))
				}
			}
			require.Error(t, c.deployMaintenance(t.Context(), ds))
			var pods corev1.PodList
			require.NoError(t, spoke.List(t.Context(), &pods))
			require.Empty(t, pods.Items)
		})
	}
}

func TestNodeMaintenanceLeaseSerializesProfilesAndNeverSteals(t *testing.T) {
	_, ds, spoke, _ := maintenanceFixture(t)
	ds.Status.NodeMaintenance = &breakglassv1alpha1.NodeMaintenanceStatus{OperationID: "session-one"}
	second := ds.DeepCopy()
	second.Status.NodeMaintenance.OperationID = "session-two"
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, request := range []*breakglassv1alpha1.DebugSession{ds, second} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := acquireMaintenanceLease(t.Context(), spoke, request, func() error { return nil })
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	successes, conflicts := 0, 0
	for err := range results {
		if err == nil {
			successes++
		} else if errors.Is(err, errNodeMaintenanceBusy) {
			conflicts++
		} else {
			t.Fatalf("unexpected result: %v", err)
		}
	}
	require.Equal(t, 1, successes)
	require.Equal(t, 1, conflicts)
	lease := &coordinationv1.Lease{}
	require.NoError(t, spoke.Get(t.Context(), client.ObjectKey{Namespace: breakglassv1alpha1.NodeMaintenanceNamespace, Name: maintenanceIdentity("node-a")}, lease))
	lease.Spec.LeaseDurationSeconds = ptr.To(int32(1))
	lease.Spec.RenewTime = &metav1.MicroTime{Time: time.Now().Add(-time.Hour)}
	require.NoError(t, spoke.Update(t.Context(), lease))
	loser := ds
	if *lease.Spec.HolderIdentity == ds.Status.NodeMaintenance.OperationID {
		loser = second
	}
	_, err := acquireMaintenanceLease(t.Context(), spoke, loser, func() error { return nil })
	require.ErrorIs(t, err, errNodeMaintenanceBusy)
}

func TestNodeMaintenanceUnknownCreateNeverReplaysOrUnlocks(t *testing.T) {
	c, ds, spoke, _ := maintenanceFixture(t)
	require.NoError(t, c.deployMaintenance(t.Context(), ds))
	pod := &corev1.Pod{}
	require.NoError(t, spoke.Get(t.Context(), client.ObjectKey{Name: ds.Status.NodeMaintenance.OperationID, Namespace: breakglassv1alpha1.NodeMaintenanceNamespace}, pod))
	require.NoError(t, spoke.Delete(t.Context(), pod))
	require.NoError(t, c.patchMaintenanceStatus(t.Context(), ds, func(status *breakglassv1alpha1.NodeMaintenanceStatus) { status.PodUID = "" }))
	require.Error(t, c.deployMaintenance(t.Context(), ds))
	require.ErrorContains(t, c.cleanupMaintenance(t.Context(), ds), "outcome is unknown")
	require.False(t, ds.Status.NodeMaintenance.Released)
	var pods corev1.PodList
	require.NoError(t, spoke.List(t.Context(), &pods))
	require.Empty(t, pods.Items)
	var leases coordinationv1.LeaseList
	require.NoError(t, spoke.List(t.Context(), &leases))
	require.Len(t, leases.Items, 1)
}

func TestNodeMaintenanceAuditFailureBlocksExecution(t *testing.T) {
	c, ds, spoke, _ := maintenanceFixture(t)
	c.WithAuditManager(nil)
	require.ErrorContains(t, c.deployMaintenance(t.Context(), ds), "durable audit")
	var pods corev1.PodList
	require.NoError(t, spoke.List(t.Context(), &pods))
	require.Empty(t, pods.Items)
	require.False(t, ds.Status.NodeMaintenance.CreateAttempted)
}

func TestNodeMaintenanceAdmissionCannotWidenExecutor(t *testing.T) {
	c, ds, _, _ := maintenanceFixture(t)
	require.NoError(t, c.deployMaintenance(t.Context(), ds))
	for _, mutate := range []func(*corev1.Pod){
		func(p *corev1.Pod) { p.Spec.HostPID = true },
		func(p *corev1.Pod) { p.Spec.Containers[0].Args = []string{"reboot"} },
		func(p *corev1.Pod) { p.Spec.Containers[0].SecurityContext.Privileged = ptr.To(true) },
		func(p *corev1.Pod) { p.Spec.Containers[0].EnvFrom = []corev1.EnvFromSource{{}} },
		func(p *corev1.Pod) { p.Spec.Containers = append(p.Spec.Containers, corev1.Container{Name: "sidecar"}) },
		func(p *corev1.Pod) { p.Spec.AutomountServiceAccountToken = ptr.To(true) },
	} {
		pod := maintenancePod(ds)
		pod.UID = types.UID(ds.Status.NodeMaintenance.PodUID)
		pod.OwnerReferences = maintenancePodOwners(ds)
		mutate(pod)
		require.False(t, matchesMaintenancePod(ds, pod))
	}
}

func TestNodeMaintenanceUnsupportedJobManagerCannotExecute(t *testing.T) {
	c, ds, spoke, _ := maintenanceFixture(t)
	target := interceptor.NewClient(spoke.(client.WithWatch), interceptor.Funcs{
		Create: func(ctx context.Context, cl client.WithWatch, object client.Object, options ...client.CreateOption) error {
			if job, ok := object.(*batchv1.Job); ok {
				require.True(t, *job.Spec.Suspend, "unsupported API servers must never start the built-in executor")
				job.Spec.ManagedBy = nil
			}
			return cl.Create(ctx, object, options...)
		},
	})
	c.targetClientFactory = func(_ *rest.Config) (client.Client, error) { return target, nil }
	require.ErrorContains(t, c.deployMaintenance(t.Context(), ds), "Job identity")
	var pods corev1.PodList
	require.NoError(t, spoke.List(t.Context(), &pods))
	require.Empty(t, pods.Items)
}

func TestNodeMaintenancePendingJobDeletionRetainsLease(t *testing.T) {
	c, ds, spoke, _ := maintenanceFixture(t)
	require.NoError(t, c.deployMaintenance(t.Context(), ds))
	key := client.ObjectKey{Namespace: breakglassv1alpha1.NodeMaintenanceNamespace, Name: ds.Status.NodeMaintenance.OperationID}
	job := &batchv1.Job{}
	require.NoError(t, spoke.Get(t.Context(), key, job))
	job.Finalizers = []string{"example.com/pending-job-cleanup"}
	require.NoError(t, spoke.Update(t.Context(), job))
	require.ErrorContains(t, c.cleanupMaintenance(t.Context(), ds), "Job deletion is pending")
	require.False(t, ds.Status.NodeMaintenance.Released)
	require.True(t, apierrors.IsNotFound(spoke.Get(t.Context(), key, &corev1.Pod{})))
	require.NoError(t, spoke.Get(t.Context(), client.ObjectKey{
		Namespace: key.Namespace, Name: maintenanceIdentity(ds.Spec.NodeMaintenance.TargetNode),
	}, &coordinationv1.Lease{}))
}

func TestNodeMaintenanceCannotOverrideApprovalBinding(t *testing.T) {
	_, ds, _, _ := maintenanceFixture(t)
	template := &breakglassv1alpha1.DebugSessionTemplate{Spec: *ds.Status.ResolvedTemplate}
	binding := &breakglassv1alpha1.DebugSessionClusterBinding{Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{Approvers: &breakglassv1alpha1.DebugSessionApprovers{}}}
	require.Error(t, maintenanceApprovers(template, binding))
	binding.Spec.Approvers.Users = []string{"approver"}
	binding.Spec.Approvers.AutoApproveFor = &breakglassv1alpha1.AutoApproveConfig{Groups: []string{"*"}}
	require.Error(t, maintenanceApprovers(template, binding))

	selfApproval := &breakglassv1alpha1.DebugSessionClusterBinding{Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
		BlockSelfApproval: ptr.To(false),
	}}
	require.ErrorContains(t, maintenanceApprovers(template, selfApproval), "blocked self-approval")
	selfApproval.Spec.BlockSelfApproval = ptr.To(true)
	require.NoError(t, maintenanceApprovers(template, selfApproval))
}

func TestNodeMaintenanceRejectsIdleTimeoutBeforeExecution(t *testing.T) {
	c, ds, spoke, _ := maintenanceFixture(t)
	template := &breakglassv1alpha1.DebugSessionTemplate{Spec: *ds.Status.ResolvedTemplate}
	binding := &breakglassv1alpha1.DebugSessionClusterBinding{Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
		Constraints: &breakglassv1alpha1.DebugSessionConstraints{IdleTimeout: "1m"},
	}}
	require.ErrorContains(t, maintenanceApprovers(template, binding), "idleTimeout")

	ds.Status.ResolvedTemplate.Constraints.IdleTimeout = "1m"
	require.NoError(t, c.client.Status().Update(t.Context(), ds))
	require.ErrorContains(t, c.deployMaintenance(t.Context(), ds), "idleTimeout")
	var pods corev1.PodList
	require.NoError(t, spoke.List(t.Context(), &pods))
	require.Empty(t, pods.Items, "an idle-bounded session must never start the hard-deadline executor")
	var jobs batchv1.JobList
	require.NoError(t, spoke.List(t.Context(), &jobs))
	require.Empty(t, jobs.Items)
}

func TestNodeMaintenanceCleanupRetainsReplacedResources(t *testing.T) {
	for _, kind := range []string{"Pod", "Job", "Lease"} {
		t.Run(kind, func(t *testing.T) {
			c, ds, spoke, _ := maintenanceFixture(t)
			require.NoError(t, c.deployMaintenance(t.Context(), ds))
			var object client.Object = &corev1.Pod{}
			key := client.ObjectKey{Namespace: breakglassv1alpha1.NodeMaintenanceNamespace, Name: ds.Status.NodeMaintenance.OperationID}
			if kind == "Lease" {
				object = &coordinationv1.Lease{}
				key.Name = maintenanceIdentity("node-a")
			} else if kind == "Job" {
				object = &batchv1.Job{}
			}
			require.NoError(t, spoke.Get(t.Context(), key, object))
			object.SetUID("replacement-resource")
			require.NoError(t, spoke.Update(t.Context(), object))
			require.Error(t, c.cleanupMaintenance(t.Context(), ds))
			require.False(t, ds.Status.NodeMaintenance.Released)
			require.NoError(t, spoke.Get(t.Context(), key, object))
			require.Equal(t, types.UID("replacement-resource"), object.GetUID())
		})
	}
}

func TestNodeMaintenanceExpiryIsNotSuccess(t *testing.T) {
	c, ds, _, _ := maintenanceFixture(t)
	expired := metav1.NewTime(time.Now().Add(5 * time.Second).Truncate(time.Second))
	ds.Status.ExpiresAt = &expired
	require.NoError(t, c.client.Status().Update(t.Context(), ds))
	require.NoError(t, c.deployMaintenance(t.Context(), ds))
	time.Sleep(time.Until(expired.Time) + time.Millisecond)
	_, err := c.handleMaintenanceActive(t.Context(), ds)
	require.NoError(t, err)
	require.Equal(t, breakglassv1alpha1.DebugSessionStateExpired, ds.Status.State)
	require.Equal(t, "interrupted", ds.Status.NodeMaintenance.Result)
}

type maintenanceCreateResponseClient struct {
	client.Client
	create bool
	job    bool
}

func (c maintenanceCreateResponseClient) Create(ctx context.Context, obj client.Object, options ...client.CreateOption) error {
	_, pod := obj.(*corev1.Pod)
	_, job := obj.(*batchv1.Job)
	if c.job && !job || !c.job && !pod {
		return c.Client.Create(ctx, obj, options...)
	}
	if c.create {
		if err := c.Client.Create(ctx, obj, options...); err != nil {
			return err
		}
	}
	return errors.New("ambiguous target API response")
}

func TestNodeMaintenanceAmbiguousJobCreateRecovery(t *testing.T) {
	for _, created := range []bool{true, false} {
		t.Run(strconv.FormatBool(created), func(t *testing.T) {
			c, ds, spoke, _ := maintenanceFixture(t)
			target := maintenanceCreateResponseClient{Client: spoke, create: created, job: true}
			c.targetClientFactory = func(_ *rest.Config) (client.Client, error) { return target, nil }
			err := c.deployMaintenance(t.Context(), ds)
			if created {
				require.NoError(t, err)
				require.NotEmpty(t, ds.Status.NodeMaintenance.JobUID)
				require.NoError(t, c.deployMaintenance(t.Context(), ds), "reuse the recovered Job")
			} else {
				require.Error(t, err)
				require.Empty(t, ds.Status.NodeMaintenance.JobUID)
				require.True(t, ds.Status.NodeMaintenance.JobCreateAttempted)
				require.False(t, ds.Status.NodeMaintenance.CreateAttempted)
				require.Error(t, c.deployMaintenance(t.Context(), ds), "missing Job must not be recreated")
				require.ErrorContains(t, c.cleanupMaintenance(t.Context(), ds), "Job create outcome is unknown")
				require.False(t, ds.Status.NodeMaintenance.Released)
				var jobs batchv1.JobList
				require.NoError(t, spoke.List(t.Context(), &jobs))
				require.Empty(t, jobs.Items)
			}
		})
	}
}

func TestNodeMaintenanceAmbiguousCreateRecovery(t *testing.T) {
	for _, created := range []bool{true, false} {
		t.Run(strconv.FormatBool(created), func(t *testing.T) {
			c, ds, spoke, _ := maintenanceFixture(t)
			target := maintenanceCreateResponseClient{Client: spoke, create: created}
			c.targetClientFactory = func(_ *rest.Config) (client.Client, error) { return target, nil }
			err := c.deployMaintenance(t.Context(), ds)
			if created {
				require.NoError(t, err)
				require.NotEmpty(t, ds.Status.NodeMaintenance.PodUID)
				require.NoError(t, c.deployMaintenance(t.Context(), ds), "reuse the recovered Pod")
			} else {
				require.Error(t, err)
				require.Empty(t, ds.Status.NodeMaintenance.PodUID)
				require.Error(t, c.deployMaintenance(t.Context(), ds), "missing outcome must not be recreated")
				require.ErrorContains(t, c.cleanupMaintenance(t.Context(), ds), "outcome is unknown")
				require.False(t, ds.Status.NodeMaintenance.Released)
			}
		})
	}
}

func TestNodeMaintenanceDeletionFinalizerCleansExactResources(t *testing.T) {
	c, ds, spoke, _ := maintenanceFixture(t)
	require.NoError(t, c.deployMaintenance(t.Context(), ds))
	require.True(t, hasMaintenanceFinalizer(ds))
	require.NoError(t, c.client.Delete(t.Context(), ds))
	_, err := c.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(ds)})
	require.NoError(t, err)
	require.True(t, apierrors.IsNotFound(c.client.Get(t.Context(), client.ObjectKeyFromObject(ds), &breakglassv1alpha1.DebugSession{})))
	var pods corev1.PodList
	var leases coordinationv1.LeaseList
	var jobs batchv1.JobList
	require.NoError(t, spoke.List(t.Context(), &pods))
	require.NoError(t, spoke.List(t.Context(), &leases))
	require.NoError(t, spoke.List(t.Context(), &jobs))
	require.Empty(t, pods.Items)
	require.Empty(t, leases.Items)
	require.Empty(t, jobs.Items)
}

func TestNodeMaintenanceResultAuditFailureRetainsLockAndPod(t *testing.T) {
	c, ds, spoke, _ := maintenanceFixture(t)
	require.NoError(t, c.deployMaintenance(t.Context(), ds))
	c.WithAuditManager(nil)
	require.Error(t, c.cleanupMaintenance(t.Context(), ds))
	require.False(t, ds.Status.NodeMaintenance.Released)
	var pods corev1.PodList
	var leases coordinationv1.LeaseList
	require.NoError(t, spoke.List(t.Context(), &pods))
	require.NoError(t, spoke.List(t.Context(), &leases))
	require.Len(t, pods.Items, 1)
	require.Len(t, leases.Items, 1)
}

func TestNodeMaintenanceCleanupRetainsNodeLossUncertainty(t *testing.T) {
	for _, change := range []string{"replacement", "unavailable"} {
		t.Run(change, func(t *testing.T) {
			c, ds, spoke, _ := maintenanceFixture(t)
			require.NoError(t, c.deployMaintenance(t.Context(), ds))
			node := &corev1.Node{}
			require.NoError(t, spoke.Get(t.Context(), client.ObjectKey{Name: "node-a"}, node))
			if change == "replacement" {
				node.UID = "replacement-node-uid"
				require.NoError(t, spoke.Update(t.Context(), node))
			} else {
				node.Status.Conditions[0].Status = corev1.ConditionUnknown
				require.NoError(t, spoke.Status().Update(t.Context(), node))
			}
			require.ErrorContains(t, c.cleanupMaintenance(t.Context(), ds), "retaining Lease")
			require.False(t, ds.Status.NodeMaintenance.Released)
			require.NoError(t, spoke.Get(t.Context(), client.ObjectKey{
				Namespace: breakglassv1alpha1.NodeMaintenanceNamespace, Name: maintenanceIdentity("node-a"),
			}, &coordinationv1.Lease{}))
		})
	}
}

func TestNodeMaintenanceCancelAuditsObservedTerminalResult(t *testing.T) {
	c, ds, spoke, sink := maintenanceFixture(t)
	require.NoError(t, c.deployMaintenance(t.Context(), ds))
	pod := &corev1.Pod{}
	key := client.ObjectKey{Namespace: breakglassv1alpha1.NodeMaintenanceNamespace, Name: ds.Status.NodeMaintenance.OperationID}
	require.NoError(t, spoke.Get(t.Context(), key, pod))
	pod.Status.Phase = corev1.PodFailed
	require.NoError(t, spoke.Status().Update(t.Context(), pod))
	require.NoError(t, c.cleanupMaintenance(t.Context(), ds))
	require.Equal(t, "failed", ds.Status.NodeMaintenance.Result)
	require.Equal(t, "failed", sink.Events()[1].Details["result"])
	require.Equal(t, string(pod.UID), sink.Events()[1].Details["podUID"])
}

func TestNodeMaintenanceCleanupAuditsRecoveredNonterminalPodUID(t *testing.T) {
	c, ds, spoke, sink := maintenanceFixture(t)
	require.NoError(t, c.deployMaintenance(t.Context(), ds))
	pod := &corev1.Pod{}
	key := client.ObjectKey{Namespace: breakglassv1alpha1.NodeMaintenanceNamespace, Name: ds.Status.NodeMaintenance.OperationID}
	require.NoError(t, spoke.Get(t.Context(), key, pod))
	require.NoError(t, c.patchMaintenanceStatus(t.Context(), ds, func(status *breakglassv1alpha1.NodeMaintenanceStatus) {
		status.PodUID = ""
	}))
	require.NoError(t, c.cleanupMaintenance(t.Context(), ds))
	require.Equal(t, "unknown", ds.Status.NodeMaintenance.Result)
	require.Equal(t, string(pod.UID), sink.Events()[1].Details["podUID"])
}

type maintenanceRevokingReader struct {
	client.Client
	revoke func()
}

func (c maintenanceRevokingReader) Get(ctx context.Context, key client.ObjectKey, object client.Object, options ...client.GetOption) error {
	err := c.Client.Get(ctx, key, object, options...)
	if _, pod := object.(*corev1.Pod); pod && err == nil {
		c.revoke()
	}
	return err
}

func TestNodeMaintenanceResultStatusRejectsRevokedConfiguration(t *testing.T) {
	c, ds, spoke, sink := maintenanceFixture(t)
	require.NoError(t, c.deployMaintenance(t.Context(), ds))
	key := client.ObjectKey{Namespace: breakglassv1alpha1.NodeMaintenanceNamespace, Name: ds.Status.NodeMaintenance.OperationID}
	pod := &corev1.Pod{}
	require.NoError(t, spoke.Get(t.Context(), key, pod))
	pod.Status.Phase = corev1.PodSucceeded
	require.NoError(t, spoke.Status().Update(t.Context(), pod))
	target := maintenanceRevokingReader{Client: spoke, revoke: func() {
		secret := &corev1.Secret{}
		require.NoError(t, c.client.Get(t.Context(), client.ObjectKey{Namespace: "default", Name: "spoke-kubeconfig"}, secret))
		secret.Data["value"] = []byte("revoked credentials")
		require.NoError(t, c.client.Update(t.Context(), secret))
	}}
	c.targetClientFactory = func(_ *rest.Config) (client.Client, error) { return target, nil }
	_, err := c.handleMaintenanceActive(t.Context(), ds)
	require.Error(t, err)
	job := &batchv1.Job{}
	require.NoError(t, spoke.Get(t.Context(), key, job))
	require.Empty(t, job.Status.Conditions)
	require.Empty(t, ds.Status.NodeMaintenance.Result)
	require.Len(t, sink.Events(), 1, "revoked target provenance must not emit a result receipt")
}

func TestNodeMaintenanceCleanupRejectsRevokedResultProvenance(t *testing.T) {
	c, ds, spoke, sink := maintenanceFixture(t)
	require.NoError(t, c.deployMaintenance(t.Context(), ds))
	target := maintenanceRevokingReader{Client: spoke, revoke: func() {
		secret := &corev1.Secret{}
		require.NoError(t, c.client.Get(t.Context(), client.ObjectKey{Namespace: "default", Name: "spoke-kubeconfig"}, secret))
		secret.Data["value"] = []byte("revoked credentials")
		require.NoError(t, c.client.Update(t.Context(), secret))
	}}
	c.targetClientFactory = func(_ *rest.Config) (client.Client, error) { return target, nil }
	require.Error(t, c.cleanupMaintenance(t.Context(), ds))
	require.Len(t, sink.Events(), 1, "cleanup must not receipt an outcome read with revoked target credentials")
	require.False(t, ds.Status.NodeMaintenance.Released)
	require.False(t, ds.Status.NodeMaintenance.ResultAudited)
}

func TestNodeMaintenanceTerminalFenceRejectsLiveChanges(t *testing.T) {
	for _, change := range []string{"approval", "cancel", "node", "namespace"} {
		t.Run(change, func(t *testing.T) {
			c, ds, spoke, sink := maintenanceFixture(t)
			require.NoError(t, c.deployMaintenance(t.Context(), ds))
			key := client.ObjectKey{Namespace: breakglassv1alpha1.NodeMaintenanceNamespace, Name: ds.Status.NodeMaintenance.OperationID}
			pod := &corev1.Pod{}
			require.NoError(t, spoke.Get(t.Context(), key, pod))
			pod.Status.Phase = corev1.PodSucceeded
			require.NoError(t, spoke.Status().Update(t.Context(), pod))
			c.beforeDebugTargetWrite = func(_ string) {
				switch change {
				case "approval", "cancel":
					live := &breakglassv1alpha1.DebugSession{}
					require.NoError(t, c.client.Get(t.Context(), client.ObjectKeyFromObject(ds), live))
					if change == "approval" {
						live.Status.Approval.ApprovedBy = "different-approver@example.com"
					} else {
						live.Status.State = breakglassv1alpha1.DebugSessionStateTerminated
					}
					require.NoError(t, c.client.Status().Update(t.Context(), live))
				case "node":
					node := &corev1.Node{}
					require.NoError(t, spoke.Get(t.Context(), client.ObjectKey{Name: "node-a"}, node))
					node.UID = "replacement"
					require.NoError(t, spoke.Update(t.Context(), node))
				case "namespace":
					namespace := &corev1.Namespace{}
					require.NoError(t, spoke.Get(t.Context(), client.ObjectKey{Name: breakglassv1alpha1.NodeMaintenanceNamespace}, namespace))
					namespace.UID = "replacement"
					require.NoError(t, spoke.Update(t.Context(), namespace))
				}
			}
			_, err := c.handleMaintenanceActive(t.Context(), ds)
			require.Error(t, err)
			job := &batchv1.Job{}
			require.NoError(t, spoke.Get(t.Context(), key, job))
			require.Empty(t, job.Status.Conditions)
			require.Len(t, sink.Events(), 1)
		})
	}
}

func TestNodeMaintenanceCleanupRetainsMismatchedLeaseNodeUID(t *testing.T) {
	for _, persisted := range []bool{false, true} {
		for _, nodeUID := range []string{"", "replacement-node"} {
			t.Run(fmt.Sprintf("persisted=%t/nodeUID=%s", persisted, nodeUID), func(t *testing.T) {
				c, ds, spoke, _ := maintenanceFixture(t)
				require.NoError(t, c.deployMaintenance(t.Context(), ds))
				key := client.ObjectKey{Name: maintenanceIdentity(ds.Spec.NodeMaintenance.TargetNode), Namespace: breakglassv1alpha1.NodeMaintenanceNamespace}
				lease := &coordinationv1.Lease{}
				require.NoError(t, spoke.Get(t.Context(), key, lease))
				lease.Annotations["breakglass.t-caas.telekom.com/node-uid"] = nodeUID
				require.NoError(t, spoke.Update(t.Context(), lease))
				if !persisted {
					require.NoError(t, c.patchMaintenanceStatus(t.Context(), ds, func(status *breakglassv1alpha1.NodeMaintenanceStatus) { status.LeaseUID = "" }))
				}

				require.ErrorContains(t, c.cleanupMaintenance(t.Context(), ds), "Lease Node identity")
				require.NoError(t, spoke.Get(t.Context(), key, lease))
				require.False(t, ds.Status.NodeMaintenance.Released)
			})
		}
	}
}

func TestNodeMaintenanceApprovalUsesImmutableBindingSnapshot(t *testing.T) {
	c, ds, _, _ := maintenanceFixture(t)
	binding := &breakglassv1alpha1.DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "maintenance-binding", Namespace: "default"},
		Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
			TemplateRef: &breakglassv1alpha1.TemplateReference{Name: "template"},
			Clusters:    []string{"spoke"},
			Approvers:   &breakglassv1alpha1.DebugSessionApprovers{Users: []string{"snapshot-approver"}, Groups: []string{"snapshot-approvers"}},
		},
	}
	raw, err := json.Marshal(binding.Spec)
	require.NoError(t, err)
	ds.Spec.BindingRef = &breakglassv1alpha1.BindingReference{Name: binding.Name, Namespace: binding.Namespace}
	ds.Status.ResolvedBindingSnapshotCaptured = true
	ds.Status.ResolvedBinding = &breakglassv1alpha1.ResolvedBindingRef{Name: binding.Name, Namespace: binding.Namespace}
	ds.Status.ResolvedBindingSpec = &apiextensionsv1.JSON{Raw: raw}
	require.True(t, breakglassv1alpha1.HasCompleteResolvedBindingSnapshot(ds.Status))
	binding.Spec.Approvers = &breakglassv1alpha1.DebugSessionApprovers{Users: []string{"new-approver"}, Groups: []string{"new-approvers"}}
	require.NoError(t, c.client.Create(t.Context(), binding))
	api := NewDebugSessionAPIController(zap.NewNop().Sugar(), c.client, nil, nil)
	for _, tc := range []struct {
		user   string
		groups []string
		want   bool
	}{
		{"snapshot-approver", nil, true},
		{"group-approver", []string{"snapshot-approvers"}, true},
		{"new-approver", nil, false},
		{"group-approver", []string{"new-approvers"}, false},
	} {
		require.Equal(t, tc.want, api.isIdentityAuthorizedToApprove(t.Context(), ds, debugSessionReadIdentity{
			username: tc.user, groups: tc.groups, provider: ds.Spec.IdentityProviderName, issuer: ds.Spec.IdentityProviderIssuer, legacyAllowed: true,
		}))
	}
	require.NoError(t, c.client.Delete(t.Context(), binding))
	require.True(t, api.isIdentityAuthorizedToApprove(t.Context(), ds, debugSessionReadIdentity{
		username: "snapshot-approver", provider: ds.Spec.IdentityProviderName, issuer: ds.Spec.IdentityProviderIssuer, legacyAllowed: true,
	}), "the immutable approval snapshot is not replaced by a live binding read")
	ds.Status.ResolvedBindingSpec = nil
	require.False(t, api.isIdentityAuthorizedToApprove(t.Context(), ds, debugSessionReadIdentity{
		username: "snapshot-approver", provider: ds.Spec.IdentityProviderName, issuer: ds.Spec.IdentityProviderIssuer, legacyAllowed: true,
	}))
}

func TestNodeMaintenanceCancelledContenderHasNoExecutionReceipt(t *testing.T) {
	c, first, spoke, sink := maintenanceFixture(t)
	require.NoError(t, c.deployMaintenance(t.Context(), first))
	second := first.DeepCopy()
	second.Name = "maintenance-contender"
	second.UID = "contender-uid"
	second.ResourceVersion = ""
	second.Status.NodeMaintenance = nil
	require.NoError(t, c.client.Create(t.Context(), second))
	require.NoError(t, c.client.Status().Update(t.Context(), second))
	require.ErrorIs(t, c.deployMaintenance(t.Context(), second), errNodeMaintenanceBusy)
	require.NoError(t, c.cleanupMaintenance(t.Context(), second))
	require.True(t, second.Status.NodeMaintenance.Released)
	require.Empty(t, second.Status.NodeMaintenance.Result)
	require.False(t, second.Status.NodeMaintenance.ResultAudited)
	require.Len(t, sink.Events(), 1, "contenders never had execution intent and must not emit executor results")
	require.NoError(t, spoke.Get(t.Context(), client.ObjectKey{
		Name: maintenanceIdentity(first.Spec.NodeMaintenance.TargetNode), Namespace: breakglassv1alpha1.NodeMaintenanceNamespace,
	}, &coordinationv1.Lease{}))
}

func TestNodeMaintenanceReplacedJobCannotBeReceipted(t *testing.T) {
	c, ds, spoke, sink := maintenanceFixture(t)
	require.NoError(t, c.deployMaintenance(t.Context(), ds))
	job := &batchv1.Job{}
	key := client.ObjectKey{Name: ds.Status.NodeMaintenance.OperationID, Namespace: breakglassv1alpha1.NodeMaintenanceNamespace}
	require.NoError(t, spoke.Get(t.Context(), key, job))
	job.UID = "replacement-job"
	require.NoError(t, spoke.Update(t.Context(), job))
	require.ErrorContains(t, c.cleanupMaintenance(t.Context(), ds), "Job identity")
	require.Len(t, sink.Events(), 1)
	require.Empty(t, ds.Status.NodeMaintenance.Result)
	require.False(t, ds.Status.NodeMaintenance.Released)
}

func TestNodeMaintenanceDeletionReleasesHubConnectionLease(t *testing.T) {
	for _, tc := range []struct {
		name        string
		leaseAbsent bool
	}{
		{name: "lease present"},
		{name: "lease already removed", leaseAbsent: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, ds, spoke, _ := maintenanceFixture(t)
			lease, err := c.connectionLeases.AcquireForSession(t.Context(), ds, "cluster-uid")
			require.NoError(t, err)
			ds.Status.ConnectionLease = &lease
			require.NoError(t, breakglass.ApplyDebugSessionStatus(t.Context(), c.client, ds))
			require.NoError(t, c.deployMaintenance(t.Context(), ds))
			require.True(t, hasMaintenanceFinalizer(ds))
			leaseKey := client.ObjectKey{Namespace: lease.Namespace, Name: lease.Name}
			if tc.leaseAbsent {
				require.NoError(t, c.client.Delete(t.Context(), &coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Namespace: lease.Namespace, Name: lease.Name}}))
			} else {
				require.NoError(t, c.client.Get(t.Context(), leaseKey, &coordinationv1.Lease{}))
			}
			require.NoError(t, c.client.Delete(t.Context(), ds))

			_, err = c.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(ds)})
			require.NoError(t, err)

			require.True(t, apierrors.IsNotFound(c.client.Get(t.Context(), client.ObjectKeyFromObject(ds), &breakglassv1alpha1.DebugSession{})),
				"finalizer must be removed once maintenance cleanup and lease release succeed")
			require.True(t, apierrors.IsNotFound(c.client.Get(t.Context(), leaseKey, &coordinationv1.Lease{})),
				"deleting a maintenance session must release its hub connection lease")
			podKey := client.ObjectKey{Name: ds.Status.NodeMaintenance.OperationID, Namespace: breakglassv1alpha1.NodeMaintenanceNamespace}
			require.True(t, apierrors.IsNotFound(spoke.Get(t.Context(), podKey, &corev1.Pod{})))
			require.True(t, apierrors.IsNotFound(spoke.Get(t.Context(), client.ObjectKey{Namespace: podKey.Namespace, Name: maintenanceIdentity("node-a")}, &coordinationv1.Lease{})))
		})
	}
}

func TestNodeMaintenanceDeletionDuringActivationReleasesHubConnectionLease(t *testing.T) {
	c, ds, spoke, _ := maintenanceFixture(t)
	ds.Status.State = breakglassv1alpha1.DebugSessionStatePendingApproval
	ds.Status.ResolvedBindingSnapshotCaptured = true
	ds.Status.ResolvedTemplateVariablePolicy = []breakglassv1alpha1.ExtraDeployVariable{}
	require.NoError(t, c.client.Status().Update(t.Context(), ds))
	template := &breakglassv1alpha1.DebugSessionTemplate{ObjectMeta: metav1.ObjectMeta{Name: ds.Spec.TemplateRef}, Spec: *ds.Status.ResolvedTemplate.DeepCopy()}
	key := client.ObjectKeyFromObject(ds)
	var leaseKey *client.ObjectKey
	// The requester deletes the session exactly while activation creates the
	// hub connection Lease, before any maintenance executor exists.
	c.client = interceptor.NewClient(c.client.(client.WithWatch), interceptor.Funcs{Create: func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
		if _, ok := obj.(*coordinationv1.Lease); ok && leaseKey == nil {
			leaseKey = &client.ObjectKey{Namespace: obj.GetNamespace(), Name: obj.GetName()}
			live := &breakglassv1alpha1.DebugSession{}
			require.NoError(t, cl.Get(ctx, key, live))
			require.True(t, hasMaintenanceFinalizer(live), "cleanup responsibility must be durable before the hub Lease exists")
			require.NoError(t, cl.Delete(ctx, live))
		}
		return cl.Create(ctx, obj, opts...)
	}})
	c.connectionLeases = NewConnectionLeaseService(c.client)

	_, err := c.activateSession(t.Context(), ds, template, nil)
	require.NotNil(t, leaseKey, "activation must acquire the hub connection Lease")
	require.True(t, apierrors.IsConflict(err), "the deletion must prevent recording the Lease in status, got %v", err)
	foreign := &coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Namespace: leaseKey.Namespace, Name: connectionSessionLeasePrefix + "other",
		Annotations: map[string]string{connectionLeaseSessionAnnotation: "other-session-uid"}},
		Spec: coordinationv1.LeaseSpec{HolderIdentity: ptr.To("other-session-uid")}}
	require.NoError(t, c.client.Create(t.Context(), foreign))
	for i := 0; i < 3; i++ {
		_, err = c.Reconcile(t.Context(), ctrl.Request{NamespacedName: key})
		require.NoError(t, err)
	}

	require.True(t, apierrors.IsNotFound(c.client.Get(t.Context(), key, &breakglassv1alpha1.DebugSession{})))
	require.True(t, apierrors.IsNotFound(c.client.Get(t.Context(), *leaseKey, &coordinationv1.Lease{})),
		"a deletion racing activation must not orphan the hub connection Lease")
	require.NoError(t, c.client.Get(t.Context(), client.ObjectKeyFromObject(foreign), &coordinationv1.Lease{}), "another session's Lease must survive")
	require.True(t, apierrors.IsNotFound(spoke.Get(t.Context(), client.ObjectKey{Namespace: breakglassv1alpha1.NodeMaintenanceNamespace, Name: maintenanceIdentity("node-a")}, &coordinationv1.Lease{})))
}

func TestNodeMaintenancePendingValidationSeparatesTargetOutageFromInvalidRequest(t *testing.T) {
	for _, tc := range []struct {
		name        string
		setup       func(*DebugSessionController, client.Client)
		unavailable bool
		status      int
	}{
		{name: "matching node", status: http.StatusOK},
		{name: "node absent", setup: func(_ *DebugSessionController, spoke client.Client) {
			require.NoError(t, spoke.Delete(t.Context(), &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-a"}}))
		}, status: http.StatusBadRequest},
		{name: "node uid mismatch", setup: func(_ *DebugSessionController, spoke client.Client) {
			node := &corev1.Node{}
			require.NoError(t, spoke.Get(t.Context(), client.ObjectKey{Name: "node-a"}, node))
			require.NoError(t, spoke.Delete(t.Context(), node))
			require.NoError(t, spoke.Create(t.Context(), &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-a", UID: "replacement"}}))
		}, status: http.StatusBadRequest},
		{name: "target client unavailable", setup: func(c *DebugSessionController, _ client.Client) {
			c.targetClientFactory = func(_ *rest.Config) (client.Client, error) { return nil, errors.New("dial target: connection refused") }
		}, unavailable: true, status: http.StatusServiceUnavailable},
		{name: "node read timeout", setup: func(c *DebugSessionController, spoke client.Client) {
			c.targetClientFactory = func(_ *rest.Config) (client.Client, error) {
				return interceptor.NewClient(spoke.(client.WithWatch), interceptor.Funcs{Get: func(ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
					if _, ok := obj.(*corev1.Node); ok {
						return apierrors.NewTimeoutError("node read timed out", 1)
					}
					return cl.Get(ctx, key, obj, opts...)
				}}), nil
			}
		}, unavailable: true, status: http.StatusServiceUnavailable},
		{name: "node read forbidden", setup: func(c *DebugSessionController, spoke client.Client) {
			c.targetClientFactory = func(_ *rest.Config) (client.Client, error) {
				return interceptor.NewClient(spoke.(client.WithWatch), interceptor.Funcs{Get: func(ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
					if _, ok := obj.(*corev1.Node); ok {
						return apierrors.NewForbidden(corev1.Resource("nodes"), key.Name, errors.New("rbac"))
					}
					return cl.Get(ctx, key, obj, opts...)
				}}), nil
			}
		}, unavailable: true, status: http.StatusServiceUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, ds, spoke, _ := maintenanceFixture(t)
			if tc.setup != nil {
				tc.setup(c, spoke)
			}
			template := &breakglassv1alpha1.DebugSessionTemplate{Spec: *ds.Status.ResolvedTemplate.DeepCopy()}
			err := c.validateMaintenancePending(t.Context(), ds, template, nil)
			if tc.status == http.StatusOK {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			require.Equal(t, tc.unavailable, errors.Is(err, errMaintenanceTargetUnavailable), err.Error())

			recorder := httptest.NewRecorder()
			ginCtx, _ := gin.CreateTestContext(recorder)
			respondMaintenanceValidationError(ginCtx, zap.NewNop().Sugar(), err)
			require.Equal(t, tc.status, recorder.Code, recorder.Body.String())
			if tc.unavailable {
				require.NotContains(t, recorder.Body.String(), "connection refused", "target internals must not leak to the requester")
			}
		})
	}
}

func TestNodeMaintenancePreCreateFailureDoesNotRecordUnknownOutcome(t *testing.T) {
	for _, stage := range []string{"job", "pod"} {
		for _, followUp := range []string{"retry", "cleanup"} {
			t.Run(stage+"/"+followUp, func(t *testing.T) {
				c, ds, spoke, _ := maintenanceFixture(t)
				setNodeUID := func(uid types.UID) {
					node := &corev1.Node{}
					require.NoError(t, spoke.Get(t.Context(), client.ObjectKey{Name: "node-a"}, node))
					node.UID = uid
					require.NoError(t, spoke.Update(t.Context(), node))
				}
				failed := false
				c.beforeDebugTargetWrite = func(_ string) {
					if failed {
						return
					}
					live := &breakglassv1alpha1.DebugSession{}
					require.NoError(t, c.client.Get(t.Context(), client.ObjectKeyFromObject(ds), live))
					status := live.Status.NodeMaintenance
					if status == nil {
						return
					}
					if (stage == "job" && status.JobCreateAttempted && status.JobUID == "") ||
						(stage == "pod" && status.CreateAttempted && status.PodUID == "") {
						failed = true
						setNodeUID("replacement")
					}
				}
				require.Error(t, c.deployMaintenance(t.Context(), ds))
				require.True(t, failed, "the final fence must run after the create marker is persisted")
				c.beforeDebugTargetWrite = nil

				live := &breakglassv1alpha1.DebugSession{}
				require.NoError(t, c.client.Get(t.Context(), client.ObjectKeyFromObject(ds), live))
				key := client.ObjectKey{Namespace: breakglassv1alpha1.NodeMaintenanceNamespace, Name: ds.Status.NodeMaintenance.OperationID}
				require.True(t, apierrors.IsNotFound(spoke.Get(t.Context(), key, &corev1.Pod{})))
				require.False(t, live.Status.NodeMaintenance.CreateAttempted, "a proven pre-create failure must not record an unknown Pod outcome")
				if stage == "job" {
					require.True(t, apierrors.IsNotFound(spoke.Get(t.Context(), key, &batchv1.Job{})))
					require.False(t, live.Status.NodeMaintenance.JobCreateAttempted, "a proven pre-create failure must not record an unknown Job outcome")
				} else {
					require.True(t, live.Status.NodeMaintenance.JobCreateAttempted, "the created Job keeps its marker")
					require.NotEmpty(t, live.Status.NodeMaintenance.JobUID)
				}

				setNodeUID("node-uid")
				ds = live
				leaseKey := client.ObjectKey{Namespace: breakglassv1alpha1.NodeMaintenanceNamespace, Name: maintenanceIdentity("node-a")}
				if followUp == "retry" {
					require.NoError(t, c.deployMaintenance(t.Context(), ds))
					require.NoError(t, spoke.Get(t.Context(), key, &corev1.Pod{}))
					require.NotEmpty(t, ds.Status.NodeMaintenance.PodUID)
					return
				}
				require.NoError(t, c.cleanupMaintenance(t.Context(), ds))
				require.True(t, ds.Status.NodeMaintenance.Released)
				require.True(t, apierrors.IsNotFound(spoke.Get(t.Context(), leaseKey, &coordinationv1.Lease{})),
					"cleanup must release the node Lease after a proven pre-create failure")
			})
		}
	}
}
