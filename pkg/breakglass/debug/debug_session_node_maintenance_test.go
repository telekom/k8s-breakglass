// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"context"
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
	"go.uber.org/zap"
	batchv1 "k8s.io/api/batch/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
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
	require.Equal(t, maintenanceTuple("neighbor-replace", ds.Spec.NodeMaintenance), sink.Events()[0].Details["tuple"])
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
