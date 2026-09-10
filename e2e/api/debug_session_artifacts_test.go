//go:build e2e

package api

import (
	"crypto/sha256"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	batchv1 "k8s.io/api/batch/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
)

// TestDebugSessionArtifactCollectorE2E is the real Kind lane. The fixture
// supplies an already enabled template and a running target Pod because those
// are deployment concerns; every artifact operation below uses the public API.
func TestDebugSessionArtifactCollectorE2E(t *testing.T) {
	s := helpers.SetupTest(t, helpers.WithLongTimeout())
	template := os.Getenv("E2E_ARTIFACT_TEMPLATE")
	targetPod := os.Getenv("E2E_ARTIFACT_TARGET_POD")
	if template == "" || targetPod == "" {
		t.Skip("artifact fixture requires E2E_ARTIFACT_TEMPLATE and E2E_ARTIFACT_TARGET_POD")
	}
	namespace := s.Namespace
	ctx := s.Ctx
	tc := helpers.NewTestContext(t, ctx)
	requester := tc.RequesterClient()
	outsider := helpers.NewAPIClientWithAuth(tc.OIDCProvider().GetTokenForUser(t, ctx, helpers.TestUsers.UnauthorizedUser))

	session, err := requester.CreateDebugSession(ctx, t, helpers.DebugSessionRequest{TemplateRef: template, Cluster: s.Cluster, RequestedDuration: "30m", Reason: "diagnostic artifact E2E"})
	require.NoError(t, err)
	require.NotEmpty(t, session.Name)
	active := helpers.WaitForDebugSessionState(t, ctx, s.Client, session.Name, namespace, breakglassv1alpha1.DebugSessionStateActive, helpers.WaitForStateTimeout)
	require.NotEmpty(t, active.Status.ConnectionLease, "active session must have a real ConnectionLease")
	require.NotEmpty(t, active.Status.AllowedPods, "active session must publish an allowed target Pod")

	collect, err := requester.CollectDebugSessionArtifact(ctx, namespace, session.Name, helpers.DebugSessionArtifactRequest{Recipe: "system-summary.v1", PodNamespace: namespace, PodName: targetPod, DetailLevel: "basic"})
	require.NoError(t, err)
	require.NotEmpty(t, collect.ArtifactID)

	var job batchv1.Job
	require.Eventually(t, func() bool {
		jobs := &batchv1.JobList{}
		if s.Client.List(ctx, jobs, client.InNamespace(namespace), client.MatchingLabels{"breakglass.t-caas.telekom.com/artifact": collect.ArtifactID}) != nil || len(jobs.Items) != 1 {
			return false
		}
		job = jobs.Items[0]
		return job.Status.Succeeded == 1
	}, helpers.WaitForStateTimeout, time.Second)
	require.Equal(t, os.Getenv("E2E_ARTIFACT_IMAGE_DIGEST"), job.Spec.Template.Spec.Containers[len(job.Spec.Template.Spec.Containers)-1].Image)

	var metadata []helpers.DebugSessionArtifact
	require.Eventually(t, func() bool {
		metadata, err = requester.ListDebugSessionArtifacts(ctx, namespace, session.Name)
		return err == nil && len(metadata) == 1 && metadata[0].State == "Available"
	}, helpers.WaitForStateTimeout, time.Second)
	archive, err := requester.DownloadDebugSessionArtifact(ctx, namespace, session.Name, collect.ArtifactID)
	require.NoError(t, err)
	require.NotEmpty(t, archive)
	require.Equal(t, metadata[0].SHA256, fmt.Sprintf("%x", sha256.Sum256(archive)))

	_, err = outsider.ListDebugSessionArtifacts(ctx, namespace, session.Name)
	require.Error(t, err)
	_, err = outsider.DownloadDebugSessionArtifact(ctx, namespace, session.Name, collect.ArtifactID)
	require.Error(t, err)
	require.NoError(t, requester.TerminateDebugSession(ctx, t, session.Name))
	_, err = requester.DownloadDebugSessionArtifact(ctx, namespace, session.Name, collect.ArtifactID)
	require.Error(t, err)
}
