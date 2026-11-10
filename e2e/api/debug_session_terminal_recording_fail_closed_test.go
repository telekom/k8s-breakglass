// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
)

// TestDebugSessionTerminalRecordingFailsClosedWithoutTransport runs on a
// controller without an artifact backend. A template that requires terminal
// recording must never yield an active, unrecorded session, and the recorded
// terminal endpoint must refuse to stream.
func TestDebugSessionTerminalRecordingFailsClosedWithoutTransport(t *testing.T) {
	s := helpers.SetupTest(t, helpers.WithLongTimeout())
	ctx := s.Ctx
	requesterUser := helpers.TestUsers.SecurityRequester
	requester := s.TC.ClientForUser(requesterUser)
	template := &breakglassv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: helpers.GenerateUniqueName("recording-fail-closed")},
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			Mode: breakglassv1alpha1.DebugSessionModeWorkload, TargetNamespace: s.Namespace,
			Allowed:              &breakglassv1alpha1.DebugSessionAllowed{Clusters: []string{s.Cluster}, Groups: requesterUser.Groups},
			AllowedPodOperations: &breakglassv1alpha1.AllowedPodOperations{Exec: ptr.To(true)},
			Audit:                &breakglassv1alpha1.DebugSessionAuditConfig{EnableTerminalRecording: true},
			PodTemplateString: `apiVersion: v1
kind: Pod
metadata:
  name: recording-fail-closed
spec:
  containers:
  - name: shell
    image: busybox:latest
    imagePullPolicy: IfNotPresent
    command: ["sleep", "3600"]
`,
		},
	}
	require.NoError(t, s.CreateResource(template))
	session, err := requester.CreateDebugSession(ctx, t, helpers.DebugSessionRequest{TemplateRef: template.Name, Cluster: s.Cluster, RequestedDuration: "10m", Reason: "terminal recording fail-closed e2e"})
	if err != nil {
		require.Contains(t, strings.ToLower(err.Error()), "recording", "a rejected request must name the missing recording transport")
		return
	}
	s.Cleanup.Add(session)
	t.Cleanup(func() { _ = requester.TerminateDebugSession(context.Background(), t, session.Name) })
	failed := helpers.WaitForDebugSessionState(t, ctx, s.Client, session.Name, session.Namespace, breakglassv1alpha1.DebugSessionStateFailed, helpers.WaitForStateTimeout)
	require.Contains(t, failed.Status.Message, "terminal-byte transport is not configured")
	require.Empty(t, failed.Status.AllowedPods, "no debug workload may be reachable without recording")

	streamCtx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	result, err := requester.StreamRecordedTerminal(streamCtx, helpers.TerminalStreamRequest{
		Session: session.Name, SessionNamespace: session.Namespace, PodNamespace: s.Namespace, PodName: "recording-fail-closed", Command: []string{"sh"},
	})
	require.NoError(t, err)
	require.Equal(t, http.StatusServiceUnavailable, result.StatusCode, result.Body)
	status, body, err := requester.GetRaw(ctx, "/api/debugSessions/"+url.PathEscape(session.Name)+"/terminal?namespace="+url.QueryEscape(session.Namespace))
	require.NoError(t, err)
	require.Equal(t, http.StatusServiceUnavailable, status, string(body))
}
