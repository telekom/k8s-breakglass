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
	"k8s.io/apimachinery/pkg/api/meta"
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
	ensureAuditPipeline(t, ctx, s)
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
		// The reconciler can fail the request before the API finishes its
		// admission wait; the created session must then be Failed, never Active.
		var sessions breakglassv1alpha1.DebugSessionList
		require.NoError(t, s.Client.List(ctx, &sessions))
		session = nil
		for i := range sessions.Items {
			if sessions.Items[i].Spec.TemplateRef == template.Name {
				session = &sessions.Items[i]
			}
		}
		if session == nil {
			require.Contains(t, strings.ToLower(err.Error()), "recording", "a rejected request must name the missing recording transport")
			return
		}
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

// ensureAuditPipeline makes sure an enabled, Ready AuditConfig with a sink
// that confirms delivery (webhook) exists: recorded streams deliver their audit
// events synchronously and refuse to start without one. Log sinks give no
// delivery receipt and are not sufficient.
func ensureAuditPipeline(t *testing.T, ctx context.Context, s *helpers.TestSetup) {
	t.Helper()
	ready := func() bool {
		var configs breakglassv1alpha1.AuditConfigList
		if s.Client.List(ctx, &configs) != nil {
			return false
		}
		for _, config := range configs.Items {
			if !config.Spec.Enabled || !meta.IsStatusConditionTrue(config.Status.Conditions, "Ready") {
				continue
			}
			for _, sink := range config.Spec.Sinks {
				if sink.Type == breakglassv1alpha1.AuditSinkTypeWebhook || sink.Type == breakglassv1alpha1.AuditSinkTypeKafka {
					return true
				}
			}
		}
		return false
	}
	if ready() {
		return
	}
	config := &breakglassv1alpha1.AuditConfig{
		ObjectMeta: metav1.ObjectMeta{Name: helpers.GenerateUniqueName("terminal-recording-audit")},
		Spec: breakglassv1alpha1.AuditConfigSpec{Enabled: true, Sinks: []breakglassv1alpha1.AuditSinkConfig{{
			Name: "recording-webhook", Type: breakglassv1alpha1.AuditSinkTypeWebhook,
			Webhook: &breakglassv1alpha1.WebhookSinkSpec{URL: "http://breakglass-audit-webhook-receiver.breakglass-system.svc.cluster.local:80/audit", TimeoutSeconds: 10},
		}}},
	}
	require.NoError(t, s.CreateResource(config))
	require.Eventually(t, ready, helpers.WaitForStateTimeout, time.Second, "an AuditConfig with a confirming sink must become Ready")
}
