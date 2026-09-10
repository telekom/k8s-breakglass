// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestTerminalAuthorityRejectsLiveRevocation(t *testing.T) {
	for _, scenario := range []string{"unchanged", "terminated", "deleted", "participant left", "different issuer", "different target", "expired", "revoked during target lookup"} {
		t.Run(scenario, func(t *testing.T) {
			expiry := metav1.NewTime(time.Now().Add(time.Hour))
			allow := true
			session := &breakglassv1alpha1.DebugSession{ObjectMeta: metav1.ObjectMeta{Name: "session", Namespace: "hub", UID: types.UID("session-uid")},
				Status: breakglassv1alpha1.DebugSessionStatus{State: breakglassv1alpha1.DebugSessionStateActive, ExpiresAt: &expiry,
					ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{Audit: &breakglassv1alpha1.DebugSessionAuditConfig{EnableTerminalRecording: true}},
					Participants:     []breakglassv1alpha1.DebugSessionParticipant{{User: "alice", IdentityProviderName: "provider", IdentityProviderIssuer: "issuer", Role: breakglassv1alpha1.ParticipantRoleParticipant}},
					AllowedPods:      []breakglassv1alpha1.AllowedPodRef{{Name: "pod", Namespace: "target", UID: "pod-uid"}}, AllowedPodOperations: &breakglassv1alpha1.AllowedPodOperations{Exec: &allow}}}
			hub := fake.NewClientBuilder().WithScheme(Scheme).WithObjects(session).WithStatusSubresource(session).Build()
			controller := NewDebugSessionAPIController(zap.NewNop().Sugar(), hub, nil, nil).WithAPIReader(hub)
			identity := debugSessionReadIdentity{username: "alice", provider: "provider", issuer: "issuer"}
			authorize := controller.terminalRecordingAuthority(session, identity, "target", "pod", "pod-uid", "exec", func(ctx context.Context) error {
				if scenario == "revoked during target lookup" {
					changed := session.DeepCopy()
					require.NoError(t, hub.Get(ctx, ctrlclient.ObjectKeyFromObject(session), changed))
					changed.Status.State = breakglassv1alpha1.DebugSessionStateTerminated
					require.NoError(t, hub.Status().Update(ctx, changed))
				}
				return nil
			})
			live := session.DeepCopy()
			require.NoError(t, hub.Get(context.Background(), ctrlclient.ObjectKeyFromObject(session), live))
			switch scenario {
			case "terminated":
				live.Status.State = breakglassv1alpha1.DebugSessionStateTerminated
			case "participant left":
				now := metav1.Now()
				live.Status.Participants[0].LeftAt = &now
			case "different issuer":
				live.Status.Participants[0].IdentityProviderIssuer = "other"
			case "different target":
				live.Status.AllowedPods[0].UID = "replacement"
			case "expired":
				expired := metav1.NewTime(time.Now().Add(-time.Second))
				live.Status.ExpiresAt = &expired
			}
			require.NoError(t, hub.Status().Update(context.Background(), live))
			if scenario == "deleted" {
				require.NoError(t, hub.Delete(context.Background(), live))
			}
			err := authorize(context.Background())
			if scenario == "unchanged" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}

func TestRecordingReaderDropsBytesWhenAuthorizationChangesDuringRead(t *testing.T) {
	calls := 0
	authorize := func(context.Context) error {
		calls++
		if calls > 1 {
			return context.Canceled
		}
		return nil
	}
	reader := authorizedRecordingReader{ctx: context.Background(), reader: strings.NewReader("private evidence"), authorize: authorize}
	bytes, err := io.ReadAll(reader)
	require.Error(t, err)
	require.Empty(t, bytes)
}

func TestEmptyTerminalProducesBoundedEvidence(t *testing.T) {
	recording, err := NewTerminalRecorder(terminalRecordingFrameHeaderSize).Finalize()
	require.NoError(t, err)
	require.Len(t, recording.Bytes, terminalRecordingFrameHeaderSize)
	require.EqualValues(t, 1, recording.Frames)
	require.Equal(t, byte(1), recording.Bytes[0])
	require.NotEmpty(t, recording.SHA256)
	_, err = NewTerminalRecorder(terminalRecordingFrameHeaderSize - 1).Finalize()
	require.Error(t, err)
}
