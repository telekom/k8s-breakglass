// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/telekom/k8s-breakglass/pkg/artifacts/backend"
)

type fakeRecoverer struct {
	published backend.PublicRecord
	recovered bool
	err       error
	grace     time.Duration
}

func (f *fakeRecoverer) RecoverAbandonedRecording(_ context.Context, _ backend.Record, grace time.Duration) (backend.PublicRecord, bool, error) {
	f.grace = grace
	return f.published, f.recovered, f.err
}

func TestRecoverAbandonedRecordingReportsOutcomes(t *testing.T) {
	type call struct {
		published backend.PublicRecord
		err       error
	}
	var calls []call
	reconciler := &Reconciler{RecordingRecovered: func(_ context.Context, _ backend.Record, published backend.PublicRecord, err error) {
		calls = append(calls, call{published, err})
	}}
	ctx := context.Background()
	record := backend.Record{ArtifactUID: "uid-1"}

	idle := &fakeRecoverer{}
	reconciler.recoverAbandonedRecording(ctx, idle, record)
	require.Empty(t, calls, "nothing recovered, nothing reported")
	require.Equal(t, terminalRecordingRecoveryGrace, idle.grace)

	done := &fakeRecoverer{recovered: true, published: backend.PublicRecord{SHA256: "abc"}}
	reconciler.recoverAbandonedRecording(ctx, done, record)
	require.Equal(t, []call{{published: backend.PublicRecord{SHA256: "abc"}}}, calls)

	failing := &fakeRecoverer{err: errors.New("conflict")}
	other := backend.Record{ArtifactUID: "uid-2"}
	for range 3 {
		reconciler.recoverAbandonedRecording(ctx, failing, other)
	}
	require.Len(t, calls, 2, "a failure is reported once, not on every reconcile")
	require.ErrorContains(t, calls[1].err, "conflict")
}
