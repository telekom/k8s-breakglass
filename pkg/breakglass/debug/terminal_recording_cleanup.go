// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"context"
	"errors"
	"fmt"
	"time"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	artifactstorage "github.com/telekom/k8s-breakglass/pkg/artifacts/storage"
	breakglass "github.com/telekom/k8s-breakglass/pkg/breakglass"
)

func (c *DebugSessionController) cleanupExpiredTerminalRecordings(ctx context.Context, session *breakglassv1alpha1.DebugSession) error {
	status := session.Status.KubectlDebugStatus
	if status == nil || len(status.TerminalRecordings) == 0 {
		return nil
	}
	if c.recordingStore == nil {
		return fmt.Errorf("terminal recording storage is not configured while recordings are retained")
	}
	now := time.Now().UTC()
	remaining := make([]breakglassv1alpha1.TerminalRecordingRef, 0, len(status.TerminalRecordings))
	changed := false
	for _, ref := range status.TerminalRecordings {
		if ref.ExpiresAt.IsZero() || now.Before(ref.ExpiresAt.Time) {
			remaining = append(remaining, ref)
			continue
		}
		if ref.Backend != c.recordingStore.Backend() || ref.BackendInstanceID != c.recordingStore.BackendInstanceID() {
			return fmt.Errorf("terminal recording %s backend identity changed", ref.ID)
		}
		object := terminalRecordingObject(ref)
		metadata, err := c.recordingStore.StatVersion(ctx, object, artifactstorage.Metadata{
			BackendInstanceID: ref.BackendInstanceID, Key: ref.ID, VersionID: ref.VersionID,
			RuntimeBindingDigest: ref.RuntimeBindingDigest, Size: ref.Size, SHA256: ref.SHA256,
		})
		if err != nil {
			if errors.Is(err, artifactstorage.ErrNotFound) {
				// A prior cleanup may have deleted the exact version before its
				// status update conflicted. Drop the stale reference and let the
				// status patch converge on the next retry.
				changed = true
				continue
			}
			return fmt.Errorf("stat expired terminal recording %s: %w", ref.ID, err)
		}
		if err := c.recordingStore.DeleteVersion(ctx, object, artifactstorage.Version{
			VersionID: metadata.VersionID, RuntimeBindingDigest: metadata.RuntimeBindingDigest,
			Size: metadata.Size, SHA256: metadata.SHA256, ETag: metadata.ETag,
			ProviderChecksum: metadata.ProviderChecksum, ModifiedAt: metadata.ModifiedAt,
		}); err != nil {
			return fmt.Errorf("delete expired terminal recording %s: %w", ref.ID, err)
		}
		changed = true
	}
	if !changed {
		return nil
	}
	return breakglass.PatchDebugSessionStatusWithReader(ctx, c.client, c.reader, session, func(updated *breakglassv1alpha1.DebugSessionStatus) {
		if updated.KubectlDebugStatus != nil {
			updated.KubectlDebugStatus.TerminalRecordings = remaining
			if len(updated.KubectlDebugStatus.TerminalRecordings) == 0 && len(updated.KubectlDebugStatus.EphemeralContainersInjected) == 0 && len(updated.KubectlDebugStatus.CopiedPods) == 0 {
				updated.KubectlDebugStatus = nil
			}
		}
	})
}
