// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"context"
	"fmt"
	"io"
	"time"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

// terminalRecordingAuthority keeps identity from authenticated middleware, never
// from query parameters, and rechecks live authorization at every byte boundary.
func (c *DebugSessionAPIController) terminalRecordingAuthority(session *breakglassv1alpha1.DebugSession, identity debugSessionReadIdentity, namespace, podName, podUID, operation string, target func(context.Context) error) func(context.Context) error {
	expectedProfile, profileErr := ProfileDigestForSession(session)
	checkSession := func(live *breakglassv1alpha1.DebugSession) error {
		if profileErr != nil {
			return profileErr
		}
		if live.UID != session.UID || !live.DeletionTimestamp.IsZero() || live.Spec.Cluster != session.Spec.Cluster || live.Status.State != breakglassv1alpha1.DebugSessionStateActive || live.Status.ExpiresAt == nil || isDebugSessionExpired(live, time.Now().UTC()) || !c.canUserOperateDebugResources(live, identity) || !live.Status.AllowedPodOperations.IsOperationAllowed(operation) {
			return fmt.Errorf("terminal session authority changed")
		}
		uid, ok := allowedTargetPodUID(live, namespace, podName)
		if !ok || uid != podUID {
			return fmt.Errorf("terminal target authority changed")
		}
		actual, err := ProfileDigestForSession(live)
		if err != nil || actual != expectedProfile {
			return fmt.Errorf("terminal profile authority changed")
		}
		return nil
	}
	return func(ctx context.Context) error {
		checkCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		live := &breakglassv1alpha1.DebugSession{}
		if err := c.reader().Get(checkCtx, ctrlclient.ObjectKeyFromObject(session), live); err != nil {
			return fmt.Errorf("read terminal session authority: %w", err)
		}
		if err := checkSession(live); err != nil {
			return err
		}
		if err := target(checkCtx); err != nil {
			return err
		}
		// Bracket target lookup: neither revocation nor expiry during that lookup
		// may authorize even an exec command that never consumes stdin.
		if err := c.reader().Get(checkCtx, ctrlclient.ObjectKeyFromObject(session), live); err != nil {
			return fmt.Errorf("recheck terminal session authority: %w", err)
		}
		return checkSession(live)
	}
}

type authorizedTerminalConnection struct {
	TerminalRecordingConnection
	authorize func(context.Context) error
}

func (c authorizedTerminalConnection) Validate(ctx context.Context) error {
	if err := c.authorize(ctx); err != nil {
		return err
	}
	return c.TerminalRecordingConnection.Validate(ctx)
}

type authorizedRecordingReader struct {
	ctx       context.Context
	reader    io.Reader
	authorize func(context.Context) error
}

func (r authorizedRecordingReader) Read(p []byte) (int, error) {
	if err := r.authorize(r.ctx); err != nil {
		return 0, err
	}
	n, err := r.reader.Read(p)
	if n > 0 {
		if authErr := r.authorize(r.ctx); authErr != nil {
			return 0, authErr
		}
	}
	return n, err
}

type authorizedRecordingWriter struct {
	ctx       context.Context
	writer    io.Writer
	authorize func(context.Context) error
}

func (w authorizedRecordingWriter) Write(p []byte) (int, error) {
	if err := w.authorize(w.ctx); err != nil {
		return 0, err
	}
	return w.writer.Write(p)
}

func (r authorizedRecordingReader) Close() error {
	if closer, ok := r.reader.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}
