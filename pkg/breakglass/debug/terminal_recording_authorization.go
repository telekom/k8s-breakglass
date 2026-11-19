// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"context"
	"fmt"
	"io"
	"sync/atomic"
	"time"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

// terminalRecordingAuthority keeps identity from authenticated middleware, never
// from query parameters, and rechecks live authorization around transport operations. An admitted write can complete during remote
// revocation; the transport watcher aborts blocked I/O after detecting it.
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

// terminalAuthorityMaxAge bounds how long transport I/O of a recorded terminal
// is admitted on the last successful live authority check (#1761). A
// revocation visible to the controller's live reads stops forwarding within
// this bound plus one already admitted write; the stream watcher, which
// re-checks every terminalWatchInterval, additionally ends the stream.
const terminalAuthorityMaxAge = time.Second

// terminalAuthorityCheckTimeout bounds one live check, so a hung read cannot
// hold the serialized check slot.
const terminalAuthorityCheckTimeout = 2 * time.Second

// terminalAuthority admits transport I/O on a cached live authority check.
// Validate is always backed by a live check that started after it was called
// (watcher, reservation, post-stream probe); Admit reuses a successful check
// that started less than maxAge ago. Live checks are serialized, so the cache
// reflects the most recent one, a failure stops admission at once, and callers
// waiting for the slot share a check that started after they asked. maxAge <=
// 0 is the strict mode: every admission is backed by its own live check.
type terminalAuthority struct {
	TerminalRecordingConnection
	maxAge time.Duration
	live   chan struct{} // one live check at a time
	okAt   atomic.Pointer[time.Time]
}

func newTerminalAuthority(connection TerminalRecordingConnection, maxAge time.Duration) *terminalAuthority {
	return &terminalAuthority{TerminalRecordingConnection: connection, maxAge: maxAge, live: make(chan struct{}, 1)}
}

func (a *terminalAuthority) Validate(ctx context.Context) error { return a.check(ctx, false) }

// Admit authorizes one transport read or write.
func (a *terminalAuthority) Admit(ctx context.Context) error {
	if a.fresh() {
		return nil
	}
	if err := a.check(ctx, true); err != nil {
		return fmt.Errorf("terminal authority check failed: %w", err)
	}
	return nil
}

func (a *terminalAuthority) fresh() bool {
	okAt := a.okAt.Load()
	return okAt != nil && time.Since(*okAt) < a.maxAge
}

func (a *terminalAuthority) check(ctx context.Context, admit bool) error {
	requested := time.Now()
	select {
	case a.live <- struct{}{}:
	case <-ctx.Done():
		return fmt.Errorf("wait for terminal authority check: %w", ctx.Err())
	}
	defer func() { <-a.live }()
	if okAt := a.okAt.Load(); okAt != nil && (!okAt.Before(requested) || admit && a.fresh()) {
		// A check that another caller ran while this one waited suffices.
		return nil
	}
	checkCtx, cancel := context.WithTimeout(ctx, terminalAuthorityCheckTimeout)
	defer cancel()
	// The start of the check bounds admission: all of its reads happen later.
	started := time.Now()
	if err := a.TerminalRecordingConnection.Validate(checkCtx); err != nil {
		a.okAt.Store(nil)
		return err
	}
	a.okAt.Store(&started)
	return nil
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
