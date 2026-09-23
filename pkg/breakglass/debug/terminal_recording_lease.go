// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	coordinationv1 "k8s.io/api/coordination/v1"

	"k8s.io/apimachinery/pkg/types"
)

// NewTerminalRecordingConnectionProvider adapts the durable Kubernetes Lease
// service to the recording proxy. The proxy uses the lease epoch as its
// opaque transport generation; no credential or Secret material is exposed.
func NewTerminalRecordingConnectionProvider(service *ConnectionLeaseService) TerminalRecordingConnectionProvider {
	if service == nil {
		return nil
	}
	return terminalRecordingLeaseProvider{service: service}
}

const terminalStreamClaimAnnotation = "breakglass.telekom.com/terminal-stream-claim"
const terminalStreamExpiryAnnotation = "breakglass.telekom.com/terminal-stream-expires-at"

type terminalRecordingLeaseProvider struct{ service *ConnectionLeaseService }

func (p terminalRecordingLeaseProvider) AcquireTerminalRecordingConnection(ctx context.Context, binding TerminalRecordingConnectionBinding) (TerminalRecordingConnection, error) {
	if p.service == nil {
		return nil, fmt.Errorf("terminal recording lease service is not configured")
	}
	namespace := p.service.namespace
	if namespace == "" {
		return nil, fmt.Errorf("terminal recording execution namespace is not configured")
	}
	ref, err := p.service.Acquire(ctx, ConnectionLeaseProof{Namespace: namespace, SessionUID: types.UID(binding.SessionUID), TargetUID: types.UID(binding.TargetPodUID), ProfileDigest: binding.RuntimeBindingDigest, ExpiresAt: binding.ExpiresAt})
	if err != nil {
		return nil, fmt.Errorf("acquire terminal recording lease: %w", err)
	}
	failed := func(cause error) (TerminalRecordingConnection, error) {
		if !ref.createdByAcquire {
			return nil, cause
		}
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		// Only the unchanged object created by this call may be retired. A
		// concurrent publisher/acquirer changes resourceVersion and is preserved.
		uid, rv := ref.UID, ref.ResourceVersion
		err := p.service.client.Delete(cleanupCtx, &coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Name: ref.Name, Namespace: ref.Namespace}}, &ctrlclient.DeleteOptions{Raw: &metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid, ResourceVersion: &rv}}})
		if apierrors.IsNotFound(err) {
			err = nil
		} else if err != nil {
			err = fmt.Errorf("clean up newly acquired terminal lease: %w", err)
		}
		return nil, errors.Join(cause, err)
	}
	// A lease epoch is ownership, not a ready credential generation. Until
	// the generation producer has published its real readiness proof, fail closed.
	lease := &coordinationv1.Lease{}
	if err := p.service.liveReader().Get(ctx, types.NamespacedName{Namespace: ref.Namespace, Name: ref.Name}, lease); err != nil {
		return failed(fmt.Errorf("read terminal recording generation: %w", err))
	}
	generation, parseErr := strconv.ParseInt(lease.Annotations[connectionLeaseGenerationAnnotation], 10, 64)
	if parseErr != nil || generation < 1 || lease.Annotations[connectionLeaseSecretUIDAnnotation] == "" {
		return failed(fmt.Errorf("terminal recording credential generation is not ready"))
	}
	if err := p.service.Validate(ctx, ref, generation); err != nil {
		return failed(err)
	}
	if claim := lease.Annotations[terminalStreamClaimAnnotation]; claim != "" {
		expires, err := time.Parse(time.RFC3339Nano, lease.Annotations[terminalStreamExpiryAnnotation])
		if err != nil || time.Now().Before(expires) {
			return failed(fmt.Errorf("terminal target already has an active stream claim"))
		}
	}
	claim := uuid.NewString()
	lease.Annotations[terminalStreamClaimAnnotation] = claim
	lease.Annotations[terminalStreamExpiryAnnotation] = ref.ExpiresAt.UTC().Format(time.RFC3339Nano)
	connection := &terminalRecordingLeaseConnection{service: p.service, ref: ref, generation: generation, claim: claim, binding: TerminalRecordingConnectionBinding{
		Namespace: binding.Namespace, SessionUID: binding.SessionUID, TargetPodUID: binding.TargetPodUID, TargetClusterUID: binding.TargetClusterUID, LeaseUID: string(ref.UID),
		Epoch: strconv.FormatInt(ref.Epoch, 10), Generation: strconv.FormatInt(generation, 10),
		ExpiresAt: ref.ExpiresAt, RuntimeBindingDigest: ref.ProfileDigest,
	}}
	if err := p.service.client.Update(ctx, lease); err != nil {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		return nil, errors.Join(fmt.Errorf("claim terminal recording stream: %w", err), connection.Close(cleanupCtx))
	}
	if err := connection.Validate(ctx); err != nil {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		return nil, errors.Join(err, connection.Close(cleanupCtx))
	}
	return connection, nil
}

type terminalRecordingLeaseConnection struct {
	claim      string
	closed     atomic.Bool
	service    *ConnectionLeaseService
	ref        ConnectionLeaseRef
	generation int64
	binding    TerminalRecordingConnectionBinding
}

func (c *terminalRecordingLeaseConnection) Binding() TerminalRecordingConnectionBinding {
	return c.binding
}

func (c *terminalRecordingLeaseConnection) Validate(ctx context.Context) error {
	if c == nil || c.service == nil || c.closed.Load() {
		return fmt.Errorf("terminal recording lease connection is closed")
	}
	lease := &coordinationv1.Lease{}
	if err := c.service.liveReader().Get(ctx, types.NamespacedName{Namespace: c.ref.Namespace, Name: c.ref.Name}, lease); err != nil {
		return fmt.Errorf("read terminal stream claim: %w", err)
	}
	now := time.Now().UTC()
	if err := ValidateConnectionLease(lease, c.ref, now); err != nil {
		return err
	}
	expires, err := time.Parse(time.RFC3339Nano, lease.Annotations[terminalStreamExpiryAnnotation])
	if c.closed.Load() || err != nil || !now.Before(expires) || !now.Before(c.binding.ExpiresAt) || lease.Annotations[connectionLeaseGenerationAnnotation] != strconv.FormatInt(c.generation, 10) || lease.Annotations[terminalStreamClaimAnnotation] != c.claim {
		return fmt.Errorf("terminal stream claim expired or changed")
	}
	return nil
}

func (c *terminalRecordingLeaseConnection) Close(ctx context.Context) error {
	if c == nil || c.service == nil {
		return nil
	}
	c.closed.Store(true)
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		lease := &coordinationv1.Lease{}
		if err := c.service.liveReader().Get(ctx, types.NamespacedName{Namespace: c.ref.Namespace, Name: c.ref.Name}, lease); err != nil {
			if apierrors.IsNotFound(err) {
				return nil
			}
			return fmt.Errorf("read terminal stream before release: %w", err)
		}
		epoch, err := leaseEpoch(lease)
		if err != nil {
			return err
		}
		if lease.UID != c.ref.UID || epoch != c.ref.Epoch || lease.Annotations[terminalStreamClaimAnnotation] != c.claim {
			return nil
		}
		delete(lease.Annotations, terminalStreamClaimAnnotation)
		delete(lease.Annotations, terminalStreamExpiryAnnotation)
		if err := c.service.client.Update(ctx, lease); err != nil {
			return fmt.Errorf("release terminal stream claim: %w", err)
		}
		return nil
	})
}
