// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"context"
	"errors"
	"fmt"
	coordinationv1 "k8s.io/api/coordination/v1"
	"strconv"
	"time"

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
	// A lease epoch is ownership, not a ready credential generation. Until
	// the generation producer has published its real readiness proof, fail closed.
	lease := &coordinationv1.Lease{}
	if err := p.service.client.Get(ctx, types.NamespacedName{Namespace: ref.Namespace, Name: ref.Name}, lease); err != nil {
		return nil, fmt.Errorf("read terminal recording generation: %w", err)
	}
	generation, parseErr := strconv.ParseInt(lease.Annotations[connectionLeaseGenerationAnnotation], 10, 64)
	if parseErr != nil || generation < 1 || lease.Annotations[connectionLeaseSecretUIDAnnotation] == "" {
		return nil, errors.Join(fmt.Errorf("terminal recording credential generation is not ready"), p.service.Revoke(ctx, ref))
	}
	if err := p.service.Validate(ctx, ref, generation); err != nil {
		return nil, err
	}
	return &terminalRecordingLeaseConnection{service: p.service, ref: ref, generation: generation, binding: TerminalRecordingConnectionBinding{
		Namespace: binding.Namespace, SessionUID: binding.SessionUID, TargetPodUID: binding.TargetPodUID,
		Epoch: strconv.FormatInt(ref.Epoch, 10), Generation: strconv.FormatInt(generation, 10),
		ExpiresAt: ref.ExpiresAt, RuntimeBindingDigest: ref.ProfileDigest,
	}}, nil
}

type terminalRecordingLeaseConnection struct {
	service    *ConnectionLeaseService
	ref        ConnectionLeaseRef
	generation int64
	binding    TerminalRecordingConnectionBinding
}

func (c *terminalRecordingLeaseConnection) Binding() TerminalRecordingConnectionBinding {
	return c.binding
}

func (c *terminalRecordingLeaseConnection) Validate(ctx context.Context) error {
	if c == nil || c.service == nil {
		return fmt.Errorf("terminal recording lease connection is closed")
	}
	return c.service.Validate(ctx, c.ref, c.generation)
}

func (c *terminalRecordingLeaseConnection) Close(ctx context.Context) error {
	if c == nil || c.service == nil {
		return nil
	}
	err := c.service.Revoke(ctx, c.ref)
	c.service = nil
	return err
}

func (c *terminalRecordingLeaseConnection) expiresBefore(now time.Time) bool {
	return c == nil || !now.Before(c.binding.ExpiresAt)
}
