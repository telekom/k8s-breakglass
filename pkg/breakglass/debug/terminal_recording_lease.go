// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"context"
	"fmt"
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
	namespace := binding.Namespace
	if namespace == "" {
		namespace = p.service.namespace
	}
	ref, err := p.service.Acquire(ctx, ConnectionLeaseProof{Namespace: namespace, SessionUID: types.UID(binding.SessionUID), TargetUID: types.UID(binding.TargetPodUID), ProfileDigest: binding.RuntimeBindingDigest, ExpiresAt: binding.ExpiresAt})
	if err != nil {
		return nil, fmt.Errorf("acquire terminal recording lease: %w", err)
	}
	return &terminalRecordingLeaseConnection{service: p.service, ref: ref, binding: TerminalRecordingConnectionBinding{
		Namespace: namespace, SessionUID: binding.SessionUID, TargetPodUID: binding.TargetPodUID,
		Epoch: strconv.FormatInt(ref.Epoch, 10), Generation: strconv.FormatInt(ref.Epoch, 10),
		ExpiresAt: ref.ExpiresAt, RuntimeBindingDigest: ref.ProfileDigest,
	}}, nil
}

type terminalRecordingLeaseConnection struct {
	service *ConnectionLeaseService
	ref     ConnectionLeaseRef
	binding TerminalRecordingConnectionBinding
}

func (c *terminalRecordingLeaseConnection) Binding() TerminalRecordingConnectionBinding {
	return c.binding
}

func (c *terminalRecordingLeaseConnection) Validate(ctx context.Context) error {
	if c == nil || c.service == nil {
		return fmt.Errorf("terminal recording lease connection is closed")
	}
	return c.service.Validate(ctx, c.ref, -1)
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
