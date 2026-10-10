// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"time"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
)

func queuedConfig(queue *breakglassv1alpha1.AuditQueueConfig) QueuedSinkConfig {
	cfg := DefaultQueuedSinkConfig()
	if queue == nil {
		return cfg
	}
	if queue.Size > 0 {
		cfg.QueueSize = queue.Size
	}
	if queue.Workers > 0 {
		cfg.WorkerCount = queue.Workers
	}
	cfg.DropOnFull = queue.DropOnFull
	if queue.RetryAttempts > 0 {
		cfg.RetryAttempts = queue.RetryAttempts
	}
	if queue.RetryInitialBackoffMillis > 0 {
		cfg.RetryInitialBackoff = time.Duration(queue.RetryInitialBackoffMillis) * time.Millisecond
	}
	if queue.RetryMaxBackoffMillis > 0 {
		cfg.RetryMaxBackoff = time.Duration(queue.RetryMaxBackoffMillis) * time.Millisecond
	}
	if queue.RetryTimeoutSeconds > 0 {
		cfg.RetryTimeout = time.Duration(queue.RetryTimeoutSeconds) * time.Second
	}
	return cfg
}
