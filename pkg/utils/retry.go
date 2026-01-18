// SPDX-FileCopyrightText: 2024 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"context"
	"time"

	"go.uber.org/zap"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// RetryConfig defines the configuration for retry operations
type RetryConfig struct {
	// MaxRetries is the maximum number of retry attempts (0 means no retries)
	MaxRetries int
	// InitialBackoff is the initial backoff duration before the first retry
	InitialBackoff time.Duration
	// MaxBackoff is the maximum backoff duration between retries
	MaxBackoff time.Duration
	// BackoffMultiplier is the factor by which backoff is multiplied after each retry
	BackoffMultiplier float64
}

// DefaultRetryConfig returns a sensible default retry configuration for status updates
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxRetries:        3,
		InitialBackoff:    100 * time.Millisecond,
		MaxBackoff:        2 * time.Second,
		BackoffMultiplier: 2.0,
	}
}

// StatusUpdateWithRetry performs a status update with retry logic for conflict errors.
// It will re-fetch the object on conflict and reapply the status changes before retrying.
// The modifyFunc is called to apply status changes to the freshly fetched object on each retry.
func StatusUpdateWithRetry[T client.Object](
	ctx context.Context,
	c client.Client,
	obj T,
	modifyFunc func(T) error,
	config RetryConfig,
) error {
	backoff := config.InitialBackoff

	for attempt := 0; attempt <= config.MaxRetries; attempt++ {
		// Apply the modification function
		if err := modifyFunc(obj); err != nil {
			return err
		}

		// Try to update the status
		err := c.Status().Update(ctx, obj)
		if err == nil {
			return nil // Success
		}

		// Check if it's a conflict error and we should retry
		if !apierrors.IsConflict(err) || attempt >= config.MaxRetries {
			return err
		}

		zap.S().Debugw("Status update conflict, retrying",
			"attempt", attempt+1,
			"maxRetries", config.MaxRetries,
			"backoff", backoff.String(),
		)

		// Wait before retrying
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}

		// Increase backoff for next retry
		backoff = time.Duration(float64(backoff) * config.BackoffMultiplier)
		if backoff > config.MaxBackoff {
			backoff = config.MaxBackoff
		}

		// Re-fetch the object to get the latest version
		objKey := client.ObjectKeyFromObject(obj)
		if err := c.Get(ctx, objKey, obj); err != nil {
			return err
		}
	}

	// Should not reach here, but return the last error for safety
	return nil
}

// UpdateWithRetry performs an object update with retry logic for conflict errors.
// Similar to StatusUpdateWithRetry but for full object updates.
func UpdateWithRetry[T client.Object](
	ctx context.Context,
	c client.Client,
	obj T,
	modifyFunc func(T) error,
	config RetryConfig,
) error {
	backoff := config.InitialBackoff

	for attempt := 0; attempt <= config.MaxRetries; attempt++ {
		// Apply the modification function
		if err := modifyFunc(obj); err != nil {
			return err
		}

		// Try to update the object
		err := c.Update(ctx, obj)
		if err == nil {
			return nil // Success
		}

		// Check if it's a conflict error and we should retry
		if !apierrors.IsConflict(err) || attempt >= config.MaxRetries {
			return err
		}

		zap.S().Debugw("Update conflict, retrying",
			"attempt", attempt+1,
			"maxRetries", config.MaxRetries,
			"backoff", backoff.String(),
		)

		// Wait before retrying
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}

		// Increase backoff for next retry
		backoff = time.Duration(float64(backoff) * config.BackoffMultiplier)
		if backoff > config.MaxBackoff {
			backoff = config.MaxBackoff
		}

		// Re-fetch the object to get the latest version
		objKey := client.ObjectKeyFromObject(obj)
		if err := c.Get(ctx, objKey, obj); err != nil {
			return err
		}
	}

	// Should not reach here, but return the last error for safety
	return nil
}
