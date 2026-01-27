/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package helpers provides shared test utilities for e2e tests.
package helpers

import (
	"context"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// RetryConfig configures retry behavior for update operations.
type RetryConfig struct {
	// MaxRetries is the maximum number of retry attempts (default: 5)
	MaxRetries int
	// InitialBackoff is the initial backoff duration (default: 50ms)
	InitialBackoff time.Duration
	// MaxBackoff is the maximum backoff duration (default: 1s)
	MaxBackoff time.Duration
	// BackoffMultiplier is the multiplier for exponential backoff (default: 2.0)
	BackoffMultiplier float64
}

// DefaultRetryConfig returns a default retry configuration suitable for e2e tests.
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxRetries:        5,
		InitialBackoff:    50 * time.Millisecond,
		MaxBackoff:        1 * time.Second,
		BackoffMultiplier: 2.0,
	}
}

// UpdateWithRetry performs an object update with automatic retry on conflict errors.
// This is essential for e2e tests where controllers may be reconciling the same
// object concurrently (e.g., updating status while test updates spec).
//
// The modifyFunc should apply the desired modifications to the object. It will be
// called once per retry attempt with a fresh version of the object.
//
// Example usage:
//
//	err := helpers.UpdateWithRetry(ctx, cli, &policy, func(p *v1alpha1.DenyPolicy) error {
//	    p.Spec.Rules = append(p.Spec.Rules, newRule)
//	    return nil
//	})
func UpdateWithRetry[T client.Object](
	ctx context.Context,
	c client.Client,
	obj T,
	modifyFunc func(T) error,
) error {
	return UpdateWithRetryConfig(ctx, c, obj, modifyFunc, DefaultRetryConfig())
}

// UpdateWithRetryConfig is like UpdateWithRetry but allows custom retry configuration.
func UpdateWithRetryConfig[T client.Object](
	ctx context.Context,
	c client.Client,
	obj T,
	modifyFunc func(T) error,
	config RetryConfig,
) error {
	backoff := config.InitialBackoff

	// First, get the latest version
	objKey := client.ObjectKeyFromObject(obj)
	if err := c.Get(ctx, objKey, obj); err != nil {
		return err
	}

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
		if err := c.Get(ctx, objKey, obj); err != nil {
			return err
		}
	}

	return nil
}
