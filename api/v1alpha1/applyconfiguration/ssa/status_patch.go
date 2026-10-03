// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package ssa

import (
	"context"

	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// PatchStatusWithOptimisticLock runs a read-mutate-patch cycle against the
// status subresource of the object identified by key:
//
//  1. a fresh object from newObj is read through reader (nil means c);
//  2. mutate edits it in place and reports whether anything changed;
//  3. if changed, the difference is sent as a JSON merge patch that carries the
//     read resourceVersion (client.MergeFromWithOptimisticLock), so a concurrent
//     writer makes the API server reject the patch with a conflict.
//
// The whole cycle is retried with retry.RetryOnConflict using backoff, so mutate
// always works on the latest live object. Pass retry.DefaultRetry or
// retry.DefaultBackoff for retrying callers, or wait.Backoff{Steps: 1} for a
// single attempt that surfaces the conflict to the caller.
//
// mutate must only edit the object in memory (reads are fine). It must not
// write the object itself: the patch base is captured before mutate runs, so a
// write that advances the resourceVersion would make every patch conflict.
//
// When mutate returns changed=false no patch is sent. Errors from reader.Get,
// mutate and the patch are returned unwrapped, so callers can use
// apierrors.IsNotFound / errors.As; a mutate error that is itself a conflict
// is retried like a patch conflict.
//
// On success the returned object is the patched object as returned by the API
// server. When the patch was skipped it is the object as read plus any
// in-memory edits mutate made before returning changed=false; those edits are
// not persisted. On error the zero value of T is returned.
func PatchStatusWithOptimisticLock[T client.Object](
	ctx context.Context,
	c client.Client,
	reader client.Reader,
	backoff wait.Backoff,
	key client.ObjectKey,
	newObj func() T,
	mutate func(T) (changed bool, err error),
) (T, error) {
	if reader == nil {
		reader = c
	}
	var result T
	err := retry.RetryOnConflict(backoff, func() error {
		obj := newObj()
		if err := reader.Get(ctx, key, obj); err != nil {
			return err
		}
		base := obj.DeepCopyObject().(client.Object)
		changed, err := mutate(obj)
		if err != nil {
			return err
		}
		if changed {
			if err := c.Status().Patch(ctx, obj, client.MergeFromWithOptions(base, client.MergeFromWithOptimisticLock{})); err != nil {
				return err
			}
		}
		result = obj
		return nil
	})
	if err != nil {
		var zero T
		return zero, err
	}
	return result, nil
}
