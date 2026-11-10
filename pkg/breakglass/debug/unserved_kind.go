// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"context"
	"errors"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
)

// isKindNotServedError reports whether err proves that the API server does not
// serve the requested kind: a RESTMapper NoMatch, or a discovery failure in
// which every failed group-version answered NotFound. Transient discovery
// failures are not proof and stay retryable.
func isKindNotServedError(err error) bool {
	var discoveryErr *apiutil.ErrResourceDiscoveryFailed
	if errors.As(err, &discoveryErr) {
		for _, groupErr := range *discoveryErr {
			if !apierrors.IsNotFound(groupErr) && !meta.IsNoMatchError(groupErr) {
				return false
			}
		}
		return len(*discoveryErr) > 0
	}
	return meta.IsNoMatchError(err)
}

// targetKindNotServed reports whether opErr, returned by an operation on
// apiVersion/kind against target, proves that the target serves no version of
// that group/kind. Objects of an unserved kind cannot exist (removing a CRD
// deletes its objects), so cleanup may treat them as absent. Only an actual
// NoMatch from the operation counts; the follow-up probe is version-agnostic
// on purpose, because a kind still served at another version may hold objects
// and must keep its cleanup inventory.
func targetKindNotServed(target client.Client, apiVersion, kind string, opErr error) bool {
	if !isKindNotServedError(opErr) || target == nil || target.RESTMapper() == nil || kind == "" {
		return false
	}
	gv, err := schema.ParseGroupVersion(apiVersion)
	if err != nil {
		return false
	}
	_, err = target.RESTMapper().RESTMapping(schema.GroupKind{Group: gv.Group, Kind: kind})
	return isKindNotServedError(err)
}

// probeKindNotServed reads the recorded object, which resolves its kind
// through the target RESTMapper, to learn whether the kind is served at all.
// An unresolved create intent has no other operation error to inspect.
func probeKindNotServed(ctx context.Context, target client.Client, apiVersion, kind, namespace, name string) bool {
	if target == nil {
		return false
	}
	obj := &unstructured.Unstructured{}
	obj.SetAPIVersion(apiVersion)
	obj.SetKind(kind)
	return targetKindNotServed(target, apiVersion, kind, target.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, obj))
}

func kindNotServedReason(apiVersion, kind string) string {
	return fmt.Sprintf("target cluster does not serve %s %s; nothing can exist to delete", apiVersion, kind)
}
