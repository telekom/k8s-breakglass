// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/rest"
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
//
// The RESTMapper alone is weak evidence: aggregated discovery silently drops
// a stale APIService, so its kind looks unserved during an outage. A target
// wrapped by withKindDiscovery therefore also has to confirm the absence via
// legacy discovery, which lists unavailable APIServices and fails on them.
func targetKindNotServed(ctx context.Context, target client.Client, apiVersion, kind string, opErr error) bool {
	if !isKindNotServedError(opErr) || target == nil || target.RESTMapper() == nil || kind == "" {
		return false
	}
	gv, err := schema.ParseGroupVersion(apiVersion)
	if err != nil {
		return false
	}
	gk := schema.GroupKind{Group: gv.Group, Kind: kind}
	if _, err = target.RESTMapper().RESTMapping(gk); !isKindNotServedError(err) {
		return false
	}
	if confirmer, ok := target.(kindAbsenceConfirmer); ok {
		absent, err := confirmer.confirmKindAbsent(ctx, gk)
		return err == nil && absent
	}
	return true
}

type kindAbsenceConfirmer interface {
	confirmKindAbsent(ctx context.Context, gk schema.GroupKind) (bool, error)
}

// discoveryConfirmedClient adds a legacy-discovery absence check to a target
// client.
type discoveryConfirmedClient struct {
	client.Client
	confirm func(ctx context.Context, gk schema.GroupKind) (bool, error)
}

func (c *discoveryConfirmedClient) confirmKindAbsent(ctx context.Context, gk schema.GroupKind) (bool, error) {
	return c.confirm(ctx, gk)
}

// withKindDiscovery wraps target so that unserved-kind decisions are
// confirmed against the target's legacy discovery endpoints.
func withKindDiscovery(target client.Client, cfg *rest.Config) client.Client {
	if target == nil || cfg == nil {
		return target
	}
	return &discoveryConfirmedClient{Client: target, confirm: func(ctx context.Context, gk schema.GroupKind) (bool, error) {
		dc, err := discovery.NewDiscoveryClientForConfig(cfg)
		if err != nil {
			return false, err
		}
		return legacyDiscoveryKindAbsent(ctx, dc.RESTClient(), gk)
	}}
}

// legacyDiscoveryKindAbsent reads the unaggregated discovery documents. The
// kube-aggregator lists every registered APIService group in /apis whether or
// not its backend is available, and a per-version request to an unavailable
// backend fails, so any error or listing keeps the kind "maybe served".
func legacyDiscoveryKindAbsent(ctx context.Context, rc rest.Interface, gk schema.GroupKind) (bool, error) {
	if gk.Group == "" {
		return false, nil // The core group is always served.
	}
	var groups metav1.APIGroupList
	if err := getLegacyJSON(ctx, rc, "/apis", &groups); err != nil {
		return false, err
	}
	for _, group := range groups.Groups {
		if group.Name != gk.Group {
			continue
		}
		for _, version := range group.Versions {
			var resources metav1.APIResourceList
			if err := getLegacyJSON(ctx, rc, path.Join("/apis", version.GroupVersion), &resources); err != nil {
				return false, err
			}
			for _, resource := range resources.APIResources {
				if resource.Kind == gk.Kind {
					return false, nil
				}
			}
		}
	}
	return true, nil
}

func getLegacyJSON(ctx context.Context, rc rest.Interface, absPath string, into any) error {
	raw, err := rc.Get().AbsPath(absPath).SetHeader("Accept", "application/json").DoRaw(ctx)
	if err != nil {
		return fmt.Errorf("discover %s: %w", absPath, err)
	}
	return json.Unmarshal(raw, into)
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
	return targetKindNotServed(ctx, target, apiVersion, kind, target.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, obj))
}

func kindNotServedReason(apiVersion, kind string) string {
	return fmt.Sprintf("target cluster does not serve %s %s; nothing can exist to delete", apiVersion, kind)
}
