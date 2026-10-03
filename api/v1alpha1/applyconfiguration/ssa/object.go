// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package ssa

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	appsv1ac "k8s.io/client-go/applyconfigurations/apps/v1"
	batchv1ac "k8s.io/client-go/applyconfigurations/batch/v1"
	corev1ac "k8s.io/client-go/applyconfigurations/core/v1"
	metav1ac "k8s.io/client-go/applyconfigurations/meta/v1"
	policyv1ac "k8s.io/client-go/applyconfigurations/policy/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	ac "github.com/telekom/k8s-breakglass/api/v1alpha1/applyconfiguration/api/v1alpha1"
)

// ApplyObject performs a cache-aware server-side apply using the client.Apply() API.
// When used with a cache-backed controller-runtime client, it reads the current state
// from the informer cache and skips the API call if the desired state already matches.
// With an uncached client, the pre-check Get will hit the API server directly.
// This follows the cluster-api patchHelper pattern.
//
// Callers that need the result (skipped/created/patched) should use [PatchApplyObject].
func ApplyObject(ctx context.Context, c client.Client, obj client.Object) error {
	_, err := PatchApplyObject(ctx, c, obj)
	return err
}

// ApplyUnstructured performs a cache-aware server-side apply on an unstructured object.
// When used with a cache-backed controller-runtime client, it reads the current state
// from the informer cache and skips the API call if the desired state already matches.
// With an uncached client, the pre-check Get will hit the API server directly.
// This follows the cluster-api patchHelper pattern.
//
// Callers that need the result (skipped/created/patched) should use [PatchApplyUnstructured].
func ApplyUnstructured(ctx context.Context, c client.Client, obj *unstructured.Unstructured) error {
	_, err := PatchApplyUnstructured(ctx, c, obj)
	return err
}

// ToApplyConfiguration converts a client.Object to a runtime.ApplyConfiguration
// containing metadata and spec (never status). This supports all known CRD types
// and the core types the controller applies.
func ToApplyConfiguration(obj client.Object) (runtime.ApplyConfiguration, error) {
	switch o := obj.(type) {
	case *breakglassv1alpha1.BreakglassSession:
		return ApplyConfigurationFrom(ac.BreakglassSession(o.Name, o.Namespace), o)
	case *breakglassv1alpha1.ClusterConfig:
		return ApplyConfigurationFrom(ac.ClusterConfig(o.Name, o.Namespace), o)
	case *breakglassv1alpha1.DebugSession:
		return ApplyConfigurationFrom(ac.DebugSession(o.Name, o.Namespace), o)
	case *breakglassv1alpha1.BreakglassEscalation:
		return ApplyConfigurationFrom(ac.BreakglassEscalation(o.Name, o.Namespace), o)
	case *breakglassv1alpha1.IdentityProvider:
		return ApplyConfigurationFrom(ac.IdentityProvider(o.Name), o)
	case *breakglassv1alpha1.MailProvider:
		return ApplyConfigurationFrom(ac.MailProvider(o.Name), o)
	case *breakglassv1alpha1.DenyPolicy:
		return ApplyConfigurationFrom(ac.DenyPolicy(o.Name), o)
	case *breakglassv1alpha1.DebugSessionTemplate:
		return ApplyConfigurationFrom(ac.DebugSessionTemplate(o.Name), o)
	case *breakglassv1alpha1.DebugPodTemplate:
		return ApplyConfigurationFrom(ac.DebugPodTemplate(o.Name), o)
	case *breakglassv1alpha1.DebugSessionClusterBinding:
		return ApplyConfigurationFrom(ac.DebugSessionClusterBinding(o.Name, o.Namespace), o)
	case *corev1.Secret:
		return secretToApplyConfig(o), nil
	case *corev1.Pod:
		return ApplyConfigurationFrom(corev1ac.Pod(o.Name, o.Namespace), o)
	case *corev1.ResourceQuota:
		return ApplyConfigurationFrom(corev1ac.ResourceQuota(o.Name, o.Namespace), o)
	case *policyv1.PodDisruptionBudget:
		return ApplyConfigurationFrom(policyv1ac.PodDisruptionBudget(o.Name, o.Namespace), o)
	case *appsv1.DaemonSet:
		return ApplyConfigurationFrom(appsv1ac.DaemonSet(o.Name, o.Namespace), o)
	case *appsv1.Deployment:
		return ApplyConfigurationFrom(appsv1ac.Deployment(o.Name, o.Namespace), o)
	case *batchv1.Job:
		return ApplyConfigurationFrom(batchv1ac.Job(o.Name, o.Namespace), o)
	default:
		return nil, fmt.Errorf("unsupported type for ApplyConfiguration: %T", obj)
	}
}

// ApplyConfigurationFrom decodes obj into seed via a JSON round-trip and returns
// seed. seed is normally a generated constructor result (for example
// ac.BreakglassSession(name, namespace)) and supplies apiVersion, kind and
// name, which typed objects read through a client usually lack.
//
// The status stanza of obj is dropped so the result only declares metadata and
// spec. When seed carries no namespace (cluster-scoped kinds), metadata.namespace
// from obj is dropped as well.
func ApplyConfigurationFrom[AC runtime.ApplyConfiguration](seed AC, obj any) (AC, error) {
	data, err := json.Marshal(obj)
	if err != nil {
		var zero AC
		return zero, fmt.Errorf("failed to marshal %T: %w", obj, err)
	}
	// UseNumber keeps int64 values exact across the map round-trip.
	var fields map[string]any
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&fields); err != nil {
		var zero AC
		return zero, fmt.Errorf("failed to unmarshal %T: %w", obj, err)
	}
	delete(fields, "status")
	if ns, ok := any(seed).(interface{ GetNamespace() *string }); ok && ns.GetNamespace() == nil {
		if meta, ok := fields["metadata"].(map[string]any); ok {
			delete(meta, "namespace")
		}
	}
	if data, err = json.Marshal(fields); err != nil {
		var zero AC
		return zero, fmt.Errorf("failed to marshal %T: %w", obj, err)
	}
	if err := json.Unmarshal(data, seed); err != nil {
		var zero AC
		return zero, fmt.Errorf("failed to unmarshal into %T: %w", seed, err)
	}
	return seed, nil
}

func secretToApplyConfig(o *corev1.Secret) *corev1ac.SecretApplyConfiguration {
	cfg := corev1ac.Secret(o.Name, o.Namespace)
	if o.Labels != nil {
		cfg.WithLabels(o.Labels)
	}
	if o.Annotations != nil {
		cfg.WithAnnotations(o.Annotations)
	}
	if len(o.Finalizers) > 0 {
		cfg.WithFinalizers(o.Finalizers...)
	}
	if o.Data != nil {
		cfg.WithData(o.Data)
	}
	if o.Type != "" {
		cfg.WithType(o.Type)
	}
	if o.OwnerReferences != nil {
		owners := make([]*metav1ac.OwnerReferenceApplyConfiguration, 0, len(o.OwnerReferences))
		for _, ref := range o.OwnerReferences {
			owners = append(owners, metav1ac.OwnerReference().
				WithAPIVersion(ref.APIVersion).
				WithKind(ref.Kind).
				WithName(ref.Name).
				WithUID(ref.UID))
		}
		cfg.WithOwnerReferences(owners...)
	}
	return cfg
}
