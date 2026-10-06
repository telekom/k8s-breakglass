package utils

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"reflect"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
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
	sharedssa "github.com/telekom/t-caas-go-library/pkg/ssa"
	"go.uber.org/zap"
)

// FieldOwnerController is the field owner name used for server-side apply operations.
const FieldOwnerController = "breakglass-controller"

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

// ApplyTypedObject performs a server-side apply on any typed Kubernetes object by
// converting it to unstructured first. This is useful for core k8s types like
// ResourceQuota, PodDisruptionBudget, DaemonSet, Deployment, etc. that don't have
// generated ApplyConfiguration types in this repo.
//
// The object must have TypeMeta (APIVersion and Kind) set properly.
func ApplyTypedObject(ctx context.Context, c client.Client, obj client.Object, scheme *runtime.Scheme) error {
	// Convert typed object to unstructured
	u := &unstructured.Unstructured{}
	objData, err := runtime.DefaultUnstructuredConverter.ToUnstructured(obj)
	if err != nil {
		return fmt.Errorf("failed to convert typed object to unstructured: %w", err)
	}
	u.SetUnstructuredContent(objData)

	// Ensure GVK is set (runtime conversion may lose it)
	gvk := obj.GetObjectKind().GroupVersionKind()
	if gvk.Empty() && scheme != nil {
		// Try to get GVK from scheme
		gvks, _, err := scheme.ObjectKinds(obj)
		if err == nil && len(gvks) > 0 {
			gvk = gvks[0]
		}
	}
	if !gvk.Empty() {
		u.SetGroupVersionKind(gvk)
	} else {
		return fmt.Errorf("cannot apply object without GVK: set TypeMeta (APIVersion, Kind) on the object or provide a scheme")
	}

	return ApplyUnstructured(ctx, c, u)
}

// ApplyStatus performs a server-side apply on the status subresource.
func ApplyStatus(ctx context.Context, c client.Client, obj client.Object) error {
	applyConfig, err := ToStatusApplyConfiguration(obj)
	if err != nil {
		return fmt.Errorf("failed to convert object to status apply configuration: %w", err)
	}

	if err := sharedssa.ApplyStatus(ctx, c, applyConfig, FieldOwnerController); err != nil {
		if apierrors.IsConflict(err) {
			zap.S().Warnw("SSA status apply conflict",
				"kind", obj.GetObjectKind().GroupVersionKind().String(),
				"name", obj.GetName(),
				"namespace", obj.GetNamespace(),
				"error", err)
		}
		return err
	}
	return nil
}

// ToApplyConfiguration converts a client.Object to a runtime.ApplyConfiguration.
// This supports all known CRD types and core types like Secrets.
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

// ToStatusApplyConfiguration converts a client.Object to a runtime.ApplyConfiguration
// containing only the metadata and status fields (for status subresource updates).
func ToStatusApplyConfiguration(obj client.Object) (runtime.ApplyConfiguration, error) {
	switch o := obj.(type) {
	case *breakglassv1alpha1.BreakglassSession:
		return decodeApplyConfiguration(ac.BreakglassSession(o.Name, o.Namespace), o, "spec")
	case *breakglassv1alpha1.ClusterConfig:
		return decodeApplyConfiguration(ac.ClusterConfig(o.Name, o.Namespace), o, "spec")
	case *breakglassv1alpha1.DebugSession:
		return decodeApplyConfiguration(ac.DebugSession(o.Name, o.Namespace), o, "spec")
	case *breakglassv1alpha1.BreakglassEscalation:
		return decodeApplyConfiguration(ac.BreakglassEscalation(o.Name, o.Namespace), o, "spec")
	case *breakglassv1alpha1.IdentityProvider:
		return decodeApplyConfiguration(ac.IdentityProvider(o.Name), o, "spec")
	case *breakglassv1alpha1.MailProvider:
		return decodeApplyConfiguration(ac.MailProvider(o.Name), o, "spec")
	default:
		return nil, fmt.Errorf("unsupported type for status ApplyConfiguration: %T", obj)
	}
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

// ApplyConfigurationFrom decodes obj into a generated constructor seed,
// preserving its GVK and scope while excluding status from the main-resource apply.
func ApplyConfigurationFrom[AC runtime.ApplyConfiguration](seed AC, obj any) (AC, error) {
	return decodeApplyConfiguration(seed, obj, "status")
}

func decodeApplyConfiguration[AC runtime.ApplyConfiguration](seed AC, obj any, excludedField string) (AC, error) {
	var zero AC
	value := reflect.ValueOf(seed)
	if !value.IsValid() || (value.Kind() == reflect.Pointer && value.IsNil()) {
		return zero, fmt.Errorf("apply configuration seed must not be nil")
	}
	data, err := json.Marshal(obj)
	if err != nil {
		return zero, fmt.Errorf("failed to marshal %T: %w", obj, err)
	}
	var fields map[string]any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&fields); err != nil {
		return zero, fmt.Errorf("failed to unmarshal %T: %w", obj, err)
	}
	if fields == nil {
		return zero, fmt.Errorf("apply configuration source must encode a JSON object")
	}
	delete(fields, excludedField)
	if scoped, ok := any(seed).(interface{ GetNamespace() *string }); ok && scoped.GetNamespace() == nil {
		if metadata, ok := fields["metadata"].(map[string]any); ok {
			delete(metadata, "namespace")
		}
	}
	data, err = json.Marshal(fields)
	if err != nil {
		return zero, fmt.Errorf("failed to marshal %T: %w", obj, err)
	}
	if err := json.Unmarshal(data, seed); err != nil {
		return zero, fmt.Errorf("failed to unmarshal into %T: %w", seed, err)
	}
	return seed, nil
}
