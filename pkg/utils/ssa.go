package utils

import (
	"context"
	"encoding/json"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	appsv1ac "k8s.io/client-go/applyconfigurations/apps/v1"
	corev1ac "k8s.io/client-go/applyconfigurations/core/v1"
	metav1ac "k8s.io/client-go/applyconfigurations/meta/v1"
	policyv1ac "k8s.io/client-go/applyconfigurations/policy/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	telekomv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	ac "github.com/telekom/k8s-breakglass/api/v1alpha1/applyconfiguration/api/v1alpha1"
	"go.uber.org/zap"
)

// FieldOwnerController is the field owner name used for server-side apply operations.
const FieldOwnerController = "breakglass-controller"

// ApplyObject performs a server-side apply using the client.Apply() API.
// This is the preferred method for SSA as it uses typed ApplyConfiguration objects.
func ApplyObject(ctx context.Context, c client.Client, obj client.Object) error {
	applyConfig, err := ToApplyConfiguration(obj)
	if err != nil {
		return fmt.Errorf("failed to convert object to apply configuration: %w", err)
	}

	if err := c.Apply(ctx, applyConfig, client.FieldOwner(FieldOwnerController), client.ForceOwnership); err != nil {
		if apierrors.IsConflict(err) {
			zap.S().Warnw("SSA apply conflict",
				"kind", obj.GetObjectKind().GroupVersionKind().String(),
				"name", obj.GetName(),
				"namespace", obj.GetNamespace(),
				"error", err)
		}
		return err
	}
	return nil
}

// ApplyUnstructured performs a server-side apply on an unstructured object.
// This is useful for applying arbitrary Kubernetes resources (e.g., from templates).
// Defensively clears managedFields from the input object before applying, since
// managedFields are server-managed and not user-settable via SSA.
func ApplyUnstructured(ctx context.Context, c client.Client, obj *unstructured.Unstructured) error {
	// Defensively clear managedFields — they are not user-settable and can cause
	// apply failures if the rendered/parsed object happens to contain them.
	obj.SetManagedFields(nil)

	// Convert unstructured to apply configuration wrapper
	applyConfig := &unstructuredApplyConfiguration{obj: obj}

	if err := c.Apply(ctx, applyConfig, client.FieldOwner(FieldOwnerController), client.ForceOwnership); err != nil {
		if apierrors.IsConflict(err) {
			zap.S().Warnw("SSA apply conflict",
				"kind", obj.GetObjectKind().GroupVersionKind().String(),
				"name", obj.GetName(),
				"namespace", obj.GetNamespace(),
				"error", err)
		}
		return err
	}
	return nil
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

// unstructuredApplyConfiguration wraps an unstructured object to implement runtime.ApplyConfiguration.
type unstructuredApplyConfiguration struct {
	obj *unstructured.Unstructured
}

func (u *unstructuredApplyConfiguration) IsApplyConfiguration() {}

// MarshalJSON implements json.Marshaler for use with the Apply API.
func (u *unstructuredApplyConfiguration) MarshalJSON() ([]byte, error) {
	// Clean up managed fields before marshaling
	obj := u.obj.DeepCopy()
	obj.SetManagedFields(nil)
	if metaMap, ok := obj.Object["metadata"].(map[string]interface{}); ok {
		delete(metaMap, "managedFields")
	}
	return json.Marshal(obj.Object)
}

// GetName returns the name from the unstructured object for Apply API requirements.
func (u *unstructuredApplyConfiguration) GetName() *string {
	name := u.obj.GetName()
	return &name
}

// GetNamespace returns the namespace from the unstructured object for Apply API requirements.
func (u *unstructuredApplyConfiguration) GetNamespace() *string {
	ns := u.obj.GetNamespace()
	return &ns
}

// ApplyStatus performs a server-side apply on the status subresource.
func ApplyStatus(ctx context.Context, c client.Client, obj client.Object) error {
	applyConfig, err := ToStatusApplyConfiguration(obj)
	if err != nil {
		return fmt.Errorf("failed to convert object to status apply configuration: %w", err)
	}

	if err := c.SubResource("status").Apply(ctx, applyConfig, client.FieldOwner(FieldOwnerController), client.ForceOwnership); err != nil {
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
	case *telekomv1alpha1.BreakglassSession:
		return breakglassSessionToApplyConfig(o)
	case *telekomv1alpha1.ClusterConfig:
		return clusterConfigToApplyConfig(o)
	case *telekomv1alpha1.DebugSession:
		return debugSessionToApplyConfig(o)
	case *telekomv1alpha1.BreakglassEscalation:
		return breakglassEscalationToApplyConfig(o)
	case *telekomv1alpha1.IdentityProvider:
		return identityProviderToApplyConfig(o)
	case *telekomv1alpha1.MailProvider:
		return mailProviderToApplyConfig(o)
	case *telekomv1alpha1.DenyPolicy:
		return denyPolicyToApplyConfig(o)
	case *telekomv1alpha1.DebugSessionTemplate:
		return debugSessionTemplateToApplyConfig(o)
	case *telekomv1alpha1.DebugPodTemplate:
		return debugPodTemplateToApplyConfig(o)
	case *telekomv1alpha1.DebugSessionClusterBinding:
		return debugSessionClusterBindingToApplyConfig(o)
	case *corev1.Secret:
		return secretToApplyConfig(o), nil
	case *corev1.Pod:
		return podToApplyConfig(o)
	case *corev1.ResourceQuota:
		return resourceQuotaToApplyConfig(o)
	case *policyv1.PodDisruptionBudget:
		return pdbToApplyConfig(o)
	case *appsv1.DaemonSet:
		return daemonSetToApplyConfig(o)
	case *appsv1.Deployment:
		return deploymentToApplyConfig(o)
	default:
		return nil, fmt.Errorf("unsupported type for ApplyConfiguration: %T", obj)
	}
}

// ToStatusApplyConfiguration converts a client.Object to a runtime.ApplyConfiguration
// containing only the metadata and status fields (for status subresource updates).
func ToStatusApplyConfiguration(obj client.Object) (runtime.ApplyConfiguration, error) {
	switch o := obj.(type) {
	case *telekomv1alpha1.BreakglassSession:
		return breakglassSessionStatusApplyConfig(o)
	case *telekomv1alpha1.ClusterConfig:
		return clusterConfigStatusApplyConfig(o)
	case *telekomv1alpha1.DebugSession:
		return debugSessionStatusApplyConfig(o)
	case *telekomv1alpha1.BreakglassEscalation:
		return breakglassEscalationStatusApplyConfig(o)
	case *telekomv1alpha1.IdentityProvider:
		return identityProviderStatusApplyConfig(o)
	case *telekomv1alpha1.MailProvider:
		return mailProviderStatusApplyConfig(o)
	default:
		return nil, fmt.Errorf("unsupported type for status ApplyConfiguration: %T", obj)
	}
}

// Helper functions for each type

func breakglassSessionToApplyConfig(o *telekomv1alpha1.BreakglassSession) (*ac.BreakglassSessionApplyConfiguration, error) {
	cfg := ac.BreakglassSession(o.Name, o.Namespace)
	if err := jsonDecodeInto(o, cfg); err != nil {
		return nil, err
	}
	cfg.Status = nil // Don't include status when applying spec
	return cfg, nil
}

func breakglassSessionStatusApplyConfig(o *telekomv1alpha1.BreakglassSession) (*ac.BreakglassSessionApplyConfiguration, error) {
	cfg := ac.BreakglassSession(o.Name, o.Namespace)
	if err := jsonDecodeInto(o, cfg); err != nil {
		return nil, err
	}
	cfg.Spec = nil // Only include status
	return cfg, nil
}

func clusterConfigToApplyConfig(o *telekomv1alpha1.ClusterConfig) (*ac.ClusterConfigApplyConfiguration, error) {
	cfg := ac.ClusterConfig(o.Name, o.Namespace)
	if err := jsonDecodeInto(o, cfg); err != nil {
		return nil, err
	}
	cfg.Status = nil
	return cfg, nil
}

func clusterConfigStatusApplyConfig(o *telekomv1alpha1.ClusterConfig) (*ac.ClusterConfigApplyConfiguration, error) {
	cfg := ac.ClusterConfig(o.Name, o.Namespace)
	if err := jsonDecodeInto(o, cfg); err != nil {
		return nil, err
	}
	cfg.Spec = nil
	return cfg, nil
}

func debugSessionToApplyConfig(o *telekomv1alpha1.DebugSession) (*ac.DebugSessionApplyConfiguration, error) {
	cfg := ac.DebugSession(o.Name, o.Namespace)
	if err := jsonDecodeInto(o, cfg); err != nil {
		return nil, err
	}
	cfg.Status = nil
	return cfg, nil
}

func debugSessionStatusApplyConfig(o *telekomv1alpha1.DebugSession) (*ac.DebugSessionApplyConfiguration, error) {
	cfg := ac.DebugSession(o.Name, o.Namespace)
	if err := jsonDecodeInto(o, cfg); err != nil {
		return nil, err
	}
	cfg.Spec = nil
	return cfg, nil
}

func breakglassEscalationToApplyConfig(o *telekomv1alpha1.BreakglassEscalation) (*ac.BreakglassEscalationApplyConfiguration, error) {
	cfg := ac.BreakglassEscalation(o.Name, o.Namespace)
	if err := jsonDecodeInto(o, cfg); err != nil {
		return nil, err
	}
	cfg.Status = nil
	return cfg, nil
}

func breakglassEscalationStatusApplyConfig(o *telekomv1alpha1.BreakglassEscalation) (*ac.BreakglassEscalationApplyConfiguration, error) {
	cfg := ac.BreakglassEscalation(o.Name, o.Namespace)
	if err := jsonDecodeInto(o, cfg); err != nil {
		return nil, err
	}
	cfg.Spec = nil
	return cfg, nil
}

func identityProviderToApplyConfig(o *telekomv1alpha1.IdentityProvider) (*ac.IdentityProviderApplyConfiguration, error) {
	cfg := ac.IdentityProvider(o.Name, "")
	if err := jsonDecodeInto(o, cfg); err != nil {
		return nil, err
	}
	cfg.Status = nil
	return cfg, nil
}

func identityProviderStatusApplyConfig(o *telekomv1alpha1.IdentityProvider) (*ac.IdentityProviderApplyConfiguration, error) {
	cfg := ac.IdentityProvider(o.Name, "")
	if err := jsonDecodeInto(o, cfg); err != nil {
		return nil, err
	}
	cfg.Spec = nil
	return cfg, nil
}

func mailProviderToApplyConfig(o *telekomv1alpha1.MailProvider) (*ac.MailProviderApplyConfiguration, error) {
	cfg := ac.MailProvider(o.Name, "")
	if err := jsonDecodeInto(o, cfg); err != nil {
		return nil, err
	}
	cfg.Status = nil
	return cfg, nil
}

func mailProviderStatusApplyConfig(o *telekomv1alpha1.MailProvider) (*ac.MailProviderApplyConfiguration, error) {
	cfg := ac.MailProvider(o.Name, "")
	if err := jsonDecodeInto(o, cfg); err != nil {
		return nil, err
	}
	cfg.Spec = nil
	return cfg, nil
}

func denyPolicyToApplyConfig(o *telekomv1alpha1.DenyPolicy) (*ac.DenyPolicyApplyConfiguration, error) {
	cfg := ac.DenyPolicy(o.Name, "")
	if err := jsonDecodeInto(o, cfg); err != nil {
		return nil, err
	}
	cfg.Status = nil
	return cfg, nil
}

func debugSessionTemplateToApplyConfig(o *telekomv1alpha1.DebugSessionTemplate) (*ac.DebugSessionTemplateApplyConfiguration, error) {
	cfg := ac.DebugSessionTemplate(o.Name, "")
	if err := jsonDecodeInto(o, cfg); err != nil {
		return nil, err
	}
	cfg.Status = nil
	return cfg, nil
}

func debugPodTemplateToApplyConfig(o *telekomv1alpha1.DebugPodTemplate) (*ac.DebugPodTemplateApplyConfiguration, error) {
	cfg := ac.DebugPodTemplate(o.Name, "")
	if err := jsonDecodeInto(o, cfg); err != nil {
		return nil, err
	}
	cfg.Status = nil
	return cfg, nil
}

func debugSessionClusterBindingToApplyConfig(o *telekomv1alpha1.DebugSessionClusterBinding) (*ac.DebugSessionClusterBindingApplyConfiguration, error) {
	cfg := ac.DebugSessionClusterBinding(o.Name, o.Namespace)
	if err := jsonDecodeInto(o, cfg); err != nil {
		return nil, err
	}
	cfg.Status = nil
	return cfg, nil
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

// podToApplyConfig converts a Pod to its ApplyConfiguration equivalent.
func podToApplyConfig(o *corev1.Pod) (*corev1ac.PodApplyConfiguration, error) {
	cfg := corev1ac.Pod(o.Name, o.Namespace)
	if err := jsonDecodeInto(o, cfg); err != nil {
		return nil, err
	}
	// Clear status - SSA should only set spec
	cfg.Status = nil
	return cfg, nil
}

// resourceQuotaToApplyConfig converts a ResourceQuota to its ApplyConfiguration equivalent.
func resourceQuotaToApplyConfig(o *corev1.ResourceQuota) (*corev1ac.ResourceQuotaApplyConfiguration, error) {
	cfg := corev1ac.ResourceQuota(o.Name, o.Namespace)
	if err := jsonDecodeInto(o, cfg); err != nil {
		return nil, err
	}
	cfg.Status = nil
	return cfg, nil
}

// pdbToApplyConfig converts a PodDisruptionBudget to its ApplyConfiguration equivalent.
func pdbToApplyConfig(o *policyv1.PodDisruptionBudget) (*policyv1ac.PodDisruptionBudgetApplyConfiguration, error) {
	cfg := policyv1ac.PodDisruptionBudget(o.Name, o.Namespace)
	if err := jsonDecodeInto(o, cfg); err != nil {
		return nil, err
	}
	cfg.Status = nil
	return cfg, nil
}

// daemonSetToApplyConfig converts a DaemonSet to its ApplyConfiguration equivalent.
func daemonSetToApplyConfig(o *appsv1.DaemonSet) (*appsv1ac.DaemonSetApplyConfiguration, error) {
	cfg := appsv1ac.DaemonSet(o.Name, o.Namespace)
	if err := jsonDecodeInto(o, cfg); err != nil {
		return nil, err
	}
	cfg.Status = nil
	return cfg, nil
}

// deploymentToApplyConfig converts a Deployment to its ApplyConfiguration equivalent.
func deploymentToApplyConfig(o *appsv1.Deployment) (*appsv1ac.DeploymentApplyConfiguration, error) {
	cfg := appsv1ac.Deployment(o.Name, o.Namespace)
	if err := jsonDecodeInto(o, cfg); err != nil {
		return nil, err
	}
	cfg.Status = nil
	return cfg, nil
}

// jsonDecodeInto marshals src to JSON and unmarshals into dst.
// This is used to convert typed objects to their ApplyConfiguration equivalents.
func jsonDecodeInto(src, dst interface{}) error {
	data, err := json.Marshal(src)
	if err != nil {
		return fmt.Errorf("failed to marshal %T: %w", src, err)
	}
	if err := json.Unmarshal(data, dst); err != nil {
		return fmt.Errorf("failed to unmarshal into %T: %w", dst, err)
	}
	return nil
}
