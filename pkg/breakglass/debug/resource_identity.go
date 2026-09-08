// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/utils"
	corev1 "k8s.io/api/core/v1"
	schedulingv1 "k8s.io/api/scheduling/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// LegacyCleanupUIDsAnnotation is an explicit operator recovery mechanism for
// sessions created before immutable resource identities were persisted. Values
// are original UIDs, keyed by "apiVersion/kind/namespace/name". Never infer an
// original UID from mutable labels or a same-name replacement.
const LegacyCleanupUIDsAnnotation = "breakglass.t-caas.telekom.com/legacy-cleanup-uids"

func deleteTrackedResource(ctx context.Context, target client.Client, session *breakglassv1alpha1.DebugSession, obj client.Object) error {
	if _, ok := obj.(*corev1.Pod); ok && obj.GetObjectKind().GroupVersionKind().Empty() {
		obj.GetObjectKind().SetGroupVersionKind(corev1.SchemeGroupVersion.WithKind("Pod"))
	}
	gvk := obj.GetObjectKind().GroupVersionKind()
	uid := obj.GetUID()
	if uid == "" && session != nil {
		for _, ref := range session.Status.DeployedResources {
			if ref.APIVersion == gvk.GroupVersion().String() && ref.Kind == gvk.Kind && ref.Namespace == obj.GetNamespace() && ref.Name == obj.GetName() && ref.UID != "" {
				uid = types.UID(ref.UID)
				break
			}
		}
	}
	live := obj.DeepCopyObject().(client.Object)
	if err := target.Get(ctx, client.ObjectKeyFromObject(obj), live); err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("read tracked resource before cleanup: %w", err)
	}
	if uid == "" {
		key := gvk.GroupVersion().String() + "/" + gvk.Kind + "/" + obj.GetNamespace() + "/" + obj.GetName()
		recovered := map[string]string{}
		if session != nil && session.Annotations[LegacyCleanupUIDsAnnotation] != "" {
			if err := json.Unmarshal([]byte(session.Annotations[LegacyCleanupUIDsAnnotation]), &recovered); err != nil {
				return fmt.Errorf("invalid %s annotation: %w", LegacyCleanupUIDsAnnotation, err)
			}
		}
		uid = types.UID(recovered[key])
		if uid == "" {
			return fmt.Errorf("legacy resource %s lacks original UID; an operator must verify ownership and record its UID in DebugSession annotation %s, or remove the resource manually", key, LegacyCleanupUIDsAnnotation)
		}
	}
	// The original instance is gone. Retire its inventory without touching a
	// replacement, including a replacement created after an operator inspection.
	if live.GetUID() != uid {
		return nil
	}
	if err := target.Delete(ctx, live, client.Preconditions{UID: &uid}); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("delete tracked resource with UID %s: %w", uid, err)
	}
	return nil
}

// podMatchesWorkloadTemplate prevents mutable ownerReferences from enrolling an
// unrelated workload. Compare immutable workload configuration, allowing only
// Kubernetes scheduling and service-account admission additions. Other admission
// mutations must be represented in the template; mismatches fail closed.
func podMatchesWorkloadTemplate(pod *corev1.Pod, template *corev1.PodTemplateSpec, daemonSet bool) bool {
	expected, actual := template.Spec.DeepCopy(), pod.Spec.DeepCopy()
	normalize := func(spec *corev1.PodSpec) {
		spec.NodeName = ""
		spec.EphemeralContainers = nil
		if spec.ServiceAccountName == "" {
			spec.ServiceAccountName = "default"
		}
		if spec.DeprecatedServiceAccount == "" {
			spec.DeprecatedServiceAccount = spec.ServiceAccountName
		}
		// The DaemonSet controller replaces node affinity and adds node-condition
		// tolerations. These do not add credentials or executable workload content.
		if daemonSet {
			spec.Affinity = nil
			spec.Tolerations = nil
		} else {
			// DefaultTolerationSeconds admission uses configurable durations.
			tolerations := spec.Tolerations[:0]
			for _, tolerance := range spec.Tolerations {
				if (tolerance.Key == "node.kubernetes.io/not-ready" || tolerance.Key == "node.kubernetes.io/unreachable") && tolerance.Operator == corev1.TolerationOpExists && tolerance.Effect == corev1.TaintEffectNoExecute {
					continue
				}
				tolerations = append(tolerations, tolerance)
			}
			spec.Tolerations = tolerations
		}
		volumes := spec.Volumes[:0]
		tokenVolumes := map[string]bool{}
		for _, volume := range spec.Volumes {
			if isDefaultServiceAccountVolume(volume) {
				tokenVolumes[volume.Name] = true
				continue
			}
			volumes = append(volumes, volume)
		}
		spec.Volumes = volumes
		for _, containers := range [][]corev1.Container{spec.Containers, spec.InitContainers} {
			for i := range containers {
				mounts := containers[i].VolumeMounts[:0]
				for _, mount := range containers[i].VolumeMounts {
					if tokenVolumes[mount.Name] && mount.MountPath == "/var/run/secrets/kubernetes.io/serviceaccount" && mount.ReadOnly {
						continue
					}
					mounts = append(mounts, mount)
				}
				containers[i].VolumeMounts = mounts
			}
		}
	}
	normalize(expected)
	normalize(actual)
	return equality.Semantic.DeepEqual(expected, actual)
}

// podMatchesAdmittedWorkloadTemplate applies the narrow Pod-admission exception
// for a live workload Pod. ReplicaSet templates are synthetic objects and must
// continue using podMatchesWorkloadTemplate without this exception.
func podMatchesAdmittedWorkloadTemplate(ctx context.Context, target client.Client, pod *corev1.Pod, template *corev1.PodTemplateSpec, daemonSet bool) bool {
	if podMatchesWorkloadTemplate(pod, template, daemonSet) {
		return true
	}
	actual := pod.Spec.DeepCopy()
	if !verifyAdmittedPriority(ctx, target, actual, template.Spec) {
		return false
	}
	if template.Spec.Priority == nil {
		actual.Priority = nil
	}
	if template.Spec.PreemptionPolicy == nil {
		actual.PreemptionPolicy = nil
	}
	if template.Spec.PriorityClassName == "" {
		actual.PriorityClassName = ""
	}
	return podMatchesWorkloadTemplate(&corev1.Pod{Spec: *actual}, template, daemonSet)
}

func verifyAdmittedPriority(ctx context.Context, target client.Client, actual *corev1.PodSpec, expected corev1.PodSpec) bool {
	className := actual.PriorityClassName
	if className == "" && actual.Priority == nil && actual.PreemptionPolicy == nil {
		return true
	}
	if className == "" {
		return (actual.Priority == nil || *actual.Priority == 0) &&
			(actual.PreemptionPolicy == nil || *actual.PreemptionPolicy == corev1.PreemptLowerPriority)
	}
	priorityClass := &schedulingv1.PriorityClass{}
	if err := target.Get(ctx, client.ObjectKey{Name: className}, priorityClass); err != nil {
		return false
	}
	if expected.PriorityClassName == "" {
		if !priorityClass.GlobalDefault {
			return false
		}
	} else if expected.PriorityClassName != className {
		return false
	}
	if actual.Priority == nil || *actual.Priority != priorityClass.Value || actual.PreemptionPolicy == nil {
		return false
	}
	policy := corev1.PreemptLowerPriority
	if priorityClass.PreemptionPolicy != nil {
		policy = *priorityClass.PreemptionPolicy
	}
	return *actual.PreemptionPolicy == policy
}

func isDefaultServiceAccountVolume(volume corev1.Volume) bool {
	if !strings.HasPrefix(volume.Name, "kube-api-access-") || volume.Projected == nil || len(volume.Projected.Sources) != 3 {
		return false
	}
	sources := volume.Projected.Sources
	return sources[0].ServiceAccountToken != nil && sources[0].ServiceAccountToken.Audience == "" && sources[0].ServiceAccountToken.Path == "token" &&
		sources[1].ConfigMap != nil && sources[1].ConfigMap.Name == "kube-root-ca.crt" && len(sources[1].ConfigMap.Items) == 1 && sources[1].ConfigMap.Items[0].Key == "ca.crt" && sources[1].ConfigMap.Items[0].Path == "ca.crt" &&
		sources[2].DownwardAPI != nil && len(sources[2].DownwardAPI.Items) == 1 && sources[2].DownwardAPI.Items[0].Path == "namespace" && sources[2].DownwardAPI.Items[0].FieldRef != nil && sources[2].DownwardAPI.Items[0].FieldRef.FieldPath == "metadata.namespace"
}

// applyTrackedResource retains the identity returned by this exact apply request.
// Both controller-runtime Apply implementations decode the server response into
// the supplied configuration; a subsequent Get could instead observe a replacement.
func applyTrackedResource(ctx context.Context, target client.Client, obj client.Object) error {
	if u, ok := obj.(*unstructured.Unstructured); ok {
		cfg := client.ApplyConfigurationFromUnstructured(u)
		if err := target.Apply(ctx, cfg, client.FieldOwner(utils.FieldOwnerController), client.ForceOwnership); err != nil {
			return err
		}
		response, err := json.Marshal(cfg)
		if err != nil {
			return fmt.Errorf("encode tracked apply response: %w", err)
		}
		if err := json.Unmarshal(response, u); err != nil {
			return fmt.Errorf("decode tracked apply response: %w", err)
		}
		return nil
	}
	cfg, err := utils.ToApplyConfiguration(obj)
	if err != nil {
		return fmt.Errorf("build tracked apply configuration: %w", err)
	}
	if err := target.Apply(ctx, cfg, client.FieldOwner(utils.FieldOwnerController), client.ForceOwnership); err != nil {
		return err
	}
	response, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("encode tracked apply response: %w", err)
	}
	if err := json.Unmarshal(response, obj); err != nil {
		return fmt.Errorf("decode tracked apply response: %w", err)
	}
	return nil
}

func applyOwnedTrackedResource(ctx context.Context, target client.Client, obj client.Object, session *breakglassv1alpha1.DebugSession) error {
	if err := target.Create(ctx, obj); err == nil {
		return nil
	} else if !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create tracked resource: %w", err)
	}

	existing := obj.DeepCopyObject().(client.Object)
	if err := target.Get(ctx, client.ObjectKeyFromObject(obj), existing); err != nil {
		return fmt.Errorf("check tracked resource ownership: %w", err)
	}
	if session == nil || existing.GetAnnotations()[sourceSessionUIDAnnotation] != string(session.UID) {
		return fmt.Errorf("target resource %s/%s already exists and is owned by another session", obj.GetNamespace(), obj.GetName())
	}
	createOpID := obj.GetAnnotations()[createOperationIDAnnotation]
	if createOpID != "" && existing.GetAnnotations()[createOperationIDAnnotation] != createOpID {
		return fmt.Errorf("target resource %s/%s already exists with a different operation identity", obj.GetNamespace(), obj.GetName())
	}
	obj.SetUID(existing.GetUID())
	obj.SetResourceVersion(existing.GetResourceVersion())
	return nil
}
