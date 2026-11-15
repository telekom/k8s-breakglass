// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/utils"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	schedulingv1 "k8s.io/api/scheduling/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
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
		var err error
		uid, err = legacyCleanupUID(session, gvk, obj.GetNamespace(), obj.GetName())
		if err != nil {
			return err
		}
	}
	// The original instance is gone. Retire its inventory without touching a
	// replacement, including a replacement created after an operator inspection.
	if live.GetUID() != uid {
		return nil
	}
	if err := target.Delete(ctx, live, client.Preconditions{UID: &uid}, client.PropagationPolicy(metav1.DeletePropagationBackground)); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("delete tracked resource with UID %s: %w", uid, err)
	}
	// An accepted DELETE may leave the original instance pending finalizers.
	// Callers must retain its inventory until this UID is actually gone.
	remaining := obj.DeepCopyObject().(client.Object)
	if err := target.Get(ctx, client.ObjectKeyFromObject(obj), remaining); err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("verify tracked resource deletion: %w", err)
	}
	if remaining.GetUID() == uid {
		// A foreign finalizer can hold the owner indefinitely. With Background
		// propagation the garbage collector keeps its dependents (for a
		// workload: the ReplicaSets and Pods) until the owner is gone; switching
		// the pending delete to Foreground makes it delete them now.
		if remaining.GetDeletionTimestamp() != nil && len(remaining.GetFinalizers()) > 0 &&
			!slices.Contains(remaining.GetFinalizers(), metav1.FinalizerDeleteDependents) {
			if err := target.Delete(ctx, remaining, client.Preconditions{UID: &uid},
				client.PropagationPolicy(metav1.DeletePropagationForeground)); err != nil && !apierrors.IsNotFound(err) {
				return fmt.Errorf("delete dependents of tracked resource with UID %s pending finalizers: %w", uid, err)
			}
		}
		return fmt.Errorf("delete tracked resource with UID %s is pending finalizers", uid)
	}
	return nil
}

func legacyCleanupUID(session *breakglassv1alpha1.DebugSession, gvk schema.GroupVersionKind, namespace, name string) (types.UID, error) {
	key := gvk.GroupVersion().String() + "/" + gvk.Kind + "/" + namespace + "/" + name
	recovered := map[string]string{}
	if session != nil && session.Annotations[LegacyCleanupUIDsAnnotation] != "" {
		if err := json.Unmarshal([]byte(session.Annotations[LegacyCleanupUIDsAnnotation]), &recovered); err != nil {
			return "", fmt.Errorf("invalid %s annotation: %w", LegacyCleanupUIDsAnnotation, err)
		}
	}
	uid := types.UID(recovered[key])
	if uid == "" {
		return "", fmt.Errorf("legacy resource %s lacks original UID; an operator must verify ownership and record its UID in DebugSession annotation %s, or remove the resource manually", key, LegacyCleanupUIDsAnnotation)
	}
	return uid, nil
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
	memoryPressure := corev1.Toleration{
		Key: "node.kubernetes.io/memory-pressure", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoSchedule,
	}
	configured := false
	for _, tolerance := range template.Spec.Tolerations {
		if equality.Semantic.DeepEqual(tolerance, memoryPressure) {
			configured = true
		}
	}
	if !configured && workloadHasQoSResources(template.Spec) {
		// PodTolerationRestriction adds this exact toleration to non-BestEffort
		// Pods, not ReplicaSet templates. Preserve every other toleration.
		for i, tolerance := range actual.Tolerations {
			if equality.Semantic.DeepEqual(tolerance, memoryPressure) {
				actual.Tolerations = append(actual.Tolerations[:i], actual.Tolerations[i+1:]...)
				break
			}
		}
	}
	if template.Spec.EnableServiceLinks == nil && actual.EnableServiceLinks != nil && *actual.EnableServiceLinks {
		actual.EnableServiceLinks = nil
	}
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

func workloadHasQoSResources(spec corev1.PodSpec) bool {
	hasResources := func(resources corev1.ResourceRequirements) bool {
		for _, list := range []corev1.ResourceList{resources.Requests, resources.Limits} {
			for _, name := range []corev1.ResourceName{corev1.ResourceCPU, corev1.ResourceMemory} {
				if quantity, ok := list[name]; ok && quantity.Sign() > 0 {
					return true
				}
			}
		}
		return false
	}
	if spec.Resources != nil {
		return hasResources(*spec.Resources)
	}
	for _, containers := range [][]corev1.Container{spec.Containers, spec.InitContainers} {
		for _, container := range containers {
			if hasResources(container.Resources) {
				return true
			}
		}
	}
	return false
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
	} else {
		return recoverTrackedCreateResult(ctx, target, obj, session, err)
	}
}

func recoverTrackedCreateResult(ctx context.Context, target client.Client, obj client.Object, session *breakglassv1alpha1.DebugSession, createErr error) error {
	if !apierrors.IsAlreadyExists(createErr) && !isAmbiguousCreateError(createErr) {
		err := fmt.Errorf("create tracked resource: %w", createErr)
		if apierrors.IsBadRequest(createErr) || apierrors.IsInvalid(createErr) || apierrors.IsForbidden(createErr) || apierrors.IsUnauthorized(createErr) || isKindNotServedError(createErr) {
			return &trackedCreateRejectedError{err: err}
		}
		return err
	}
	if session == nil || session.UID == "" {
		return fmt.Errorf("cannot recover tracked resource without a session UID: %w", createErr)
	}
	desiredAnnotations := obj.GetAnnotations()
	desiredOperationID := desiredAnnotations[createOperationIDAnnotation]
	if desiredOperationID == "" {
		return fmt.Errorf("target resource %s/%s already exists with a different operation identity: %w", obj.GetNamespace(), obj.GetName(), createErr)
	}
	existing := obj.DeepCopyObject().(client.Object)
	if err := target.Get(ctx, client.ObjectKeyFromObject(obj), existing); err != nil {
		return fmt.Errorf("recover tracked resource after create error: %w; read existing resource: %w", createErr, err)
	}
	// Typed GET decoding clears TypeMeta. The concrete Go type and REST mapping
	// already constrain its GVK; restore it for content comparison. Unstructured
	// objects retain the server's explicit GVK and must still match it.
	if _, unstructuredObject := existing.(*unstructured.Unstructured); !unstructuredObject && existing.GetObjectKind().GroupVersionKind().Empty() {
		existing.GetObjectKind().SetGroupVersionKind(obj.GetObjectKind().GroupVersionKind())
	}
	existingAnnotations := existing.GetAnnotations()
	if existingAnnotations[sourceSessionUIDAnnotation] != string(session.UID) {
		return fmt.Errorf("target resource %s/%s already exists and is owned by another session: %w", obj.GetNamespace(), obj.GetName(), createErr)
	}
	if existingAnnotations[createOperationIDAnnotation] != desiredOperationID {
		return fmt.Errorf("target resource %s/%s already exists with a different operation identity: %w", obj.GetNamespace(), obj.GetName(), createErr)
	}
	if annotations := managedPodAnnotations(existing); annotations != nil {
		if uid := annotations[sourceSessionUIDAnnotation]; uid != "" && uid != string(session.UID) {
			return fmt.Errorf("target resource %s/%s already exists with a different PodTemplate session UID: %w", obj.GetNamespace(), obj.GetName(), createErr)
		}
	}
	contentMatches, err := recoveredCreateContentMatches(obj, existing)
	if err != nil {
		return fmt.Errorf("validate recovered resource %s/%s content: %w", obj.GetNamespace(), obj.GetName(), err)
	}
	if !contentMatches {
		return fmt.Errorf("target resource %s/%s already exists with different desired content: %w", obj.GetNamespace(), obj.GetName(), createErr)
	}
	obj.SetUID(existing.GetUID())
	obj.SetResourceVersion(existing.GetResourceVersion())
	return nil
}

// trackedCreateRejectedError means the API explicitly rejected this Create
// (for example an admission denial), so the object was never persisted.
// Transport failures and recovery errors never carry this evidence.
type trackedCreateRejectedError struct{ err error }

func (e *trackedCreateRejectedError) Error() string { return e.err.Error() }
func (e *trackedCreateRejectedError) Unwrap() error { return e.err }

func isTrackedCreateRejected(err error) bool {
	var rejected *trackedCreateRejectedError
	return errors.As(err, &rejected)
}

func stampCreateOperation(obj client.Object, session *breakglassv1alpha1.DebugSession) (string, error) {
	if session == nil {
		return "", fmt.Errorf("cannot stamp create operation without a session")
	}
	if workload, ok := obj.(*unstructured.Unstructured); ok && isManagedUnstructuredWorkload(workload) && session.UID != "" {
		annotations, _, err := unstructured.NestedStringMap(workload.Object, "spec", "template", "metadata", "annotations")
		if err != nil {
			return "", fmt.Errorf("read workload PodTemplate annotations: %w", err)
		}
		if annotations == nil {
			annotations = map[string]string{}
		}
		annotations[sourceSessionUIDAnnotation] = string(session.UID)
		if err := unstructured.SetNestedStringMap(workload.Object, annotations, "spec", "template", "metadata", "annotations"); err != nil {
			return "", err
		}
	}
	annotations := obj.GetAnnotations()
	if annotations == nil {
		annotations = make(map[string]string)
	}
	operationID, err := deterministicCreateOperationID(obj, session)
	if err != nil {
		return "", err
	}
	if persisted := persistedCreateOperationID(obj, session); persisted == operationID {
		operationID = persisted
	}
	if session.UID != "" {
		annotations[sourceSessionUIDAnnotation] = string(session.UID)
	}
	annotations[createOperationIDAnnotation] = operationID
	obj.SetAnnotations(annotations)
	return operationID, nil
}

func deterministicCreateOperationID(obj client.Object, session *breakglassv1alpha1.DebugSession) (string, error) {
	if session == nil {
		return "", fmt.Errorf("cannot stamp create operation without a session")
	}
	desired := obj.DeepCopyObject().(client.Object)
	removeManagedPodSessionUID(desired, string(session.UID))
	annotations := desired.GetAnnotations()
	if annotations != nil {
		annotations = maps.Clone(annotations)
		delete(annotations, createOperationIDAnnotation)
		delete(annotations, sourceSessionUIDAnnotation)
		desired.SetAnnotations(annotations)
	}
	desired.SetUID("")
	desired.SetResourceVersion("")
	desired.SetManagedFields(nil)
	desired.SetCreationTimestamp(metav1.Time{})
	desired.SetGeneration(0)
	desired.SetDeletionTimestamp(nil)
	desired.SetDeletionGracePeriodSeconds(nil)
	desired.SetSelfLink("")
	serialized, err := json.Marshal(desired)
	if err != nil {
		return "", fmt.Errorf("serialize create operation intent: %w", err)
	}
	return uuid.NewSHA1(uuid.Nil, append([]byte(string(session.UID)+"\x00"), serialized...)).String(), nil
}

func recoveredCreateContentMatches(desired, existing client.Object) (bool, error) {
	desiredMap, err := normalizedCreateObjectMap(desired)
	if err != nil {
		return false, fmt.Errorf("serialize desired object: %w", err)
	}
	existingMap, err := normalizedCreateObjectMap(existing)
	if err != nil {
		return false, fmt.Errorf("serialize recovered object: %w", err)
	}
	dropImageVolumesAbsentFrom(desiredMap, existingMap)
	return jsonSubset(desiredMap, existingMap), nil
}

// dropImageVolumesAbsentFrom mirrors the API server, which silently drops
// image volumes and the mounts that reference them when the ImageVolume
// feature is off. A recovered object without any image volume then still
// matches a desired object that carries the session toolbox.
func dropImageVolumesAbsentFrom(desired, existing map[string]interface{}) {
	desiredSpec, existingSpec := createPodSpecMap(desired), createPodSpecMap(existing)
	if desiredSpec == nil || existingSpec == nil {
		return
	}
	hasImage := func(v interface{}) bool {
		volume, ok := v.(map[string]interface{})
		return ok && volume["image"] != nil
	}
	existingVolumes, _ := existingSpec["volumes"].([]interface{})
	if slices.ContainsFunc(existingVolumes, hasImage) {
		return
	}
	desiredVolumes, _ := desiredSpec["volumes"].([]interface{})
	dropped := map[interface{}]bool{}
	kept := make([]interface{}, 0, len(desiredVolumes))
	for _, v := range desiredVolumes {
		if hasImage(v) {
			dropped[v.(map[string]interface{})["name"]] = true
			continue
		}
		kept = append(kept, v)
	}
	if len(dropped) == 0 {
		return
	}
	if len(kept) == 0 {
		delete(desiredSpec, "volumes")
	} else {
		desiredSpec["volumes"] = kept
	}
	for _, field := range []string{"initContainers", "containers", "ephemeralContainers"} {
		containers, _ := desiredSpec[field].([]interface{})
		for _, c := range containers {
			container, ok := c.(map[string]interface{})
			if !ok {
				continue
			}
			mounts, _ := container["volumeMounts"].([]interface{})
			mounts = slices.DeleteFunc(slices.Clone(mounts), func(m interface{}) bool {
				mount, ok := m.(map[string]interface{})
				return ok && dropped[mount["name"]]
			})
			if len(mounts) == 0 {
				delete(container, "volumeMounts")
			} else {
				container["volumeMounts"] = mounts
			}
		}
	}
}

// createPodSpecMap returns the pod spec of a Pod (spec.containers) or of a
// pod-template workload (spec.template.spec). DebugSessions create no
// CronJobs; any other shape returns nil and the comparison stays strict.
func createPodSpecMap(obj map[string]interface{}) map[string]interface{} {
	spec, _ := obj["spec"].(map[string]interface{})
	if spec == nil {
		return nil
	}
	if _, isPod := spec["containers"]; isPod {
		return spec
	}
	template, _ := spec["template"].(map[string]interface{})
	podSpec, _ := template["spec"].(map[string]interface{})
	return podSpec
}

func normalizedCreateObjectMap(obj client.Object) (map[string]interface{}, error) {
	normalized := obj.DeepCopyObject().(client.Object)
	removeManagedPodSessionUID(normalized, obj.GetAnnotations()[sourceSessionUIDAnnotation])
	serialized, err := json.Marshal(normalized)
	if err != nil {
		return nil, err
	}
	var result map[string]interface{}
	if err := json.Unmarshal(serialized, &result); err != nil {
		return nil, err
	}
	delete(result, "status")
	if metadata, ok := result["metadata"].(map[string]interface{}); ok {
		for _, key := range []string{"uid", "resourceVersion", "generation", "creationTimestamp", "deletionTimestamp", "deletionGracePeriodSeconds", "managedFields", "selfLink"} {
			delete(metadata, key)
		}
	}
	return result, nil
}

func managedWorkloadPodMetadata(obj client.Object) *metav1.ObjectMeta {
	switch workload := obj.(type) {
	case *appsv1.Deployment:
		return &workload.Spec.Template.ObjectMeta
	case *appsv1.DaemonSet:
		return &workload.Spec.Template.ObjectMeta
	case *batchv1.Job:
		return &workload.Spec.Template.ObjectMeta
	default:
		return nil
	}
}

// The controller-added marker is not workload intent. Excluding only its
// trusted value preserves create identity across upgrades from unstamped Pods.
func removeManagedPodSessionUID(obj client.Object, uid string) {
	if workload, ok := obj.(*unstructured.Unstructured); ok && isManagedUnstructuredWorkload(workload) {
		annotations := managedPodAnnotations(obj)
		if uid != "" && annotations[sourceSessionUIDAnnotation] == uid {
			delete(annotations, sourceSessionUIDAnnotation)
			if len(annotations) == 0 {
				unstructured.RemoveNestedField(workload.Object, "spec", "template", "metadata", "annotations")
			} else {
				_ = unstructured.SetNestedStringMap(workload.Object, annotations, "spec", "template", "metadata", "annotations")
			}
		}
		return
	}
	if metadata := managedWorkloadPodMetadata(obj); metadata != nil && uid != "" &&
		metadata.Annotations[sourceSessionUIDAnnotation] == uid {
		delete(metadata.Annotations, sourceSessionUIDAnnotation)
	}
}

func isManagedUnstructuredWorkload(obj *unstructured.Unstructured) bool {
	return (obj.GetAPIVersion() == "apps/v1" && (obj.GetKind() == "Deployment" || obj.GetKind() == "DaemonSet")) ||
		(obj.GetAPIVersion() == "batch/v1" && obj.GetKind() == "Job")
}

func managedPodAnnotations(obj client.Object) map[string]string {
	if workload, ok := obj.(*unstructured.Unstructured); ok && isManagedUnstructuredWorkload(workload) {
		annotations, _, _ := unstructured.NestedStringMap(workload.Object, "spec", "template", "metadata", "annotations")
		return annotations
	}
	if metadata := managedWorkloadPodMetadata(obj); metadata != nil {
		return metadata.Annotations
	}
	return nil
}

func jsonSubset(expected, actual interface{}) bool {
	switch expectedValue := expected.(type) {
	case map[string]interface{}:
		actualValue, ok := actual.(map[string]interface{})
		if !ok {
			return false
		}
		for key, value := range expectedValue {
			actualField, ok := actualValue[key]
			if !ok || !jsonSubset(value, actualField) {
				return false
			}
		}
		return true
	case []interface{}:
		actualValue, ok := actual.([]interface{})
		if !ok || len(expectedValue) != len(actualValue) {
			return false
		}
		for i := range expectedValue {
			if !jsonSubset(expectedValue[i], actualValue[i]) {
				return false
			}
		}
		return true
	default:
		return equality.Semantic.DeepEqual(expected, actual)
	}
}

func persistedCreateOperationID(obj client.Object, session *breakglassv1alpha1.DebugSession) string {
	if session == nil {
		return ""
	}
	apiVersion := obj.GetObjectKind().GroupVersionKind().GroupVersion().String()
	kind := obj.GetObjectKind().GroupVersionKind().Kind
	if unstructuredObj, ok := obj.(*unstructured.Unstructured); ok {
		apiVersion = unstructuredObj.GetAPIVersion()
		kind = unstructuredObj.GetKind()
	}
	for _, ref := range session.Status.DeployedResources {
		if ref.APIVersion == apiVersion && ref.Kind == kind && ref.Name == obj.GetName() && ref.Namespace == obj.GetNamespace() {
			return ref.CreateOperationID
		}
	}
	for _, status := range session.Status.PodTemplateResourceStatuses {
		if status.APIVersion == apiVersion && status.Kind == kind && status.ResourceName == obj.GetName() && status.Namespace == obj.GetNamespace() {
			return status.CreateOperationID
		}
	}
	for _, status := range session.Status.AuxiliaryResourceStatuses {
		if status.APIVersion == apiVersion && status.Kind == kind && status.ResourceName == obj.GetName() && status.Namespace == obj.GetNamespace() {
			return status.CreateOperationID
		}
		for _, ref := range status.AdditionalResources {
			if ref.APIVersion == apiVersion && ref.Kind == kind && ref.ResourceName == obj.GetName() && ref.Namespace == obj.GetNamespace() {
				return ref.CreateOperationID
			}
		}
	}
	return ""
}

// A debug container that ignores SIGTERM keeps running for the whole grace
// period of a pending deletion, and the garbage collector does not re-delete
// Pods that are already terminating. Session cleanup therefore shortens the
// pending deletion of the session's Pods (for example after an eviction or a
// delete with a long grace period) to their own terminationGracePeriodSeconds.

// shortenTrackedPodDeletion shortens the pending deletion of the Pod at
// namespace/name if it is still the recorded instance uid.
func shortenTrackedPodDeletion(ctx context.Context, target client.Client, namespace, name, uid string) error {
	pod := &corev1.Pod{}
	if err := target.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, pod); err != nil {
		return client.IgnoreNotFound(err)
	}
	if uid == "" || string(pod.UID) != uid {
		return nil
	}
	return shortenPendingPodDeletion(ctx, target, pod)
}

func podGracePeriod(pod *corev1.Pod) int64 {
	if pod.Spec.TerminationGracePeriodSeconds != nil {
		return *pod.Spec.TerminationGracePeriodSeconds
	}
	return corev1.DefaultTerminationGracePeriodSeconds
}

func podDeletionOutlastsGrace(pod *corev1.Pod) bool {
	return pod.DeletionTimestamp != nil && pod.DeletionGracePeriodSeconds != nil && *pod.DeletionGracePeriodSeconds > podGracePeriod(pod)
}

// shortenPendingPodDeletion deletes pod again with its own grace period if its
// pending deletion is longer. An explicit shorter grace period overrides the
// pending one; the UID precondition leaves a same-name replacement alone.
func shortenPendingPodDeletion(ctx context.Context, target client.Client, pod *corev1.Pod) error {
	if !podDeletionOutlastsGrace(pod) {
		return nil
	}
	uid := pod.UID
	err := target.Delete(ctx, pod, client.Preconditions{UID: &uid}, client.GracePeriodSeconds(podGracePeriod(pod)))
	if err != nil && !apierrors.IsNotFound(err) && !apierrors.IsConflict(err) {
		return fmt.Errorf("shorten pending deletion of pod %s/%s: %w", pod.Namespace, pod.Name, err)
	}
	return nil
}

// podForceDeleteAfter is how long a Pod may stay past its deletion deadline
// before cleanup force-deletes it.
// ponytail: fixed; make it configurable if slow kubelets need more.
const podForceDeleteAfter = 2 * time.Minute

// errDebugPodsTerminating requeues cleanup while session Pods terminate
// within their grace period; like a pending traffic mirror teardown it is
// progress, not a failure.
var errDebugPodsTerminating = errors.New("debug session Pods are terminating")

// cleanupInProgress reports whether a cleanup error only means "wait".
func cleanupInProgress(err error) bool {
	return errors.Is(err, errTrafficMirrorTeardownPending) || errors.Is(err, errDebugPodsTerminating)
}

type podDeletionState int

const (
	podGone podDeletionState = iota
	// podTerminating: still present, within its (shortened) grace period.
	podTerminating
	// podStuck: could not be verified gone, or force-deleted past its
	// deadline; a cleanup residual.
	podStuck
)

// settlePodDeletion moves a verified session Pod towards deletion and reports
// where it is. "Gone" means NotFound or a different UID; a terminating Pod is
// still present. A Pod not yet being deleted is deleted with its own grace
// period, a longer pending deletion is shortened to it, and a Pod still
// terminating podForceDeleteAfter past its (shortened) deletion deadline is
// force-deleted with a zero grace period. Every delete carries a UID
// precondition.
func settlePodDeletion(ctx context.Context, target client.Client, pod *corev1.Pod, now time.Time) (podDeletionState, error) {
	live := &corev1.Pod{}
	if err := target.Get(ctx, client.ObjectKeyFromObject(pod), live); err != nil {
		if apierrors.IsNotFound(err) {
			return podGone, nil
		}
		return podStuck, fmt.Errorf("verify deletion of pod %s/%s: %w", pod.Namespace, pod.Name, err)
	}
	if live.UID != pod.UID {
		return podGone, nil
	}
	uid := live.UID
	switch {
	case podDeletionOutlastsGrace(live):
		if err := shortenPendingPodDeletion(ctx, target, live); err != nil {
			return podStuck, err
		}
		return podTerminating, nil
	case live.DeletionTimestamp == nil:
		err := target.Delete(ctx, live, client.Preconditions{UID: &uid}, client.GracePeriodSeconds(podGracePeriod(live)))
		if err != nil && !apierrors.IsNotFound(err) && !apierrors.IsConflict(err) {
			return podStuck, fmt.Errorf("delete pod %s/%s: %w", pod.Namespace, pod.Name, err)
		}
		return podTerminating, nil
	case now.Before(live.DeletionTimestamp.Add(podForceDeleteAfter)):
		return podTerminating, nil
	}
	// A force delete only removes the API object; on a node that is not Ready
	// the kubelet may keep the containers running. The operator has to fence
	// or recover the node; until the Pod is gone it stays a residual.
	if node := live.Spec.NodeName; node != "" {
		n := &corev1.Node{}
		if err := target.Get(ctx, client.ObjectKey{Name: node}, n); err != nil && !apierrors.IsNotFound(err) {
			return podStuck, fmt.Errorf("read node %s of pod %s/%s: %w", node, pod.Namespace, pod.Name, err)
		} else if err != nil || !nodeReady(n) {
			return podStuck, fmt.Errorf("node-unreachable: %s: pod %s/%s (uid=%s) is still terminating past its deletion deadline", node, pod.Namespace, pod.Name, uid)
		}
	}
	if err := target.Delete(ctx, live, client.Preconditions{UID: &uid}, client.GracePeriodSeconds(0)); err != nil && !apierrors.IsNotFound(err) && !apierrors.IsConflict(err) {
		return podStuck, fmt.Errorf("force-delete pod %s/%s: %w", pod.Namespace, pod.Name, err)
	}
	return podStuck, fmt.Errorf("pod %s/%s (uid=%s) was still terminating %s past its deletion deadline and was force-deleted", pod.Namespace, pod.Name, uid, podForceDeleteAfter)
}

func nodeReady(node *corev1.Node) bool {
	for _, c := range node.Status.Conditions {
		if c.Type == corev1.NodeReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}

// maxTrackedSessionPods bounds the Pods cleanup records in status. Beyond it
// cleanup still deletes the owners but keeps its inventory, failing closed.
// ponytail: fixed; a variable so tests can lower it.
var maxTrackedSessionPods = 256

// podCreatorKinds are the built-in kinds whose Pods cleanup tracks, with the
// intermediate kind between them and their Pods.
var podCreatorKinds = map[string]string{
	"Deployment": "ReplicaSet", "CronJob": "Job",
	"ReplicaSet": "", "ReplicationController": "", "DaemonSet": "", "Job": "", "StatefulSet": "",
}

// controlledBy reports whether obj's controller is one of owners. Only the
// controller reference counts: anyone who may create a Pod can add other
// owner references to it.
func controlledBy(obj metav1.Object, owners []types.UID) bool {
	controller := metav1.GetControllerOfNoCopy(obj)
	return controller != nil && slices.Contains(owners, controller.UID)
}

// sessionPodDiscovery is what discoverSessionPods found.
type sessionPodDiscovery struct {
	pods []corev1.Pod
	// progressing are tracked workloads whose dependents are being torn
	// down; stuck are those with a dependent held past the deadline.
	progressing, stuck []breakglassv1alpha1.DeployedResourceRef
	// intermediates are the ReplicaSets and Jobs between tracked workloads
	// and their Pods, to be recorded so that their Pods stay discoverable
	// after the garbage collector has removed them.
	intermediates []breakglassv1alpha1.DeployedResourceRef
}

// descendants adds the Pods that descend from the tracked workload ref
// through controller references, as the garbage collector sees them, to d.
// An intermediate object deleted more than podForceDeleteAfter ago, for
// example one held by a finalizer, is stuck rather than progress.
func descendants(ctx context.Context, lists *namespaceLists, ref breakglassv1alpha1.DeployedResourceRef, now time.Time, d *sessionPodDiscovery) (progressing, stuck bool, err error) {
	owners := []types.UID{types.UID(ref.UID)}
	var intermediates []client.Object
	apiVersion := "apps/v1"
	if kind := podCreatorKinds[ref.Kind]; kind != "" {
		if kind == "Job" {
			apiVersion = "batch/v1"
		}
		if intermediates, err = lists.get(ctx, ref.Namespace, kind); err != nil {
			return false, false, err
		}
	}
	for _, obj := range intermediates {
		if !controlledBy(obj, owners[:1]) {
			continue
		}
		owners = append(owners, obj.GetUID())
		d.intermediates = append(d.intermediates, breakglassv1alpha1.DeployedResourceRef{APIVersion: apiVersion, Kind: podCreatorKinds[ref.Kind],
			Namespace: obj.GetNamespace(), Name: obj.GetName(), UID: string(obj.GetUID()), Source: "debug-pod"})
		if ts := obj.GetDeletionTimestamp(); ts != nil && now.After(ts.Add(podForceDeleteAfter)) {
			stuck = true
		} else {
			progressing = true
		}
	}
	pods, err := lists.get(ctx, ref.Namespace, "Pod")
	if err != nil {
		return false, false, err
	}
	for _, obj := range pods {
		if controlledBy(obj, owners) {
			d.addPod(*obj.(*corev1.Pod))
			progressing = true // bounded by settlePodDeletion's own deadline
		}
	}
	return progressing && !stuck, stuck, nil
}

// namespaceLists lists Pods, ReplicaSets and Jobs once per namespace and
// sweep, however many tracked references share the namespace.
type namespaceLists struct {
	target client.Client
	cache  map[[2]string][]client.Object
}

func (l *namespaceLists) get(ctx context.Context, namespace, kind string) ([]client.Object, error) {
	key := [2]string{namespace, kind}
	if objs, ok := l.cache[key]; ok {
		return objs, nil
	}
	var list client.ObjectList
	switch kind {
	case "Pod":
		list = &corev1.PodList{}
	case "ReplicaSet":
		list = &appsv1.ReplicaSetList{}
	default:
		list = &batchv1.JobList{}
	}
	if err := l.target.List(ctx, list, client.InNamespace(namespace)); err != nil {
		return nil, fmt.Errorf("list %s in namespace %s: %w", kind, namespace, err)
	}
	items, err := meta.ExtractList(list)
	if err != nil {
		return nil, err
	}
	objs := make([]client.Object, 0, len(items))
	for _, item := range items {
		objs = append(objs, item.(client.Object))
	}
	if l.cache == nil {
		l.cache = map[[2]string][]client.Object{}
	}
	l.cache[key] = objs
	return objs, nil
}

func (d *sessionPodDiscovery) addPod(pod corev1.Pod) {
	if !slices.ContainsFunc(d.pods, func(p corev1.Pod) bool { return p.UID == pod.UID }) {
		d.pods = append(d.pods, pod)
	}
}

// discoverSessionPods finds the session's Pods: those recorded as Pod
// resources, read by name and matched by UID, and those that descend from a
// tracked workload through controller references. Labels are not used:
// without the label reservation policy anyone may set or strip them. Nor is
// status.allowedPods, which also lists application Pods a session only
// injected an ephemeral container into. Intentionally retained resources and
// their descendants are left alone.
func discoverSessionPods(ctx context.Context, target client.Client, refs []breakglassv1alpha1.DeployedResourceRef, retained func(breakglassv1alpha1.DeployedResourceRef) bool) (sessionPodDiscovery, error) {
	now := time.Now()
	lists := &namespaceLists{target: target}
	var d, kept sessionPodDiscovery
	for _, ref := range refs {
		if ref.UID == "" {
			continue
		}
		if retained(ref) {
			if _, creator := podCreatorKinds[ref.Kind]; creator {
				if _, _, err := descendants(ctx, lists, ref, now, &kept); err != nil {
					return d, err
				}
			}
			kept.pods = append(kept.pods, corev1.Pod{ObjectMeta: metav1.ObjectMeta{UID: types.UID(ref.UID)}})
			continue
		}
		if ref.Kind == "Pod" {
			pod := &corev1.Pod{}
			if err := target.Get(ctx, client.ObjectKey{Namespace: ref.Namespace, Name: ref.Name}, pod); err != nil {
				if apierrors.IsNotFound(err) {
					continue
				}
				return d, fmt.Errorf("read recorded pod %s/%s: %w", ref.Namespace, ref.Name, err)
			}
			if string(pod.UID) == ref.UID {
				d.addPod(*pod)
			}
			continue
		}
		if _, creator := podCreatorKinds[ref.Kind]; !creator {
			continue
		}
		progressing, stuck, err := descendants(ctx, lists, ref, now, &d)
		if err != nil {
			return d, err
		}
		if progressing {
			d.progressing = append(d.progressing, ref)
		}
		if stuck {
			d.stuck = append(d.stuck, ref)
		}
	}
	d.pods = slices.DeleteFunc(d.pods, func(p corev1.Pod) bool {
		return slices.ContainsFunc(kept.pods, func(k corev1.Pod) bool { return k.UID == p.UID })
	})
	return d, nil
}

// sameResource compares inventory entries by identity, ignoring how they
// were recorded.
func sameResource(a, b breakglassv1alpha1.DeployedResourceRef) bool {
	return a.Kind == b.Kind && a.Namespace == b.Namespace && a.Name == b.Name && a.UID == b.UID
}

// trackSessionPod returns refs with an entry for pod, reusing an existing
// entry for the same Pod (node-debug Pods are recorded without a source), and
// that entry.
func trackSessionPod(refs []breakglassv1alpha1.DeployedResourceRef, pod *corev1.Pod) ([]breakglassv1alpha1.DeployedResourceRef, breakglassv1alpha1.DeployedResourceRef) {
	ref := breakglassv1alpha1.DeployedResourceRef{APIVersion: "v1", Kind: "Pod", Namespace: pod.Namespace, Name: pod.Name, UID: string(pod.UID), Source: "debug-pod"}
	for _, existing := range refs {
		if sameResource(existing, ref) {
			return refs, existing
		}
	}
	return append(refs, ref), ref
}

func appendDeployedRef(refs []breakglassv1alpha1.DeployedResourceRef, ref breakglassv1alpha1.DeployedResourceRef) []breakglassv1alpha1.DeployedResourceRef {
	if slices.ContainsFunc(refs, func(existing breakglassv1alpha1.DeployedResourceRef) bool { return sameResource(existing, ref) }) {
		return refs
	}
	return append(refs, ref)
}
