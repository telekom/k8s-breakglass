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

package breakglass

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/utils"
)

// KubectlDebugHandler handles kubectl-debug mode operations
type KubectlDebugHandler struct {
	client     ctrlclient.Client
	ccProvider ClientProviderInterface
}

// ClientProviderInterface abstracts the cluster.ClientProvider for testing
type ClientProviderInterface interface {
	GetClient(ctx context.Context, clusterName string) (ctrlclient.Client, error)
}

// NewKubectlDebugHandler creates a new kubectl debug handler
func NewKubectlDebugHandler(client ctrlclient.Client, ccProvider ClientProviderInterface) *KubectlDebugHandler {
	return &KubectlDebugHandler{
		client:     client,
		ccProvider: ccProvider,
	}
}

// FindActiveSession finds an active debug session for the user/cluster
func (h *KubectlDebugHandler) FindActiveSession(ctx context.Context, user, cluster string) (*v1alpha1.DebugSession, error) {
	var list v1alpha1.DebugSessionList
	// TODO: Add field selector for performance in future - NOT IMPLEMENTED (requires indexer setup)
	if err := h.client.List(ctx, &list); err != nil {
		return nil, err
	}

	for _, ds := range list.Items {
		// If cluster is specified, filter by it
		if cluster != "" && ds.Spec.Cluster != cluster {
			continue
		}
		if ds.Status.State != v1alpha1.DebugSessionStateActive {
			continue
		}
		// Check expiration just in case status is stale
		if ds.Status.ExpiresAt != nil && time.Now().After(ds.Status.ExpiresAt.Time) {
			continue
		}

		// Check if user is a participant
		for _, p := range ds.Status.Participants {
			if p.User == user {
				return &ds, nil
			}
		}
	}
	return nil, nil
}

// ValidateEphemeralContainerRequest validates an ephemeral container injection request
func (h *KubectlDebugHandler) ValidateEphemeralContainerRequest(
	ctx context.Context,
	ds *v1alpha1.DebugSession,
	namespace, podName, image string,
	capabilities []string,
	runAsNonRoot bool,
) error {
	template := ds.Status.ResolvedTemplate
	if template == nil {
		return fmt.Errorf("no resolved template in session")
	}

	if template.KubectlDebug == nil || template.KubectlDebug.EphemeralContainers == nil {
		return fmt.Errorf("ephemeral containers not configured in template")
	}

	ec := template.KubectlDebug.EphemeralContainers
	if !ec.Enabled {
		return fmt.Errorf("ephemeral containers are not enabled for this template")
	}

	// Validate namespace
	if !h.isNamespaceAllowed(namespace, ec.AllowedNamespaces, ec.DeniedNamespaces) {
		return fmt.Errorf("namespace %s is not allowed for ephemeral container injection", namespace)
	}

	// Validate image
	if !h.isImageAllowed(image, ec.AllowedImages) {
		return fmt.Errorf("image %s is not in the allowed list", image)
	}

	// Validate image digest if required
	if ec.RequireImageDigest && !h.hasImageDigest(image) {
		return fmt.Errorf("image must use @sha256: digest")
	}

	// Validate capabilities
	for _, cap := range capabilities {
		if !h.isCapabilityAllowed(cap, ec.MaxCapabilities) {
			return fmt.Errorf("capability %s is not allowed", cap)
		}
	}

	// Validate non-root
	if ec.RequireNonRoot && !runAsNonRoot {
		return fmt.Errorf("ephemeral container must run as non-root")
	}

	return nil
}

// InjectEphemeralContainer injects an ephemeral debug container into a pod
func (h *KubectlDebugHandler) InjectEphemeralContainer(
	ctx context.Context,
	ds *v1alpha1.DebugSession,
	namespace, podName, containerName, image string,
	command []string,
	securityContext *corev1.SecurityContext,
	user string,
) error {
	// Get target cluster client
	targetClient, err := h.ccProvider.GetClient(ctx, ds.Spec.Cluster)
	if err != nil {
		return fmt.Errorf("failed to get client for cluster %s: %w", ds.Spec.Cluster, err)
	}

	// Get the target pod
	pod := &corev1.Pod{}
	if err := targetClient.Get(ctx, ctrlclient.ObjectKey{Namespace: namespace, Name: podName}, pod); err != nil {
		return fmt.Errorf("failed to get pod %s/%s: %w", namespace, podName, err)
	}

	// Check if container name already exists
	for _, ec := range pod.Spec.EphemeralContainers {
		if ec.Name == containerName {
			return fmt.Errorf("ephemeral container %s already exists in pod", containerName)
		}
	}

	// Create ephemeral container spec
	ephemeralContainer := corev1.EphemeralContainer{
		EphemeralContainerCommon: corev1.EphemeralContainerCommon{
			Name:            containerName,
			Image:           image,
			Command:         command,
			ImagePullPolicy: corev1.PullIfNotPresent,
			TTY:             true,
			Stdin:           true,
		},
	}

	if securityContext != nil {
		ephemeralContainer.SecurityContext = securityContext
	}

	// Add the ephemeral container
	pod.Spec.EphemeralContainers = append(pod.Spec.EphemeralContainers, ephemeralContainer)

	// Update the pod using SubResource for ephemeral containers
	if err := targetClient.SubResource("ephemeralcontainers").Update(ctx, pod); err != nil {
		return fmt.Errorf("failed to inject ephemeral container: %w", err)
	}

	// Track the injected container in session status
	now := metav1.Now()
	if ds.Status.KubectlDebugStatus == nil {
		ds.Status.KubectlDebugStatus = &v1alpha1.KubectlDebugStatus{}
	}

	ds.Status.KubectlDebugStatus.EphemeralContainersInjected = append(
		ds.Status.KubectlDebugStatus.EphemeralContainersInjected,
		v1alpha1.EphemeralContainerRef{
			PodName:       podName,
			Namespace:     namespace,
			ContainerName: containerName,
			Image:         image,
			InjectedAt:    now,
			InjectedBy:    user,
		},
	)

	// Also add to allowed pods if not already present
	podAlreadyAllowed := false
	for _, p := range ds.Status.AllowedPods {
		if p.Namespace == namespace && p.Name == podName {
			podAlreadyAllowed = true
			break
		}
	}
	if !podAlreadyAllowed {
		ds.Status.AllowedPods = append(ds.Status.AllowedPods, v1alpha1.AllowedPodRef{
			Namespace: namespace,
			Name:      podName,
			Ready:     true,
		})
	}

	return h.client.Status().Update(ctx, ds)
}

// CreatePodCopy creates a debug copy of a pod
func (h *KubectlDebugHandler) CreatePodCopy(
	ctx context.Context,
	ds *v1alpha1.DebugSession,
	originalNamespace, originalPodName string,
	debugImage string,
	user string,
) (*corev1.Pod, error) {
	template := ds.Status.ResolvedTemplate
	if template == nil || template.KubectlDebug == nil || template.KubectlDebug.PodCopy == nil {
		return nil, fmt.Errorf("pod copy not configured in template")
	}

	pc := template.KubectlDebug.PodCopy
	if !pc.Enabled {
		return nil, fmt.Errorf("pod copy is not enabled for this template")
	}

	// Get target cluster client
	targetClient, err := h.ccProvider.GetClient(ctx, ds.Spec.Cluster)
	if err != nil {
		return nil, fmt.Errorf("failed to get client for cluster %s: %w", ds.Spec.Cluster, err)
	}

	// Get the original pod
	originalPod := &corev1.Pod{}
	if err := targetClient.Get(ctx, ctrlclient.ObjectKey{Namespace: originalNamespace, Name: originalPodName}, originalPod); err != nil {
		return nil, fmt.Errorf("failed to get pod %s/%s: %w", originalNamespace, originalPodName, err)
	}

	// Determine target namespace
	targetNs := pc.TargetNamespace
	if targetNs == "" {
		targetNs = "debug-copies"
	}

	// Ensure target namespace exists
	ns := &corev1.Namespace{}
	if err := targetClient.Get(ctx, ctrlclient.ObjectKey{Name: targetNs}, ns); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, fmt.Errorf("target namespace %s does not exist", targetNs)
		}
		return nil, fmt.Errorf("failed to check namespace: %w", err)
	}

	// Create copy name
	copyName := fmt.Sprintf("debug-copy-%s-%s", originalPodName, ds.Name[:8])
	if len(copyName) > 63 {
		copyName = copyName[:63]
	}

	// Build the copy pod spec
	copyPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      copyName,
			Namespace: targetNs,
			Labels: map[string]string{
				DebugSessionLabelKey:                 ds.Name,
				"breakglass.telekom.com/debug-copy":  "true",
				"breakglass.telekom.com/original":    originalPodName,
				"breakglass.telekom.com/original-ns": originalNamespace,
			},
		},
		Spec: *originalPod.Spec.DeepCopy(),
	}

	// Add custom labels from config
	for k, v := range pc.Labels {
		copyPod.Labels[k] = v
	}

	// Modify for debugging
	copyPod.Spec.RestartPolicy = corev1.RestartPolicyNever

	// Add debug container if image specified
	if debugImage != "" {
		debugContainer := corev1.Container{
			Name:    "debugger",
			Image:   debugImage,
			Command: []string{"sleep", "infinity"},
			TTY:     true,
			Stdin:   true,
		}
		copyPod.Spec.Containers = append(copyPod.Spec.Containers, debugContainer)
	}

	// Reset status-related fields
	copyPod.Spec.NodeName = ""
	copyPod.ResourceVersion = ""
	copyPod.UID = ""

	// Create the copy pod
	if err := targetClient.Create(ctx, copyPod); err != nil {
		return nil, fmt.Errorf("failed to create pod copy: %w", err)
	}

	// Calculate expiry
	ttl := pc.TTL
	if ttl == "" {
		ttl = "2h"
	}
	ttlDuration, err := time.ParseDuration(ttl)
	if err != nil {
		ttlDuration = 2 * time.Hour
	}
	expiresAt := metav1.NewTime(time.Now().Add(ttlDuration))

	// Track the copied pod in session status
	now := metav1.Now()
	if ds.Status.KubectlDebugStatus == nil {
		ds.Status.KubectlDebugStatus = &v1alpha1.KubectlDebugStatus{}
	}

	ds.Status.KubectlDebugStatus.CopiedPods = append(
		ds.Status.KubectlDebugStatus.CopiedPods,
		v1alpha1.CopiedPodRef{
			OriginalPod:       originalPodName,
			OriginalNamespace: originalNamespace,
			CopyName:          copyName,
			CopyNamespace:     targetNs,
			CreatedAt:         now,
			ExpiresAt:         &expiresAt,
		},
	)

	// Add to allowed pods
	ds.Status.AllowedPods = append(ds.Status.AllowedPods, v1alpha1.AllowedPodRef{
		Namespace: targetNs,
		Name:      copyName,
		Ready:     false, // Will be updated by reconciler
	})

	if err := h.client.Status().Update(ctx, ds); err != nil {
		return nil, fmt.Errorf("failed to update session status: %w", err)
	}

	return copyPod, nil
}

// CreateNodeDebugPod creates a debug pod on a specific node
func (h *KubectlDebugHandler) CreateNodeDebugPod(
	ctx context.Context,
	ds *v1alpha1.DebugSession,
	nodeName string,
	user string,
) (*corev1.Pod, error) {
	template := ds.Status.ResolvedTemplate
	if template == nil || template.KubectlDebug == nil || template.KubectlDebug.NodeDebug == nil {
		return nil, fmt.Errorf("node debug not configured in template")
	}

	nd := template.KubectlDebug.NodeDebug
	if !nd.Enabled {
		return nil, fmt.Errorf("node debug is not enabled for this template")
	}

	// Validate node selector if configured
	if len(nd.NodeSelector) > 0 {
		// Get target cluster client
		targetClient, err := h.ccProvider.GetClient(ctx, ds.Spec.Cluster)
		if err != nil {
			return nil, fmt.Errorf("failed to get client for cluster %s: %w", ds.Spec.Cluster, err)
		}

		// Get the node
		node := &corev1.Node{}
		if err := targetClient.Get(ctx, ctrlclient.ObjectKey{Name: nodeName}, node); err != nil {
			return nil, fmt.Errorf("failed to get node %s: %w", nodeName, err)
		}

		// Check node selector
		for k, v := range nd.NodeSelector {
			if nodeVal, exists := node.Labels[k]; !exists || nodeVal != v {
				return nil, fmt.Errorf("node %s does not match required selector %s=%s", nodeName, k, v)
			}
		}
	}

	// Determine image
	image := "busybox:stable"
	if len(nd.AllowedImages) > 0 {
		image = nd.AllowedImages[0]
	}

	// Build host namespace config
	hostNetwork := true
	hostPID := true
	hostIPC := false
	if nd.HostNamespaces != nil {
		hostNetwork = nd.HostNamespaces.HostNetwork
		hostPID = nd.HostNamespaces.HostPID
		hostIPC = nd.HostNamespaces.HostIPC
	}

	// Get target cluster client
	targetClient, err := h.ccProvider.GetClient(ctx, ds.Spec.Cluster)
	if err != nil {
		return nil, fmt.Errorf("failed to get client for cluster %s: %w", ds.Spec.Cluster, err)
	}

	// Create the debug pod
	podName := fmt.Sprintf("node-debugger-%s-%s", nodeName, ds.Name[:8])
	if len(podName) > 63 {
		podName = podName[:63]
	}

	// Determine namespace from template or default
	namespace := "breakglass-debug"
	if template.TargetNamespace != "" {
		namespace = template.TargetNamespace
	}

	debugPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      podName,
			Namespace: namespace,
			Labels: map[string]string{
				DebugSessionLabelKey:                  ds.Name,
				"breakglass.telekom.com/node-debug":   "true",
				"breakglass.telekom.com/target-node":  nodeName,
				"breakglass.telekom.com/requested-by": sanitizeLabel(user),
			},
		},
		Spec: corev1.PodSpec{
			NodeName:      nodeName,
			HostNetwork:   hostNetwork,
			HostPID:       hostPID,
			HostIPC:       hostIPC,
			RestartPolicy: corev1.RestartPolicyNever,
			Containers: []corev1.Container{
				{
					Name:    "debugger",
					Image:   image,
					Command: []string{"sleep", "infinity"},
					TTY:     true,
					Stdin:   true,
					SecurityContext: &corev1.SecurityContext{
						Privileged: boolPtr(true),
					},
					VolumeMounts: []corev1.VolumeMount{
						{
							Name:      "host-root",
							MountPath: "/host",
							ReadOnly:  false,
						},
					},
				},
			},
			Volumes: []corev1.Volume{
				{
					Name: "host-root",
					VolumeSource: corev1.VolumeSource{
						HostPath: &corev1.HostPathVolumeSource{
							Path: "/",
						},
					},
				},
			},
			Tolerations: []corev1.Toleration{
				{
					Operator: corev1.TolerationOpExists,
				},
			},
		},
	}

	// Create the pod
	if err := targetClient.Create(ctx, debugPod); err != nil {
		return nil, fmt.Errorf("failed to create node debug pod: %w", err)
	}

	// Add to allowed pods and deployed resources
	ds.Status.AllowedPods = append(ds.Status.AllowedPods, v1alpha1.AllowedPodRef{
		Namespace: namespace,
		Name:      podName,
		NodeName:  nodeName,
		Ready:     false, // Will be updated by reconciler
	})

	ds.Status.DeployedResources = append(ds.Status.DeployedResources, v1alpha1.DeployedResourceRef{
		APIVersion: "v1",
		Kind:       "Pod",
		Name:       podName,
		Namespace:  namespace,
	})

	if err := h.client.Status().Update(ctx, ds); err != nil {
		return nil, fmt.Errorf("failed to update session status: %w", err)
	}

	return debugPod, nil
}

// CleanupKubectlDebugResources cleans up kubectl-debug resources
func (h *KubectlDebugHandler) CleanupKubectlDebugResources(ctx context.Context, ds *v1alpha1.DebugSession) error {
	if ds.Status.KubectlDebugStatus == nil {
		return nil
	}

	targetClient, err := h.ccProvider.GetClient(ctx, ds.Spec.Cluster)
	if err != nil {
		return fmt.Errorf("failed to get client for cluster %s: %w", ds.Spec.Cluster, err)
	}

	// Cleanup copied pods
	for _, cp := range ds.Status.KubectlDebugStatus.CopiedPods {
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      cp.CopyName,
				Namespace: cp.CopyNamespace,
			},
		}
		if err := targetClient.Delete(ctx, pod); err != nil && !apierrors.IsNotFound(err) {
			// Log but continue cleanup
			continue
		}
	}

	// Note: Ephemeral containers cannot be removed, they remain until pod deletion
	// Clear the status
	ds.Status.KubectlDebugStatus = nil

	return h.client.Status().Update(ctx, ds)
}

// Helper functions

func (h *KubectlDebugHandler) isNamespaceAllowed(namespace string, allowed, denied *v1alpha1.NamespaceFilter) bool {
	// Use NamespaceAllowDenyMatcher for combined allow/deny logic
	matcher := utils.NewNamespaceAllowDenyMatcher(allowed, denied)
	return matcher.IsAllowed(namespace)
}

func (h *KubectlDebugHandler) isImageAllowed(image string, allowed []string) bool {
	if len(allowed) == 0 {
		return true // No restrictions
	}

	for _, pattern := range allowed {
		// Handle digest patterns (image@sha256:*)
		if strings.Contains(pattern, "@sha256:*") {
			base := strings.Split(pattern, "@")[0]
			if strings.HasPrefix(image, base+"@sha256:") {
				return true
			}
		}

		// Standard glob matching
		if matched, _ := filepath.Match(pattern, image); matched {
			return true
		}

		// Check if image starts with pattern (for versioned images)
		if strings.HasPrefix(image, strings.TrimSuffix(pattern, "*")) {
			return true
		}
	}

	return false
}

func (h *KubectlDebugHandler) hasImageDigest(image string) bool {
	return strings.Contains(image, "@sha256:")
}

func (h *KubectlDebugHandler) isCapabilityAllowed(cap string, maxCaps []string) bool {
	if len(maxCaps) == 0 {
		return true // No restrictions
	}

	for _, allowed := range maxCaps {
		if strings.EqualFold(cap, allowed) {
			return true
		}
	}

	return false
}

func boolPtr(b bool) *bool {
	return &b
}

func sanitizeLabel(value string) string {
	// Simple sanitization for Kubernetes label values
	// Replace invalid characters with underscore
	result := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			return r
		}
		return '_'
	}, value)

	// Truncate to max label length
	if len(result) > 63 {
		result = result[:63]
	}

	return result
}
