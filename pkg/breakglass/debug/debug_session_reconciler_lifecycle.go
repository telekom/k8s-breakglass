package debug

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/api/v1alpha1/applyconfiguration/ssa"
	breakglass "github.com/telekom/k8s-breakglass/pkg/breakglass"
	"github.com/telekom/k8s-breakglass/pkg/cluster"
	"github.com/telekom/k8s-breakglass/pkg/metrics"
	"go.uber.org/zap"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/rest"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

func (c *DebugSessionController) convertDebugPodSpec(dps breakglassv1alpha1.DebugPodSpecInner) corev1.PodSpec {
	spec := corev1.PodSpec{
		Containers:                dps.Containers,
		InitContainers:            dps.InitContainers,
		Volumes:                   dps.Volumes,
		Tolerations:               dps.Tolerations,
		Affinity:                  dps.Affinity,
		NodeSelector:              dps.NodeSelector,
		HostNetwork:               dps.HostNetwork,
		HostPID:                   dps.HostPID,
		HostIPC:                   dps.HostIPC,
		DNSPolicy:                 dps.DNSPolicy,
		DNSConfig:                 dps.DNSConfig,
		RestartPolicy:             dps.RestartPolicy,
		TopologySpreadConstraints: dps.TopologySpreadConstraints,
		HostAliases:               dps.HostAliases,
		ImagePullSecrets:          dps.ImagePullSecrets,
		Overhead:                  dps.Overhead,
	}

	if dps.SecurityContext != nil {
		spec.SecurityContext = dps.SecurityContext
	}
	if dps.AutomountServiceAccountToken != nil {
		spec.AutomountServiceAccountToken = dps.AutomountServiceAccountToken
	}
	if dps.ServiceAccountName != "" {
		spec.ServiceAccountName = dps.ServiceAccountName
	}
	if dps.TerminationGracePeriodSeconds != nil {
		spec.TerminationGracePeriodSeconds = dps.TerminationGracePeriodSeconds
	}
	if dps.PriorityClassName != "" {
		spec.PriorityClassName = dps.PriorityClassName
	}
	if dps.RuntimeClassName != nil {
		spec.RuntimeClassName = dps.RuntimeClassName
	}
	if dps.PreemptionPolicy != nil {
		spec.PreemptionPolicy = dps.PreemptionPolicy
	}
	if dps.ShareProcessNamespace != nil {
		spec.ShareProcessNamespace = dps.ShareProcessNamespace
	}
	if dps.EnableServiceLinks != nil {
		spec.EnableServiceLinks = dps.EnableServiceLinks
	}
	if dps.SchedulerName != "" {
		spec.SchedulerName = dps.SchedulerName
	}

	return spec
}

// updateAllowedPods updates the list of pods users can exec into and monitors pod health
func (c *DebugSessionController) updateAllowedPods(ctx context.Context, ds *breakglassv1alpha1.DebugSession) error {
	if c.ccProvider == nil {
		return nil
	}

	log := c.log.With("debugSession", ds.Name, "namespace", ds.Namespace, "cluster", ds.Spec.Cluster)

	restCfg, err := c.ccProvider.GetRESTConfig(ctx, ds.Spec.Cluster)
	if err != nil {
		return err
	}
	targetClient, err := ctrlclient.New(restCfg, ctrlclient.Options{})
	if err != nil {
		return err
	}

	// List pods with debug session label
	podList := &corev1.PodList{}
	labelSelector := labels.SelectorFromSet(map[string]string{
		DebugSessionLabelKey: ds.Name,
	})
	if err := targetClient.List(ctx, podList, &ctrlclient.ListOptions{
		LabelSelector: labelSelector,
	}); err != nil {
		return err
	}

	allowedPods := make([]breakglassv1alpha1.AllowedPodRef, 0, len(podList.Items))
	for _, pod := range podList.Items {
		ready := false
		for _, cond := range pod.Status.Conditions {
			if cond.Type == corev1.PodReady && cond.Status == corev1.ConditionTrue {
				ready = true
				break
			}
		}

		// Monitor pod phase for failures
		c.monitorPodHealth(ctx, ds, &pod, log)

		// Build container status for detailed information
		containerStatus := buildContainerStatus(&pod)

		allowedPods = append(allowedPods, breakglassv1alpha1.AllowedPodRef{
			Namespace:       pod.Namespace,
			Name:            pod.Name,
			NodeName:        pod.Spec.NodeName,
			Ready:           ready,
			Phase:           string(pod.Status.Phase),
			ContainerStatus: containerStatus,
		})
	}

	ds.Status.AllowedPods = allowedPods
	return breakglass.ApplyDebugSessionStatus(ctx, c.client, ds)
}

// monitorPodHealth checks pod status and emits audit events for failures/restarts
func (c *DebugSessionController) monitorPodHealth(ctx context.Context, ds *breakglassv1alpha1.DebugSession, pod *corev1.Pod, log *zap.SugaredLogger) {
	// Check for pod phase failures
	if pod.Status.Phase == corev1.PodFailed {
		reason := pod.Status.Reason
		message := pod.Status.Message
		if reason == "" {
			reason = "Unknown"
		}
		if message == "" {
			message = "Pod failed without message"
		}

		log.Warnw("Debug session pod failed",
			"pod", pod.Name,
			"podNamespace", pod.Namespace,
			"reason", reason,
			"message", message,
			"node", pod.Spec.NodeName,
		)

		if c.shouldEmitAudit(ds) && c.auditManager != nil {
			c.auditManager.DebugSessionPodFailed(ctx, ds.Name, ds.Namespace, pod.Name, pod.Namespace, reason, message)
			c.sendToWebhookDestinations(ctx, ds, "DebugSessionPodFailed", map[string]interface{}{
				"pod":       pod.Name,
				"namespace": pod.Namespace,
				"reason":    reason,
				"message":   message,
			})
		}
		metrics.DebugSessionPodFailures.WithLabelValues(ds.Spec.Cluster, ds.Name, reason).Inc()
	}

	// Check container statuses for restarts and failures
	for _, cs := range pod.Status.ContainerStatuses {
		// Check for container restarts
		if cs.RestartCount > 0 {
			lastTerminationReason := ""
			if cs.LastTerminationState.Terminated != nil {
				lastTerminationReason = cs.LastTerminationState.Terminated.Reason
				if lastTerminationReason == "" {
					lastTerminationReason = fmt.Sprintf("ExitCode=%d", cs.LastTerminationState.Terminated.ExitCode)
				}
			}

			log.Warnw("Debug session container has restarted",
				"pod", pod.Name,
				"podNamespace", pod.Namespace,
				"container", cs.Name,
				"restartCount", cs.RestartCount,
				"lastTerminationReason", lastTerminationReason,
			)

			if c.shouldEmitAudit(ds) && c.auditManager != nil {
				c.auditManager.DebugSessionPodRestarted(ctx, ds.Name, ds.Namespace, pod.Name, pod.Namespace, cs.RestartCount, lastTerminationReason)
				c.sendToWebhookDestinations(ctx, ds, "DebugSessionPodRestarted", map[string]interface{}{
					"pod":                   pod.Name,
					"namespace":             pod.Namespace,
					"container":             cs.Name,
					"restartCount":          cs.RestartCount,
					"lastTerminationReason": lastTerminationReason,
				})
			}
			metrics.DebugSessionPodRestarts.WithLabelValues(ds.Spec.Cluster, ds.Name).Inc()
		}

		// Check for waiting state issues (CrashLoopBackOff, ImagePullBackOff, etc.)
		if cs.State.Waiting != nil {
			waitingReason := cs.State.Waiting.Reason
			waitingMessage := cs.State.Waiting.Message

			// Log significant waiting states
			if waitingReason == "CrashLoopBackOff" ||
				waitingReason == "ImagePullBackOff" ||
				waitingReason == "ErrImagePull" ||
				waitingReason == "CreateContainerConfigError" ||
				waitingReason == "CreateContainerError" {
				log.Warnw("Debug session container in problematic waiting state",
					"pod", pod.Name,
					"podNamespace", pod.Namespace,
					"container", cs.Name,
					"waitingReason", waitingReason,
					"waitingMessage", waitingMessage,
				)

				if c.shouldEmitAudit(ds) && c.auditManager != nil {
					c.auditManager.DebugSessionPodFailed(ctx, ds.Name, ds.Namespace, pod.Name, pod.Namespace, waitingReason, waitingMessage)
					c.sendToWebhookDestinations(ctx, ds, "DebugSessionPodFailed", map[string]interface{}{
						"pod":       pod.Name,
						"namespace": pod.Namespace,
						"container": cs.Name,
						"reason":    waitingReason,
						"message":   waitingMessage,
					})
				}
				metrics.DebugSessionPodFailures.WithLabelValues(ds.Spec.Cluster, ds.Name, waitingReason).Inc()
			}
		}
	}
}

// buildContainerStatus extracts detailed container state information from a pod
func buildContainerStatus(pod *corev1.Pod) *breakglassv1alpha1.PodContainerStatus {
	if len(pod.Status.ContainerStatuses) == 0 {
		return nil
	}

	// Look for the most interesting container status (one with problems)
	var status *breakglassv1alpha1.PodContainerStatus
	for _, cs := range pod.Status.ContainerStatuses {
		// Check for waiting state issues
		if cs.State.Waiting != nil {
			waitingReason := cs.State.Waiting.Reason
			// Prioritize problematic waiting states
			if waitingReason == "CrashLoopBackOff" ||
				waitingReason == "ImagePullBackOff" ||
				waitingReason == "ErrImagePull" ||
				waitingReason == "CreateContainerConfigError" ||
				waitingReason == "CreateContainerError" ||
				waitingReason == "ContainerCreating" {
				status = &breakglassv1alpha1.PodContainerStatus{
					WaitingReason:  waitingReason,
					WaitingMessage: cs.State.Waiting.Message,
					RestartCount:   cs.RestartCount,
				}
				// Get last termination reason if available
				if cs.LastTerminationState.Terminated != nil {
					status.LastTerminationReason = cs.LastTerminationState.Terminated.Reason
					if status.LastTerminationReason == "" {
						status.LastTerminationReason = fmt.Sprintf("ExitCode=%d", cs.LastTerminationState.Terminated.ExitCode)
					}
				}
				// CrashLoopBackOff is most important, return immediately
				if waitingReason == "CrashLoopBackOff" {
					return status
				}
			}
		}

		// Track restart counts even for running containers
		if cs.RestartCount > 0 && status == nil {
			status = &breakglassv1alpha1.PodContainerStatus{
				RestartCount: cs.RestartCount,
			}
			if cs.LastTerminationState.Terminated != nil {
				status.LastTerminationReason = cs.LastTerminationState.Terminated.Reason
				if status.LastTerminationReason == "" {
					status.LastTerminationReason = fmt.Sprintf("ExitCode=%d", cs.LastTerminationState.Terminated.ExitCode)
				}
			}
		}
	}

	return status
}

// cleanupResources removes deployed resources from the target cluster
func (c *DebugSessionController) cleanupResources(ctx context.Context, ds *breakglassv1alpha1.DebugSession) error {
	log := c.log.With("debugSession", ds.Name, "cluster", ds.Spec.Cluster)

	if c.ccProvider == nil {
		return nil
	}

	// Clean up kubectl-debug resources (if any)
	kubectlHandler := NewKubectlDebugHandler(c.client, &clusterClientAdapter{ccProvider: c.ccProvider})
	if err := kubectlHandler.CleanupKubectlDebugResources(ctx, ds); err != nil {
		// Check if the error is due to missing ClusterConfig - if so, treat as cleanup complete
		if errors.Is(err, cluster.ErrClusterConfigNotFound) {
			log.Warnw("ClusterConfig no longer exists, treating cleanup as complete (orphaned session)",
				"cluster", ds.Spec.Cluster)
			// Clear deployed resources since we can't clean them up anyway
			ds.Status.DeployedResources = nil
			ds.Status.AllowedPods = nil
			return breakglass.ApplyDebugSessionStatus(ctx, c.client, ds)
		}
		log.Errorw("Failed to cleanup kubectl-debug resources", "error", err)
		// Continue to clean up deployed resources even if this fails
	}

	// Get spoke cluster client for cleanup
	restCfg, err := c.ccProvider.GetRESTConfig(ctx, ds.Spec.Cluster)
	if err != nil {
		// Check if the error is due to missing ClusterConfig - if so, treat as cleanup complete
		if errors.Is(err, cluster.ErrClusterConfigNotFound) {
			log.Warnw("ClusterConfig no longer exists, treating cleanup as complete (orphaned session)",
				"cluster", ds.Spec.Cluster)
			// Clear deployed resources since we can't clean them up anyway
			ds.Status.DeployedResources = nil
			ds.Status.AllowedPods = nil
			return breakglass.ApplyDebugSessionStatus(ctx, c.client, ds)
		}
		return fmt.Errorf("failed to get REST config: %w", err)
	}
	targetClient, err := ctrlclient.New(restCfg, ctrlclient.Options{})
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}

	// Cleanup auxiliary resources first using the manager
	if c.auxiliaryMgr != nil && len(ds.Status.AuxiliaryResourceStatuses) > 0 {
		if err := c.auxiliaryMgr.CleanupAuxiliaryResources(ctx, ds, targetClient); err != nil {
			log.Warnw("Failed to cleanup auxiliary resources", "error", err)
			// Continue to clean up main workloads
		}
	}

	// Cleanup pod template resources (from multi-doc pod templates)
	if len(ds.Status.PodTemplateResourceStatuses) > 0 {
		if err := c.cleanupPodTemplateResources(ctx, ds, targetClient); err != nil {
			log.Warnw("Failed to cleanup pod template resources", "error", err)
			// Continue to clean up main workloads
		}
	}

	if len(ds.Status.DeployedResources) == 0 {
		// Persist any status changes from auxiliary/pod-template cleanup above
		return breakglass.ApplyDebugSessionStatus(ctx, c.client, ds)
	}

	// Cleanup main workloads (DaemonSet/Deployment)
	for _, ref := range ds.Status.DeployedResources {
		// Skip auxiliary resources - already cleaned up by manager
		if strings.HasPrefix(ref.Source, "auxiliary:") {
			continue
		}
		// Skip pod-template resources - already cleaned up above
		if ref.Source == "pod-template" {
			continue
		}

		var obj ctrlclient.Object

		switch ref.Kind {
		case "DaemonSet":
			obj = &appsv1.DaemonSet{
				ObjectMeta: metav1.ObjectMeta{
					Name:      ref.Name,
					Namespace: ref.Namespace,
				},
			}
		case "Deployment":
			obj = &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Name:      ref.Name,
					Namespace: ref.Namespace,
				},
			}
		case "ResourceQuota":
			obj = &corev1.ResourceQuota{
				ObjectMeta: metav1.ObjectMeta{
					Name:      ref.Name,
					Namespace: ref.Namespace,
				},
			}
		case "PodDisruptionBudget":
			obj = &policyv1.PodDisruptionBudget{
				ObjectMeta: metav1.ObjectMeta{
					Name:      ref.Name,
					Namespace: ref.Namespace,
				},
			}
		default:
			log.Warnw("Unknown resource type, skipping cleanup", "kind", ref.Kind, "name", ref.Name)
			continue
		}

		if err := targetClient.Delete(ctx, obj); err != nil && !apierrors.IsNotFound(err) {
			log.Warnw("Failed to delete debug resource", "kind", ref.Kind, "name", ref.Name, "error", err)
		} else {
			log.Infow("Deleted debug resource", "kind", ref.Kind, "name", ref.Name)
		}
	}

	// Clear deployed resources from status
	ds.Status.DeployedResources = nil
	ds.Status.AllowedPods = nil
	ds.Status.PodTemplateResourceStatuses = nil
	return breakglass.ApplyDebugSessionStatus(ctx, c.client, ds)
}

// cleanupPodTemplateResources removes resources deployed from multi-document pod templates.
func (c *DebugSessionController) cleanupPodTemplateResources(ctx context.Context, ds *breakglassv1alpha1.DebugSession, targetClient ctrlclient.Client) error {
	log := c.log.With("debugSession", ds.Name, "cluster", ds.Spec.Cluster)

	for i := range ds.Status.PodTemplateResourceStatuses {
		status := &ds.Status.PodTemplateResourceStatuses[i]

		// Skip if already deleted
		if status.Deleted {
			continue
		}

		// Skip if not created
		if !status.Created {
			continue
		}

		// Create unstructured object for deletion
		gvk, err := parseGVK(status.APIVersion, status.Kind)
		if err != nil {
			log.Warnw("Failed to parse GVK for pod template resource",
				"apiVersion", status.APIVersion,
				"kind", status.Kind,
				"error", err)
			status.Error = fmt.Sprintf("failed to parse GVK: %v", err)
			continue
		}

		obj := &unstructured.Unstructured{}
		obj.SetGroupVersionKind(gvk)
		obj.SetName(status.ResourceName)
		obj.SetNamespace(status.Namespace)

		if err := targetClient.Delete(ctx, obj); err != nil {
			if apierrors.IsNotFound(err) {
				log.Debugw("Pod template resource already deleted",
					"kind", status.Kind,
					"name", status.ResourceName)
			} else {
				log.Warnw("Failed to delete pod template resource",
					"kind", status.Kind,
					"name", status.ResourceName,
					"error", err)
				status.Error = fmt.Sprintf("delete failed: %v", err)
				continue
			}
		} else {
			log.Infow("Deleted pod template resource",
				"kind", status.Kind,
				"name", status.ResourceName,
				"namespace", status.Namespace)
		}

		status.Deleted = true
		now := time.Now().UTC().Format(time.RFC3339)
		status.DeletedAt = &now
	}

	return nil
}

// parseDuration parses the requested duration with template constraints.
// Supports day units (e.g., "1d", "7d") in addition to standard Go duration units.
func (c *DebugSessionController) parseDuration(requested string, constraints *breakglassv1alpha1.DebugSessionConstraints) time.Duration {
	defaultDur := time.Hour
	maxDur := 4 * time.Hour

	if constraints != nil {
		if d, err := breakglassv1alpha1.ParseDuration(constraints.DefaultDuration); err == nil {
			defaultDur = d
		}
		if d, err := breakglassv1alpha1.ParseDuration(constraints.MaxDuration); err == nil {
			maxDur = d
		}
	}

	if requested == "" {
		return defaultDur
	}

	dur, err := breakglassv1alpha1.ParseDuration(requested)
	if err != nil {
		return defaultDur
	}

	if dur > maxDur {
		return maxDur
	}
	return dur
}

// setupTerminalSharing configures terminal sharing status for the session
func (c *DebugSessionController) setupTerminalSharing(ds *breakglassv1alpha1.DebugSession, template *breakglassv1alpha1.DebugSessionTemplate) *breakglassv1alpha1.TerminalSharingStatus {
	if template.Spec.TerminalSharing == nil || !template.Spec.TerminalSharing.Enabled {
		return nil
	}

	provider := template.Spec.TerminalSharing.Provider
	if provider == "" {
		provider = "tmux"
	}

	// Generate a unique session name
	sessionName := ds.Name
	if len(sessionName) > 32 {
		sessionName = sessionName[:32]
	}

	// Build attach command based on provider
	var attachCommand string
	switch provider {
	case "tmux":
		attachCommand = fmt.Sprintf("tmux attach-session -t %s", sessionName)
	case "screen":
		attachCommand = fmt.Sprintf("screen -x %s", sessionName)
	default:
		attachCommand = fmt.Sprintf("tmux attach-session -t %s", sessionName)
	}

	c.log.Infow("Terminal sharing configured",
		"debugSession", ds.Name,
		"provider", provider,
		"sessionName", sessionName)

	return &breakglassv1alpha1.TerminalSharingStatus{
		Enabled:       true,
		SessionName:   sessionName,
		AttachCommand: attachCommand,
	}
}

// IsPodInDebugSession checks if a pod belongs to an active debug session
func IsPodInDebugSession(namespace, name string, allowedPods []breakglassv1alpha1.AllowedPodRef) bool {
	for _, pod := range allowedPods {
		if pod.Namespace == namespace && pod.Name == name {
			return true
		}
	}
	return false
}

// updateTemplateStatus updates the DebugSessionTemplate and DebugPodTemplate status
// to reflect active session counts and usage tracking.
// incrementActive: true when activating a session, false when deactivating (cleanup/expiry)
func (c *DebugSessionController) updateTemplateStatus(ctx context.Context, template *breakglassv1alpha1.DebugSessionTemplate, incrementActive bool) error {
	log := c.log.With("template", template.Name)

	// Re-fetch template to get latest version
	currentTemplate := &breakglassv1alpha1.DebugSessionTemplate{}
	if err := c.client.Get(ctx, ctrlclient.ObjectKey{Name: template.Name}, currentTemplate); err != nil {
		return fmt.Errorf("failed to get template: %w", err)
	}

	// Update active session count
	if incrementActive {
		currentTemplate.Status.ActiveSessionCount++
		now := metav1.Now()
		currentTemplate.Status.LastUsedAt = &now
	} else {
		if currentTemplate.Status.ActiveSessionCount > 0 {
			currentTemplate.Status.ActiveSessionCount--
		}
	}

	// Update the template status using SSA
	if err := ssa.ApplyDebugSessionTemplateStatus(ctx, c.client, currentTemplate); err != nil {
		return fmt.Errorf("failed to update template status: %w", err)
	}

	log.Debugw("Updated template status",
		"activeSessionCount", currentTemplate.Status.ActiveSessionCount,
		"lastUsedAt", currentTemplate.Status.LastUsedAt,
		"incrementActive", incrementActive)

	// Also update the DebugPodTemplate.status.usedBy if a pod template is referenced
	if currentTemplate.Spec.PodTemplateRef != nil && currentTemplate.Spec.PodTemplateRef.Name != "" {
		if err := c.updatePodTemplateUsedBy(ctx, currentTemplate.Spec.PodTemplateRef.Name, template.Name); err != nil {
			log.Warnw("Failed to update pod template usedBy", "podTemplate", currentTemplate.Spec.PodTemplateRef.Name, "error", err)
			// Non-fatal
		}
	}

	return nil
}

// updatePodTemplateUsedBy ensures the DebugPodTemplate.status.usedBy list includes
// the given DebugSessionTemplate name.
func (c *DebugSessionController) updatePodTemplateUsedBy(ctx context.Context, podTemplateName, sessionTemplateName string) error {
	podTemplate := &breakglassv1alpha1.DebugPodTemplate{}
	if err := c.client.Get(ctx, ctrlclient.ObjectKey{Name: podTemplateName}, podTemplate); err != nil {
		return fmt.Errorf("failed to get pod template: %w", err)
	}

	// Check if already in usedBy list
	for _, name := range podTemplate.Status.UsedBy {
		if name == sessionTemplateName {
			return nil // Already tracked
		}
	}

	// Add to usedBy list
	podTemplate.Status.UsedBy = append(podTemplate.Status.UsedBy, sessionTemplateName)

	// Update using SSA
	if err := ssa.ApplyDebugPodTemplateStatus(ctx, c.client, podTemplate); err != nil {
		return fmt.Errorf("failed to update pod template status: %w", err)
	}

	c.log.Debugw("Updated pod template usedBy",
		"podTemplate", podTemplateName,
		"addedSessionTemplate", sessionTemplateName,
		"usedBy", podTemplate.Status.UsedBy)

	return nil
}

// Ensure DebugSessionController is a valid interface type
var _ interface {
	GetRESTConfig(ctx context.Context, name string) (*rest.Config, error)
} = (*cluster.ClientProvider)(nil)
