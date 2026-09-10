package debug

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/api/v1alpha1/applyconfiguration/ssa"
	"github.com/telekom/k8s-breakglass/pkg/cluster"
	"github.com/telekom/k8s-breakglass/pkg/metrics"
	"github.com/telekom/k8s-breakglass/pkg/utils"
	"go.uber.org/zap"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/util/retry"
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

	allowedPodCandidates, retainedAllowedPods := c.filterAllowedPodsForRefresh(ctx, targetClient, ds, podList.Items)
	allowedPods := make([]breakglassv1alpha1.AllowedPodRef, 0, len(allowedPodCandidates)+len(retainedAllowedPods))
	// Keep rejected same-name identities in status so later refreshes do not
	// reinterpret the replacement as an untracked Pod.
	allowedPods = append(allowedPods, retainedAllowedPods...)
	for _, pod := range allowedPodCandidates {
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

		allowedPods = append(allowedPods, allowedPodRefFromPod(&pod, ready, containerStatus))
	}

	// Preserve allowed pods for ephemeral containers injected into existing pods
	// (these pods don't have the debug session label)
	if ds.Status.KubectlDebugStatus != nil {
		for _, ec := range ds.Status.KubectlDebugStatus.EphemeralContainersInjected {
			found := false
			for _, ap := range allowedPods {
				if ap.Namespace == ec.Namespace && ap.Name == ec.PodName {
					found = true
					break
				}
			}
			if !found {
				// Find it in the old allowedPods to preserve its state
				for _, oldAP := range ds.Status.AllowedPods {
					if oldAP.Namespace == ec.Namespace && oldAP.Name == ec.PodName && ec.PodUID != "" && oldAP.UID == ec.PodUID {
						allowedPods = append(allowedPods, oldAP)
						break
					}
				}
			}
		}
	}

	ds.Status.AllowedPods = allowedPods
	patchAuxiliaryResourceStatuses := c.auxiliaryMgr != nil && len(ds.Status.AuxiliaryResourceStatuses) > 0
	if err := c.updateAuxiliaryResourceReadiness(ctx, ds, targetClient); err != nil {
		return err
	}
	if patchAuxiliaryResourceStatuses {
		return c.patchDebugSessionAllowedPodsAndAuxiliaryStatuses(ctx, ds, allowedPods, ds.Status.AuxiliaryResourceStatuses)
	}
	return c.patchDebugSessionAllowedPods(ctx, ds, allowedPods)
}

func (c *DebugSessionController) filterAllowedPodsForRefresh(
	ctx context.Context,
	targetClient ctrlclient.Client,
	ds *breakglassv1alpha1.DebugSession,
	pods []corev1.Pod,
) ([]corev1.Pod, []breakglassv1alpha1.AllowedPodRef) {
	allowed := make([]corev1.Pod, 0, len(pods))
	retained := make([]breakglassv1alpha1.AllowedPodRef, 0)
	for _, pod := range pods {
		if !c.allowedPodForRefresh(ctx, targetClient, ds, &pod) {
			if existing, found := existingAllowedPodRef(ds, &pod); found {
				retained = append(retained, existing)
			}
			continue
		}
		allowed = append(allowed, pod)
	}
	return allowed, retained
}

func existingAllowedPodRef(ds *breakglassv1alpha1.DebugSession, pod *corev1.Pod) (breakglassv1alpha1.AllowedPodRef, bool) {
	for _, existing := range ds.Status.AllowedPods {
		if existing.Namespace == pod.Namespace && existing.Name == pod.Name {
			return existing, true
		}
	}
	return breakglassv1alpha1.AllowedPodRef{}, false
}

func (c *DebugSessionController) allowedPodForRefresh(
	ctx context.Context,
	targetClient ctrlclient.Client,
	ds *breakglassv1alpha1.DebugSession,
	pod *corev1.Pod,
) bool {
	existing, known := existingAllowedPodRef(ds, pod)
	if known {
		if existing.UID == string(pod.UID) && existing.UID != "" {
			return true
		}
		if existing.UID == "" || pod.UID == "" {
			return false
		}
		return c.podBelongsToTrackedWorkload(ctx, targetClient, ds, pod)
	}
	return c.podBelongsToTrackedWorkload(ctx, targetClient, ds, pod)
}

func allowedPodRefFromPod(pod *corev1.Pod, ready bool, containerStatus *breakglassv1alpha1.PodContainerStatus) breakglassv1alpha1.AllowedPodRef {
	return breakglassv1alpha1.AllowedPodRef{
		Namespace:       pod.Namespace,
		Name:            pod.Name,
		UID:             string(pod.UID),
		NodeName:        pod.Spec.NodeName,
		Ready:           ready,
		Phase:           string(pod.Status.Phase),
		ContainerStatus: containerStatus,
	}
}

func (c *DebugSessionController) updateAuxiliaryResourceReadiness(
	ctx context.Context,
	ds *breakglassv1alpha1.DebugSession,
	targetClient ctrlclient.Client,
) error {
	if c.auxiliaryMgr == nil || len(ds.Status.AuxiliaryResourceStatuses) == 0 {
		return nil
	}
	_, err := c.auxiliaryMgr.CheckAuxiliaryResourcesReadiness(ctx, ds, targetClient)
	return err
}

func (c *DebugSessionController) podBelongsToTrackedWorkload(ctx context.Context, targetClient ctrlclient.Client, ds *breakglassv1alpha1.DebugSession, pod *corev1.Pod) bool {
	if ds == nil || pod == nil {
		return false
	}
	for _, ref := range ds.Status.DeployedResources {
		if ref.UID == "" || ref.Namespace != pod.Namespace || ref.Source != "debug-pod" {
			continue
		}
		if ref.Kind == "Pod" && ref.Name == pod.Name && ref.UID == string(pod.UID) {
			return true
		}
		owner := metav1.GetControllerOf(pod)
		if owner == nil {
			continue
		}
		switch ref.Kind {
		case "DaemonSet":
			if owner.Kind != "DaemonSet" || owner.Name != ref.Name || string(owner.UID) != ref.UID {
				continue
			}
			workload := &appsv1.DaemonSet{}
			if err := targetClient.Get(ctx, ctrlclient.ObjectKey{Namespace: ref.Namespace, Name: ref.Name}, workload); err != nil || string(workload.UID) != ref.UID {
				continue
			}
			if podMatchesAdmittedWorkloadTemplate(ctx, targetClient, pod, &workload.Spec.Template, true) {
				return true
			}
		case "Deployment":
			if owner.Kind != "ReplicaSet" || owner.APIVersion != "apps/v1" {
				continue
			}
			rs := &appsv1.ReplicaSet{}
			if err := targetClient.Get(ctx, ctrlclient.ObjectKey{Namespace: pod.Namespace, Name: owner.Name}, rs); err != nil || rs.UID != owner.UID {
				continue
			}
			rsOwner := metav1.GetControllerOf(rs)
			if rsOwner == nil || rsOwner.Kind != "Deployment" || rsOwner.Name != ref.Name || string(rsOwner.UID) != ref.UID {
				continue
			}
			workload := &appsv1.Deployment{}
			if err := targetClient.Get(ctx, ctrlclient.ObjectKey{Namespace: ref.Namespace, Name: ref.Name}, workload); err != nil || string(workload.UID) != ref.UID {
				continue
			}
			if !podMatchesWorkloadTemplate(&corev1.Pod{Spec: rs.Spec.Template.Spec}, &workload.Spec.Template, false) {
				continue
			}
			// Only the live Pod from the API list receives admission defaults;
			// the ReplicaSet-to-Deployment template comparison above stays strict.
			if podMatchesAdmittedWorkloadTemplate(ctx, targetClient, pod, &rs.Spec.Template, false) {
				return true
			}
		case "Job":
			if owner.Kind != "Job" || owner.APIVersion != "batch/v1" || owner.Name != ref.Name || string(owner.UID) != ref.UID {
				continue
			}
			job := &batchv1.Job{}
			if err := targetClient.Get(ctx, ctrlclient.ObjectKey{Namespace: ref.Namespace, Name: ref.Name}, job); err != nil || string(job.UID) != ref.UID {
				continue
			}
			if podMatchesAdmittedWorkloadTemplate(ctx, targetClient, pod, &job.Spec.Template, false) {
				return true
			}
		}
	}
	return false
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

		if c.shouldEmitAudit(ds) {
			if auditManager := c.currentAuditManager(); auditManager != nil {
				auditManager.DebugSessionPodFailed(ctx, ds.Name, ds.Namespace, pod.Name, pod.Namespace, reason, message)
				c.sendToWebhookDestinations(ctx, ds, "DebugSessionPodFailed", map[string]interface{}{
					"pod":       pod.Name,
					"namespace": pod.Namespace,
					"reason":    reason,
					"message":   message,
				})
			}
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

			if c.shouldEmitAudit(ds) {
				if auditManager := c.currentAuditManager(); auditManager != nil {
					auditManager.DebugSessionPodRestarted(ctx, ds.Name, ds.Namespace, pod.Name, pod.Namespace, cs.RestartCount, lastTerminationReason)
					c.sendToWebhookDestinations(ctx, ds, "DebugSessionPodRestarted", map[string]interface{}{
						"pod":                   pod.Name,
						"namespace":             pod.Namespace,
						"container":             cs.Name,
						"restartCount":          cs.RestartCount,
						"lastTerminationReason": lastTerminationReason,
					})
				}
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

				if c.shouldEmitAudit(ds) {
					if auditManager := c.currentAuditManager(); auditManager != nil {
						auditManager.DebugSessionPodFailed(ctx, ds.Name, ds.Namespace, pod.Name, pod.Namespace, waitingReason, waitingMessage)
						c.sendToWebhookDestinations(ctx, ds, "DebugSessionPodFailed", map[string]interface{}{
							"pod":       pod.Name,
							"namespace": pod.Namespace,
							"container": cs.Name,
							"reason":    waitingReason,
							"message":   waitingMessage,
						})
					}
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
	// Keep the inventory observed at the start of this cleanup attempt.  A
	// concurrent outcome writer may add a newer target while cleanup is in
	// progress; the status patch below must remove only entries that this
	// attempt actually retired.
	cleanupBaseline := ds.Status.DeepCopy()
	wasCleanupFailed := cleanupConditionFailed(ds)
	finishCleanup := func(operationErr error) error {
		setCleanupCondition(ds)
		liveWasFailed := false
		patchErr := c.patchDebugSessionCleanupStatusWithTransition(ctx, ds, cleanupBaseline, &liveWasFailed)
		if patchErr == nil && c.shouldEmitAudit(ds) {
			if auditManager := c.currentAuditManager(); auditManager != nil {
				if cleanupConditionFailed(ds) {
					auditManager.DebugSessionCleanupFailed(ctx, ds.Name, ds.Namespace, ds.Spec.Cluster, cleanupResidualIdentities(ds))
				} else if liveWasFailed {
					auditManager.DebugSessionCleanupRecovered(ctx, ds.Name, ds.Namespace, ds.Spec.Cluster)
				}
			}
		}
		if patchErr == nil && cleanupStatusHasResiduals(ds) {
			operationErr = errors.Join(operationErr, errors.New("cleanup inventory remains unresolved"))
		}
		return errors.Join(operationErr, patchErr)
	}

	if c.ccProvider == nil {
		if hasTrackedSpokeResources(ds) {
			return finishCleanup(fmt.Errorf("cannot clean up tracked spoke resources: cluster client provider is unavailable"))
		}
		if wasCleanupFailed {
			return finishCleanup(nil)
		}
		return nil
	}

	// Clean up kubectl-debug resources (if any)
	kubectlHandler := c.newKubectlDebugHandler()
	var cleanupErrors []error
	if err := kubectlHandler.CleanupKubectlDebugResources(ctx, ds); err != nil {
		// An unavailable cluster cannot prove that tracked resources are gone.
		if errors.Is(err, cluster.ErrClusterConfigNotFound) {
			log.Warnw("ClusterConfig no longer exists; retaining cleanup inventory for retry", "cluster", ds.Spec.Cluster)
			return finishCleanup(fmt.Errorf("cleanup blocked by missing ClusterConfig: %w", err))
		}
		log.Errorw("Failed to cleanup kubectl-debug resources", "error", err)
		cleanupErrors = append(cleanupErrors, err)
	}

	if !cleanupNeedsTargetCluster(ds) {
		// AllowedPods are authorization references, not spoke resources. Remove
		// this attempt's baseline refs while the status merge retains newer refs.
		ds.Status.AllowedPods = nil
		if hasPreparedKubectlDebugOperation(ds) {
			cleanupErrors = append(cleanupErrors, errors.New("prepared kubectl-debug operation remains unresolved"))
		}
		if hasUnresolvedCleanupIntent(ds) {
			cleanupErrors = append(cleanupErrors, errors.New("cleanup intent remains unresolved"))
		}
		return finishCleanup(errors.Join(cleanupErrors...))
	}

	// Get spoke cluster client for cleanup
	restCfg, err := c.ccProvider.GetRESTConfig(ctx, ds.Spec.Cluster)
	if err != nil {
		cleanupErrors = append(cleanupErrors, fmt.Errorf("failed to get REST config: %w", err))
		return finishCleanup(errors.Join(cleanupErrors...))
	}
	targetClient, err := ctrlclient.New(restCfg, ctrlclient.Options{})
	if err != nil {
		cleanupErrors = append(cleanupErrors, fmt.Errorf("failed to create client: %w", err))
		return finishCleanup(errors.Join(cleanupErrors...))
	}

	// Cleanup auxiliary resources first using the manager
	auxiliaryCleanupFailed := false
	if c.auxiliaryMgr != nil && len(ds.Status.AuxiliaryResourceStatuses) > 0 {
		if err := c.auxiliaryMgr.CleanupAuxiliaryResources(ctx, ds, targetClient); err != nil {
			log.Warnw("Failed to cleanup auxiliary resources", "error", err)
			auxiliaryCleanupFailed = true
			cleanupErrors = append(cleanupErrors, err)
		}
	}

	// Cleanup pod template resources (from multi-doc pod templates)
	if len(ds.Status.PodTemplateResourceStatuses) > 0 {
		if err := c.cleanupPodTemplateResources(ctx, ds, targetClient); err != nil {
			log.Warnw("Failed to cleanup pod template resources", "error", err)
			cleanupErrors = append(cleanupErrors, err)
		}
	}

	if len(ds.Status.DeployedResources) == 0 {
		// Persist any status changes from auxiliary/pod-template cleanup above
		return finishCleanup(errors.Join(cleanupErrors...))
	}

	if err := c.cleanupDeployedResources(ctx, ds, targetClient, auxiliaryCleanupFailed, len(ds.Status.PodTemplateResourceStatuses) > 0); err != nil {
		cleanupErrors = append(cleanupErrors, err)
	}
	return finishCleanup(errors.Join(cleanupErrors...))
}

const (
	maxCleanupResidualIdentities = 16
	maxCleanupIdentityLength     = 256
	maxCleanupConditionMessage   = 1024
)

func cleanupConditionFailed(ds *breakglassv1alpha1.DebugSession) bool {
	condition := ds.GetCondition(string(breakglassv1alpha1.DebugSessionConditionCleanupFailed))
	return condition != nil && condition.Status == metav1.ConditionTrue
}

func setCleanupCondition(ds *breakglassv1alpha1.DebugSession) {
	conditionType := string(breakglassv1alpha1.DebugSessionConditionCleanupFailed)
	condition := metav1.Condition{
		Type:               conditionType,
		ObservedGeneration: ds.Generation,
		LastTransitionTime: metav1.Now(),
	}
	if cleanupStatusHasResiduals(ds) {
		condition.Status = metav1.ConditionTrue
		condition.Reason = "CleanupFailed"
		condition.Message = boundedCleanupConditionMessage(ds)
	} else {
		condition.Status = metav1.ConditionFalse
		condition.Reason = "CleanupRecovered"
		condition.Message = "Cleanup completed; no residual resources remain."
	}
	if previous := ds.GetCondition(conditionType); previous != nil && previous.Status == condition.Status {
		condition.LastTransitionTime = previous.LastTransitionTime
	}
	ds.SetCondition(condition)
}

func cleanupResidualIdentities(ds *breakglassv1alpha1.DebugSession) []string {
	identities := make([]string, 0, maxCleanupResidualIdentities)
	seen := make(map[string]struct{}, maxCleanupResidualIdentities)
	add := func(apiVersion, kind, namespace, name, uid string) {
		if name == "" {
			return
		}
		identity := kind + "/" + name
		if apiVersion != "" {
			identity = apiVersion + "/" + identity
		}
		if namespace != "" {
			identity = namespace + "/" + identity
		}
		if uid != "" {
			identity += " (uid=" + uid + ")"
		}
		if _, exists := seen[identity]; exists {
			return
		}
		seen[identity] = struct{}{}
		if len(identities) >= maxCleanupResidualIdentities {
			return
		}
		if len(identity) > maxCleanupIdentityLength {
			identity = identity[:maxCleanupIdentityLength-len("...")] + "..."
		}
		identities = append(identities, identity)
	}
	for _, ref := range ds.Status.DeployedResources {
		if !utils.DebugSessionResourceIntentionallyRetained(ds, ref) {
			add(ref.APIVersion, ref.Kind, ref.Namespace, ref.Name, ref.UID)
		}
	}
	for _, status := range ds.Status.AuxiliaryResourceStatuses {
		if auxiliaryStatusHasCleanupResidual(ds, status) {
			add(status.APIVersion, status.Kind, status.Namespace, status.ResourceName, status.UID)
		}
		for _, ref := range status.AdditionalResources {
			if utils.DebugSessionAuxiliaryChildHasCleanupResidual(ds, status.Name, ref) {
				add(ref.APIVersion, ref.Kind, ref.Namespace, ref.ResourceName, ref.UID)
			}
		}
	}
	for _, status := range ds.Status.PodTemplateResourceStatuses {
		if !status.Deleted && (status.Created || status.UID != "" || status.CreateOperationID != "") {
			add(status.APIVersion, status.Kind, status.Namespace, status.ResourceName, status.UID)
		}
	}
	if status := ds.Status.KubectlDebugStatus; status != nil {
		for _, ref := range status.CopiedPods {
			add("v1", "Pod", ref.CopyNamespace, ref.CopyName, canonicalCopiedPodUID(ref))
		}

		if hasPreparedKubectlDebugOperation(ds) {
			for _, operation := range status.Operations {
				if operation.State == breakglassv1alpha1.KubectlDebugOperationPrepared {
					add("", "KubectlDebugOperation", "", operation.ID, "")
				}
			}
		}
	}
	return identities
}

func boundedCleanupConditionMessage(ds *breakglassv1alpha1.DebugSession) string {
	const prefix = "Cleanup failed; residual resources: "
	identities := cleanupResidualIdentities(ds)
	if len(identities) == 0 {
		return "Cleanup failed; residual resources remain in the durable inventory."
	}
	message := prefix + strings.Join(identities, ", ")
	if len(message) <= maxCleanupConditionMessage {
		return message
	}
	return message[:maxCleanupConditionMessage-len("...")] + "..."
}

func residualResourceIdentities(refs []breakglassv1alpha1.DeployedResourceRef) string {
	identities := make([]string, 0, len(refs))
	for _, ref := range refs {
		identity := fmt.Sprintf("%s/%s", ref.Kind, ref.Name)
		if ref.Namespace != "" {
			identity = ref.Namespace + "/" + identity
		}
		if ref.UID != "" {
			identity += " (uid=" + ref.UID + ")"
		}
		identities = append(identities, identity)
	}
	return strings.Join(identities, ", ")
}

func (c *DebugSessionController) patchDebugSessionCleanupStatus(
	ctx context.Context,
	ds *breakglassv1alpha1.DebugSession,
	baseline ...*breakglassv1alpha1.DebugSessionStatus,
) error {
	var observed *breakglassv1alpha1.DebugSessionStatus
	if len(baseline) > 0 {
		observed = baseline[0]
	}
	return c.patchDebugSessionCleanupStatusWithTransition(ctx, ds, observed, nil)
}

func (c *DebugSessionController) patchDebugSessionCleanupStatusWithTransition(ctx context.Context, ds *breakglassv1alpha1.DebugSession, baseline *breakglassv1alpha1.DebugSessionStatus, wasFailed *bool) error {
	desiredStatus := ds.Status
	cleanupBaseline := desiredStatus
	if baseline != nil {
		cleanupBaseline = *baseline
	}
	var patchedStatus breakglassv1alpha1.DebugSessionStatus
	var patchedResourceVersion string

	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		current := &breakglassv1alpha1.DebugSession{}
		if err := c.client.Get(ctx, ctrlclient.ObjectKeyFromObject(ds), current); err != nil {
			return err
		}
		if ds.UID != "" && current.UID != ds.UID {
			return fmt.Errorf("debug session UID changed while patching cleanup status: expected %q, got %q", ds.UID, current.UID)
		}

		previouslyFailed := cleanupConditionFailed(current)
		base := current.DeepCopy()
		current.Status.DeployedResources = mergeCleanupInventory(
			cleanupBaseline.DeployedResources, desiredStatus.DeployedResources, current.Status.DeployedResources,
			deployedResourceKey,
		)
		current.Status.AllowedPods = mergeCleanupInventory(
			cleanupBaseline.AllowedPods, desiredStatus.AllowedPods, current.Status.AllowedPods,
			allowedPodKey,
		)
		current.Status.AuxiliaryResourceStatuses = mergeAuxiliaryResourceStatuses(
			cleanupBaseline.AuxiliaryResourceStatuses, desiredStatus.AuxiliaryResourceStatuses, current.Status.AuxiliaryResourceStatuses,
		)
		current.Status.PodTemplateResourceStatuses = mergeCleanupInventory(
			cleanupBaseline.PodTemplateResourceStatuses, desiredStatus.PodTemplateResourceStatuses, current.Status.PodTemplateResourceStatuses,
			podTemplateResourceStatusKey,
		)
		current.Status.KubectlDebugStatus = mergeKubectlDebugStatus(
			cleanupBaseline.KubectlDebugStatus, desiredStatus.KubectlDebugStatus, current.Status.KubectlDebugStatus,
		)
		if desiredCleanupCondition(desiredStatus.Conditions) != nil {
			// Classify the fresh merged inventory, not the operation or status-write error.
			setCleanupCondition(current)
		}

		if current.Generation > 0 {
			current.Status.ObservedGeneration = current.Generation
		}

		if err := c.client.Status().Patch(ctx, current, ctrlclient.MergeFromWithOptions(base, ctrlclient.MergeFromWithOptimisticLock{})); err != nil {
			return err
		}
		if wasFailed != nil {
			*wasFailed = previouslyFailed
		}
		patchedStatus = current.Status
		patchedResourceVersion = current.ResourceVersion
		return nil
	})
	if err != nil {
		return fmt.Errorf("patch debug session cleanup status: %w", err)
	}

	ds.Status = patchedStatus
	ds.ResourceVersion = patchedResourceVersion
	return nil
}

func cleanupStatusHasResiduals(session *breakglassv1alpha1.DebugSession) bool {
	status := session.Status
	if utils.DebugSessionHasActionableDeployedResources(session) {
		return true
	}
	for _, resource := range status.AuxiliaryResourceStatuses {
		if auxiliaryStatusHasCleanupResidual(session, resource) {
			return true
		}
		for _, child := range resource.AdditionalResources {
			if utils.DebugSessionAuxiliaryChildHasCleanupResidual(session, resource.Name, child) {
				return true
			}
		}
	}
	for _, resource := range status.PodTemplateResourceStatuses {
		if utils.DebugSessionPodTemplateStatusHasCleanupResidual(resource) {
			return true
		}
	}
	if hasPreparedKubectlDebugOperation(session) {
		return true
	}
	return status.KubectlDebugStatus != nil &&
		len(status.KubectlDebugStatus.CopiedPods) > 0
}

func cleanupNeedsTargetCluster(session *breakglassv1alpha1.DebugSession) bool {
	status := session.Status
	for _, ref := range status.DeployedResources {
		if !utils.DebugSessionResourceIntentionallyRetained(session, ref) && (ref.UID != "" || ref.CreateOperationID == "") {
			return true
		}
	}
	for _, resource := range status.AuxiliaryResourceStatuses {
		if !auxiliaryStatusHasCleanupResidual(session, resource) {
			for _, child := range resource.AdditionalResources {
				if !child.Deleted && shouldDeleteAuxiliaryResource(session, resource.Name) && (child.UID != "" || child.CreateOperationID == "") {
					return true
				}
			}
			continue
		}
		if resource.UID != "" || resource.CreateOperationID == "" {
			return true
		}
		for _, child := range resource.AdditionalResources {
			if !child.Deleted && shouldDeleteAuxiliaryResource(session, resource.Name) && (child.UID != "" || child.CreateOperationID == "") {
				return true
			}
		}
	}
	for _, resource := range status.PodTemplateResourceStatuses {
		if !resource.Deleted && (resource.UID != "" || (resource.Created && resource.CreateOperationID == "")) {
			return true
		}
	}
	return false
}

func hasUnresolvedCleanupIntent(session *breakglassv1alpha1.DebugSession) bool {
	for _, resource := range session.Status.AuxiliaryResourceStatuses {
		if !resource.Deleted && resource.UID == "" && resource.CreateOperationID != "" {
			return true
		}
		for _, child := range resource.AdditionalResources {
			if !child.Deleted && child.UID == "" && child.CreateOperationID != "" {
				return true
			}
		}
	}
	for _, resource := range session.Status.PodTemplateResourceStatuses {
		if !resource.Deleted && resource.UID == "" && resource.CreateOperationID != "" {
			return true
		}
	}
	return false
}

func auxiliaryStatusHasCleanupResidual(session *breakglassv1alpha1.DebugSession, status breakglassv1alpha1.AuxiliaryResourceStatus) bool {
	return utils.DebugSessionAuxiliaryStatusHasCleanupResidual(session, status)
}

func desiredCleanupCondition(conditions []metav1.Condition) *metav1.Condition {
	for i := range conditions {
		if conditions[i].Type == string(breakglassv1alpha1.DebugSessionConditionCleanupFailed) {
			return &conditions[i]
		}
	}
	return nil
}

// mergeCleanupInventory applies the removals observed by one cleanup attempt
// to the latest persisted list.  Entries absent from the baseline are newer
// writes and must survive, even when the cleanup caller started from an older
// same-UID session object.
func mergeCleanupInventory[T any](baseline, desired, current []T, key func(T) string) []T {
	desired = promoteObservedCleanupIntents(desired, current)
	baselineKeys := make(map[string]struct{}, len(baseline))
	for _, item := range baseline {
		baselineKeys[key(item)] = struct{}{}
	}
	desiredKeys := make(map[string]struct{}, len(desired))
	for _, item := range desired {
		desiredKeys[key(item)] = struct{}{}
	}
	merged := append([]T(nil), desired...)
	for _, item := range current {
		itemKey := key(item)
		if _, wasTracked := baselineKeys[itemKey]; wasTracked {
			continue
		}
		if _, alreadyDesired := desiredKeys[itemKey]; !alreadyDesired {
			merged = append(merged, item)
		}
	}
	return merged
}

// promoteObservedCleanupIntents folds an unresolved placeholder into its durable
// UID outcome. Known conflicting UIDs remain separate; no target lookup or
// marker-based identity adoption occurs here.
func promoteObservedCleanupIntents[T any](desired, current []T) []T {
	observed := make(map[string]T)
	ambiguous := make(map[string]bool)
	for _, item := range current {
		operation, uid := cleanupOperationIdentity(item)
		if operation == "" || uid == "" {
			continue
		}
		if previous, ok := observed[operation]; ok {
			_, previousUID := cleanupOperationIdentity(previous)
			if previousUID != uid {
				ambiguous[operation] = true
			}
		}
		observed[operation] = item
	}
	merged := append([]T(nil), desired...)
	for i, item := range merged {
		operation, uid := cleanupOperationIdentity(item)
		if operation == "" || uid != "" || ambiguous[operation] {
			continue
		}
		if resolved, ok := observed[operation]; ok {
			// Child cleanup is merged separately against its own baseline below.
			if parent, ok := any(resolved).(breakglassv1alpha1.AuxiliaryResourceStatus); ok {
				parent.AdditionalResources = any(item).(breakglassv1alpha1.AuxiliaryResourceStatus).AdditionalResources
				resolved = any(parent).(T)
			}
			merged[i] = resolved
		}
	}
	return merged
}

func cleanupOperationIdentity(item any) (string, string) {
	switch resource := item.(type) {
	case breakglassv1alpha1.DeployedResourceRef:
		if resource.CreateOperationID == "" {
			return "", resource.UID
		}
		uid := resource.UID
		resource.UID = ""
		return "deployed:" + deployedResourceKey(resource), uid
	case breakglassv1alpha1.AuxiliaryResourceStatus:
		if resource.CreateOperationID == "" {
			return "", resource.UID
		}
		uid := resource.UID
		resource.UID = ""
		return "auxiliary:" + auxiliaryResourceStatusKey(resource), uid
	case breakglassv1alpha1.AdditionalResourceRef:
		if resource.CreateOperationID == "" {
			return "", resource.UID
		}
		uid := resource.UID
		resource.UID = ""
		return "child:" + additionalResourceKey(resource), uid
	case breakglassv1alpha1.PodTemplateResourceStatus:
		if resource.CreateOperationID == "" {
			return "", resource.UID
		}
		uid := resource.UID
		resource.UID = ""
		return "pod-template:" + podTemplateResourceStatusKey(resource), uid
	}
	return "", ""
}

func deployedResourceKey(ref breakglassv1alpha1.DeployedResourceRef) string {
	return fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s", ref.APIVersion, ref.Kind, ref.Namespace, ref.Name, ref.Source, ref.UID, ref.CreateOperationID)
}

func allowedPodKey(ref breakglassv1alpha1.AllowedPodRef) string {
	return fmt.Sprintf("%s|%s|%s", ref.Namespace, ref.Name, ref.UID)
}

func auxiliaryResourceStatusKey(status breakglassv1alpha1.AuxiliaryResourceStatus) string {
	return fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s|%s", status.Name, status.Category, status.APIVersion, status.Kind, status.ResourceName, status.Namespace, status.UID, status.CreateOperationID)
}

func additionalResourceKey(ref breakglassv1alpha1.AdditionalResourceRef) string {
	return fmt.Sprintf("%s|%s|%s|%s|%s|%s", ref.APIVersion, ref.Kind, ref.Namespace, ref.ResourceName, ref.UID, ref.CreateOperationID)
}

func mergeAuxiliaryResourceStatuses(
	baseline, desired, current []breakglassv1alpha1.AuxiliaryResourceStatus,
) []breakglassv1alpha1.AuxiliaryResourceStatus {
	desired = promoteObservedCleanupIntents(desired, current)
	merged := append([]breakglassv1alpha1.AuxiliaryResourceStatus(nil), desired...)
	desiredByKey := make(map[string]int, len(desired))
	baselineByKey := make(map[string]breakglassv1alpha1.AuxiliaryResourceStatus, len(baseline))
	for i, status := range desired {
		desiredByKey[auxiliaryResourceStatusKey(status)] = i
	}
	for _, status := range baseline {
		baselineByKey[auxiliaryResourceStatusKey(status)] = status
	}
	for _, status := range current {
		key := auxiliaryResourceStatusKey(status)
		if desiredIndex, ok := desiredByKey[key]; ok {
			baselineStatus, exists := baselineByKey[key]
			if !exists {
				operation, _ := cleanupOperationIdentity(status)
				for _, previous := range baseline {
					previousOperation, uid := cleanupOperationIdentity(previous)
					if operation != "" && operation == previousOperation && uid == "" {
						baselineStatus = previous
						break
					}
				}
			}
			merged[desiredIndex].AdditionalResources = mergeCleanupInventory(
				baselineStatus.AdditionalResources,
				desired[desiredIndex].AdditionalResources,
				status.AdditionalResources,
				additionalResourceKey,
			)
			continue
		}
		if _, wasTracked := baselineByKey[key]; !wasTracked {
			merged = append(merged, status)
		}
	}
	return merged
}

func podTemplateResourceStatusKey(status breakglassv1alpha1.PodTemplateResourceStatus) string {
	return fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s", status.APIVersion, status.Kind, status.Namespace, status.ResourceName, status.Source, status.UID, status.CreateOperationID)
}

func canonicalCopiedPodUID(ref breakglassv1alpha1.CopiedPodRef) string {
	if ref.UID != "" {
		return ref.UID
	}
	return ref.CopyUID
}

func mergeKubectlDebugStatus(baseline, desired, current *breakglassv1alpha1.KubectlDebugStatus) *breakglassv1alpha1.KubectlDebugStatus {
	if baseline == nil && desired == nil {
		return current.DeepCopy()
	}
	var empty breakglassv1alpha1.KubectlDebugStatus
	if baseline == nil {
		baseline = &empty
	}
	if desired == nil {
		desired = &empty
	}
	if current == nil {
		current = &empty
	}
	merged := desired.DeepCopy()
	merged.EphemeralContainersInjected = mergeCleanupInventory(
		baseline.EphemeralContainersInjected, desired.EphemeralContainersInjected, current.EphemeralContainersInjected,
		func(ref breakglassv1alpha1.EphemeralContainerRef) string {
			return fmt.Sprintf("%s|%s|%s|%s|%s", ref.Namespace, ref.PodName, ref.ContainerName, ref.PodUID, ref.Image)
		},
	)
	merged.CopiedPods = mergeCleanupInventory(
		baseline.CopiedPods, desired.CopiedPods, current.CopiedPods,
		func(ref breakglassv1alpha1.CopiedPodRef) string {
			return fmt.Sprintf("%s|%s|%s|%s|%s", ref.CopyNamespace, ref.CopyName, canonicalCopiedPodUID(ref), ref.OriginalNamespace, ref.OriginalPod)
		},
	)
	merged.Operations = mergeKubectlDebugOperations(baseline.Operations, desired.Operations, current.Operations)
	if len(merged.EphemeralContainersInjected) == 0 && len(merged.CopiedPods) == 0 && len(merged.Operations) == 0 {
		return nil
	}
	return merged
}

// mergeKubectlDebugOperations preserves durable operation evidence while a
// cleanup attempt races with a target mutation outcome writer. Terminal state
// always wins over Prepared, and concurrent operations that were added after
// the cleanup baseline are retained.
func mergeKubectlDebugOperations(
	baseline, desired, current []breakglassv1alpha1.KubectlDebugOperation,
) []breakglassv1alpha1.KubectlDebugOperation {
	desiredByID := make(map[string]int, len(desired))
	baselineByID := make(map[string]breakglassv1alpha1.KubectlDebugOperation, len(baseline))
	for i, operation := range desired {
		desiredByID[operation.ID] = i
	}
	for _, operation := range baseline {
		baselineByID[operation.ID] = operation
	}
	merged := make([]breakglassv1alpha1.KubectlDebugOperation, 0, len(desired)+len(current))
	deferredFinalized := make([]breakglassv1alpha1.KubectlDebugOperation, 0)
	currentIDs := make(map[string]struct{}, len(current))
	for _, operation := range current {
		currentIDs[operation.ID] = struct{}{}
		if desiredIndex, ok := desiredByID[operation.ID]; ok {
			mergedOperation := mergeKubectlDebugOperation(desired[desiredIndex], operation)
			if operation.State == breakglassv1alpha1.KubectlDebugOperationPrepared && mergedOperation.State != breakglassv1alpha1.KubectlDebugOperationPrepared {
				deferredFinalized = append(deferredFinalized, mergedOperation)
			} else {
				merged = append(merged, mergedOperation)
			}
			continue
		}
		// The current server snapshot owns terminal ordering and retains any
		// operation that was observed during the cleanup race.
		merged = append(merged, operation)
	}
	merged = append(merged, deferredFinalized...)
	for _, operation := range desired {
		if _, exists := currentIDs[operation.ID]; exists {
			continue
		}
		// A terminal record absent from current was compacted by another
		// writer. Do not reintroduce it from the cleanup's stale desired copy.
		if _, wasTracked := baselineByID[operation.ID]; wasTracked {
			continue
		}
		merged = append(merged, operation)
	}
	merged = terminalKubectlDebugOperations(merged)
	return merged
}

func mergeKubectlDebugOperation(desired, current breakglassv1alpha1.KubectlDebugOperation) breakglassv1alpha1.KubectlDebugOperation {
	if current.State != breakglassv1alpha1.KubectlDebugOperationPrepared || desired.State == breakglassv1alpha1.KubectlDebugOperationPrepared {
		return current
	}
	return desired
}

func (c *DebugSessionController) cleanupDeployedResources(
	ctx context.Context,
	ds *breakglassv1alpha1.DebugSession,
	targetClient ctrlclient.Client,
	keepAuxiliaryRefs bool,
	keepPodTemplateRefs bool,
) error {
	log := c.log.With("debugSession", ds.Name, "cluster", ds.Spec.Cluster)
	var cleanupErrors []error
	remainingDeployedResources := make([]breakglassv1alpha1.DeployedResourceRef, 0, len(ds.Status.DeployedResources))

	for _, ref := range ds.Status.DeployedResources {
		if ref.UID == "" && ref.CreateOperationID != "" {
			remainingDeployedResources = append(remainingDeployedResources, ref)
			cleanupErrors = append(cleanupErrors, fmt.Errorf("deployed resource %s/%s creation outcome is unresolved", ref.Namespace, ref.Name))
			continue
		}
		// Confirm retention before any generic target deletion, including legacy
		// references whose source was not persisted.
		if utils.DebugSessionResourceIntentionallyRetained(ds, ref) {
			continue
		}
		// Skip auxiliary resources - already cleaned up by manager.
		if strings.HasPrefix(ref.Source, "auxiliary:") || (ref.Source == "" && auxiliaryResourceCoordinatesKnown(ds, ref)) {
			if keepAuxiliaryRefs {
				remainingDeployedResources = append(remainingDeployedResources, ref)
				continue
			}
			if auxiliaryResourceDeleted(ds, ref) || !auxiliaryResourceRequiresCleanup(ds, ref) {
				if !auxiliaryResourceStatusKnown(ds, ref) {
					remainingDeployedResources = append(remainingDeployedResources, ref)
					cleanupErrors = append(cleanupErrors, fmt.Errorf("missing auxiliary cleanup status for %s %s/%s; retaining inventory", ref.Kind, ref.Namespace, ref.Name))
				}
				continue
			}
		}
		// Retain pod-template inventory while specialized cleanup is pending;
		// otherwise let the generic pass remove legacy residual references.
		if ref.Source == "pod-template" {
			if keepPodTemplateRefs {
				remainingDeployedResources = append(remainingDeployedResources, ref)
				continue
			}
		}

		if ref.APIVersion == "" || ref.Kind == "" || ref.Name == "" {
			remainingDeployedResources = append(remainingDeployedResources, ref)
			cleanupErrors = append(cleanupErrors, fmt.Errorf("invalid deployed resource identity %q", residualResourceIdentities([]breakglassv1alpha1.DeployedResourceRef{ref})))
			continue
		}

		// The inventory is deliberately generic: auxiliary resources and
		// multi-document templates may contain PVCs, NetworkPolicies, RBAC
		// objects, CRDs, or kinds added after this controller was released.
		if ref.Source == "workload" && ref.Kind != "DaemonSet" && ref.Kind != "Deployment" &&
			ref.Kind != "Job" && ref.Kind != "ResourceQuota" && ref.Kind != "PodDisruptionBudget" &&
			ref.Kind != "Pod" {
			remainingDeployedResources = append(remainingDeployedResources, ref)
			cleanupErrors = append(cleanupErrors, fmt.Errorf("unsupported deployed resource kind %q for %s/%s", ref.Kind, ref.Namespace, ref.Name))
			continue
		}
		obj := &unstructured.Unstructured{}
		obj.SetGroupVersionKind(schema.FromAPIVersionAndKind(ref.APIVersion, ref.Kind))
		obj.SetName(ref.Name)
		obj.SetNamespace(ref.Namespace)
		if ref.UID != "" {
			obj.SetUID(types.UID(ref.UID))
		}

		if err := deleteTrackedResource(ctx, targetClient, ds, obj); err != nil {
			if apierrors.IsNotFound(err) {
				log.Debugw("Debug resource already deleted", "kind", ref.Kind, "name", ref.Name, "namespace", ref.Namespace)
				continue
			}
			log.Warnw("Failed to delete debug resource", "kind", ref.Kind, "name", ref.Name, "namespace", ref.Namespace, "error", err)
			remainingDeployedResources = append(remainingDeployedResources, ref)
			cleanupErrors = append(cleanupErrors, fmt.Errorf("delete debug resource %s %s/%s: %w", ref.Kind, ref.Namespace, ref.Name, err))
		} else {
			// Kubernetes reports a successful DELETE before finalizers finish.
			// Verify the identity is actually gone so finalizer stalls remain in
			// the durable inventory and are retried/visible to operators.
			remaining := &unstructured.Unstructured{}
			remaining.SetGroupVersionKind(obj.GroupVersionKind())
			remaining.SetName(ref.Name)
			remaining.SetNamespace(ref.Namespace)
			if getErr := targetClient.Get(ctx, ctrlclient.ObjectKey{Name: ref.Name, Namespace: ref.Namespace}, remaining); getErr == nil {
				expectedUID := types.UID(ref.UID)
				if expectedUID == "" {
					var resolveErr error
					expectedUID, resolveErr = legacyCleanupUID(ds, obj.GroupVersionKind(), ref.Namespace, ref.Name)
					if resolveErr != nil {
						remainingDeployedResources = append(remainingDeployedResources, ref)
						cleanupErrors = append(cleanupErrors, fmt.Errorf("resolve legacy identity for debug resource %s %s/%s: %w", ref.Kind, ref.Namespace, ref.Name, resolveErr))
						continue
					}
				}
				if remaining.GetUID() != expectedUID {
					// The recorded instance is gone and a same-name replacement is
					// intentionally left untouched.
					continue
				}
				remainingDeployedResources = append(remainingDeployedResources, ref)
				cleanupErrors = append(cleanupErrors, fmt.Errorf("delete debug resource %s %s/%s is pending finalizers", ref.Kind, ref.Namespace, ref.Name))
				continue
			} else if !apierrors.IsNotFound(getErr) {
				remainingDeployedResources = append(remainingDeployedResources, ref)
				cleanupErrors = append(cleanupErrors, fmt.Errorf("verify deletion of debug resource %s %s/%s: %w", ref.Kind, ref.Namespace, ref.Name, getErr))
				continue
			}
			log.Infow("Deleted debug resource", "kind", ref.Kind, "name", ref.Name, "namespace", ref.Namespace)
		}
	}

	ds.Status.DeployedResources = remainingDeployedResources
	ds.Status.AllowedPods = allowedPodsForRemainingDeployedPods(ds.Status.AllowedPods, remainingDeployedResources)
	return errors.Join(cleanupErrors...)
}

const sourceSessionUIDAnnotation = "breakglass.t-caas.telekom.com/source-session-uid"

const createOperationIDAnnotation = "breakglass.t-caas.telekom.com/create-operation-id"

// deleteOwnedResource resolves the target object immediately before deletion and
// verifies immutable ownership. A name is reusable after deletion, so deleting
// a name-only placeholder can destroy a replacement belonging to another
// session. Records written before UID tracking was introduced are only
// deletable when the immutable session UID annotation is present and matches.
func deleteOwnedResource(ctx context.Context, targetClient ctrlclient.Client, obj ctrlclient.Object, expectedUID string, session *breakglassv1alpha1.DebugSession) error {
	live := obj.DeepCopyObject().(ctrlclient.Object)
	if err := targetClient.Get(ctx, ctrlclient.ObjectKeyFromObject(obj), live); err != nil {
		return err
	}
	if live.GetUID() == "" {
		return fmt.Errorf("refusing to delete %s %s/%s: live UID is unavailable", obj.GetObjectKind().GroupVersionKind().Kind, obj.GetNamespace(), obj.GetName())
	}
	if expectedUID != "" {
		if string(live.GetUID()) != expectedUID {
			return nil
		}
	} else if session == nil || session.UID == "" || live.GetAnnotations()[sourceSessionUIDAnnotation] != string(session.UID) {
		return fmt.Errorf("refusing to delete %s %s/%s: ownership identity is unavailable or changed", obj.GetObjectKind().GroupVersionKind().Kind, obj.GetNamespace(), obj.GetName())
	}
	if live.GetUID() != "" {
		uid := live.GetUID()
		return targetClient.Delete(ctx, live, ctrlclient.Preconditions{UID: &uid})
	}
	return targetClient.Delete(ctx, live)
}

func captureResourceUID(_ context.Context, _ ctrlclient.Client, obj ctrlclient.Object) (string, error) {
	// Use only the mutation response; a name lookup could observe a replacement.
	if obj.GetUID() == "" {
		return "", fmt.Errorf("resource %s/%s has no UID after mutation", obj.GetNamespace(), obj.GetName())
	}
	return string(obj.GetUID()), nil
}

func auxiliaryResourceDeleted(ds *breakglassv1alpha1.DebugSession, ref breakglassv1alpha1.DeployedResourceRef) bool {
	for _, status := range ds.Status.AuxiliaryResourceStatuses {
		if ref.UID != "" && status.UID == ref.UID && (ref.Source == "" || ref.Source == "auxiliary:"+status.Name) && status.Kind == ref.Kind && status.APIVersion == ref.APIVersion &&
			status.ResourceName == ref.Name && status.Namespace == ref.Namespace {
			return status.Deleted
		}
		for _, additional := range status.AdditionalResources {
			if ref.UID != "" && additional.UID == ref.UID && (ref.Source == "" || ref.Source == "auxiliary:"+status.Name) && additional.Kind == ref.Kind && additional.APIVersion == ref.APIVersion &&
				additional.ResourceName == ref.Name && additional.Namespace == ref.Namespace {
				return additional.Deleted
			}
		}
	}
	return false
}

func auxiliaryResourceRequiresCleanup(ds *breakglassv1alpha1.DebugSession, ref breakglassv1alpha1.DeployedResourceRef) bool {
	for _, status := range ds.Status.AuxiliaryResourceStatuses {
		if ref.UID != "" && status.UID == ref.UID && (ref.Source == "" || ref.Source == "auxiliary:"+status.Name) && status.Kind == ref.Kind && status.APIVersion == ref.APIVersion &&
			status.ResourceName == ref.Name && status.Namespace == ref.Namespace {
			return shouldDeleteAuxiliaryResource(ds, status.Name)
		}
		for _, additional := range status.AdditionalResources {
			if ref.UID != "" && additional.UID == ref.UID && (ref.Source == "" || ref.Source == "auxiliary:"+status.Name) && additional.Kind == ref.Kind && additional.APIVersion == ref.APIVersion &&
				additional.ResourceName == ref.Name && additional.Namespace == ref.Namespace {
				return shouldDeleteAuxiliaryResource(ds, status.Name)
			}
		}
	}
	// Without the durable status metadata, deleteAfter cannot be determined.
	// Retain the inventory and surface the ambiguity rather than guessing that
	// the resource was controller-owned.
	return false
}

func auxiliaryResourceStatusKnown(ds *breakglassv1alpha1.DebugSession, ref breakglassv1alpha1.DeployedResourceRef) bool {
	for _, status := range ds.Status.AuxiliaryResourceStatuses {
		if ref.UID != "" && status.UID == ref.UID && (ref.Source == "" || ref.Source == "auxiliary:"+status.Name) && status.Kind == ref.Kind && status.APIVersion == ref.APIVersion &&
			status.ResourceName == ref.Name && status.Namespace == ref.Namespace {
			return true
		}
		for _, additional := range status.AdditionalResources {
			if ref.UID != "" && additional.UID == ref.UID && (ref.Source == "" || ref.Source == "auxiliary:"+status.Name) && additional.Kind == ref.Kind && additional.APIVersion == ref.APIVersion &&
				additional.ResourceName == ref.Name && additional.Namespace == ref.Namespace {
				return true
			}
		}
	}
	return false
}

func allowedPodsForRemainingDeployedPods(
	allowedPods []breakglassv1alpha1.AllowedPodRef,
	remainingDeployedResources []breakglassv1alpha1.DeployedResourceRef,
) []breakglassv1alpha1.AllowedPodRef {
	if len(allowedPods) == 0 {
		return nil
	}

	remainingPodRefs := make(map[[2]string]struct{})
	for _, ref := range remainingDeployedResources {
		if ref.Kind != "Pod" {
			continue
		}
		remainingPodRefs[[2]string{ref.Namespace, ref.Name}] = struct{}{}
	}
	if len(remainingPodRefs) == 0 {
		return nil
	}

	filtered := make([]breakglassv1alpha1.AllowedPodRef, 0, len(allowedPods))
	for _, pod := range allowedPods {
		if _, ok := remainingPodRefs[[2]string{pod.Namespace, pod.Name}]; ok {
			filtered = append(filtered, pod)
		}
	}
	if len(filtered) == 0 {
		return nil
	}
	return filtered
}

// cleanupPodTemplateResources removes resources deployed from multi-document pod templates.
func (c *DebugSessionController) cleanupPodTemplateResources(ctx context.Context, ds *breakglassv1alpha1.DebugSession, targetClient ctrlclient.Client) error {
	log := c.log.With("debugSession", ds.Name, "cluster", ds.Spec.Cluster)

	var cleanupErrors []error
	remainingStatuses := make([]breakglassv1alpha1.PodTemplateResourceStatus, 0, len(ds.Status.PodTemplateResourceStatuses))

	for i := range ds.Status.PodTemplateResourceStatuses {
		status := &ds.Status.PodTemplateResourceStatuses[i]

		// Skip if already deleted
		if status.Deleted {
			continue
		}

		// A missing create response leaves an intent with no UID. Keep it and
		// retry rather than looking up a same-name replacement. A recorded UID
		// is enough to continue cleanup safely even if Created was not persisted.
		if status.UID == "" && (!status.Created || status.CreateOperationID != "") {
			status.Error = "creation outcome unresolved; cleanup retry required"
			remainingStatuses = append(remainingStatuses, *status)
			cleanupErrors = append(cleanupErrors, fmt.Errorf("pod template resource %s/%s creation outcome is unresolved", status.Namespace, status.ResourceName))
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
			remainingStatuses = append(remainingStatuses, *status)
			cleanupErrors = append(cleanupErrors, fmt.Errorf("parse GVK for pod template resource %s/%s: %w", status.Namespace, status.ResourceName, err))
			continue
		}

		obj := &unstructured.Unstructured{}
		obj.SetGroupVersionKind(gvk)
		obj.SetName(status.ResourceName)
		obj.SetNamespace(status.Namespace)
		if status.UID != "" {
			obj.SetUID(types.UID(status.UID))
		}

		if err := deleteTrackedResource(ctx, targetClient, ds, obj); err != nil {
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
				remainingStatuses = append(remainingStatuses, *status)
				cleanupErrors = append(cleanupErrors, fmt.Errorf("delete pod template resource %s %s/%s: %w", status.Kind, status.Namespace, status.ResourceName, err))
				continue
			}
		} else {
			// DELETE can be accepted while a finalizer keeps the object live.
			// Keep the specialized status and deployed-resource inventory until a
			// later reconcile confirms that the recorded instance is gone. This
			// prevents the generic cleanup pass from issuing a second delete with
			// incomplete legacy identity data.
			remaining := &unstructured.Unstructured{}
			remaining.SetGroupVersionKind(gvk)
			remaining.SetName(status.ResourceName)
			remaining.SetNamespace(status.Namespace)
			if getErr := targetClient.Get(ctx, ctrlclient.ObjectKeyFromObject(remaining), remaining); getErr == nil {
				expectedUID := types.UID(status.UID)
				if expectedUID != "" && remaining.GetUID() == expectedUID {
					status.Error = "delete accepted but resource remains pending finalizers"
					remainingStatuses = append(remainingStatuses, *status)
					cleanupErrors = append(cleanupErrors, fmt.Errorf("delete pod template resource %s %s/%s is pending finalizers", status.Kind, status.Namespace, status.ResourceName))
					continue
				}
			} else if !apierrors.IsNotFound(getErr) {
				status.Error = fmt.Sprintf("verify deletion failed: %v", getErr)
				remainingStatuses = append(remainingStatuses, *status)
				cleanupErrors = append(cleanupErrors, fmt.Errorf("verify deletion of pod template resource %s %s/%s: %w", status.Kind, status.Namespace, status.ResourceName, getErr))
				continue
			}
			log.Infow("Deleted pod template resource",
				"kind", status.Kind,
				"name", status.ResourceName,
				"namespace", status.Namespace)
		}

		status.Deleted = true
		now := time.Now().UTC().Format(time.RFC3339)
		status.DeletedAt = &now
	}

	ds.Status.PodTemplateResourceStatuses = remainingStatuses
	return errors.Join(cleanupErrors...)
}

// parseDuration parses the requested duration with template constraints.
// Supports day, week, and year units (e.g., "1d", "1w", "1y") in addition to standard Go duration units.
func (c *DebugSessionController) parseDuration(requested string, constraints *breakglassv1alpha1.DebugSessionConstraints) time.Duration {
	defaultDur := time.Hour
	maxDur := 4 * time.Hour

	if constraints != nil {
		if d, err := breakglassv1alpha1.ParseDuration(constraints.DefaultDuration); err == nil && d > 0 {
			defaultDur = d
		}
		if d, err := breakglassv1alpha1.ParseDuration(constraints.MaxDuration); err == nil && d > 0 {
			maxDur = d
		}
	}
	if defaultDur > maxDur {
		defaultDur = maxDur
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

// reconcilePeriodicActiveAccounting coalesces periodic repairs per template.
// Lifecycle transitions bypass this throttle, and failed repairs remain retryable.
func (c *DebugSessionController) reconcilePeriodicActiveAccounting(ctx context.Context, ds *breakglassv1alpha1.DebugSession) error {
	_, err, _ := c.accountingFlight.Do(ds.Spec.TemplateRef, func() (any, error) {
		c.accountingMu.Lock()
		last := c.accountingLast[ds.Spec.TemplateRef]
		failureVersion := c.accountingFailureVersion
		c.accountingMu.Unlock()
		if time.Since(last) < DefaultDebugSessionRequeue {
			return nil, nil
		}
		if err := c.reconcileActiveAccounting(ctx, ds, true); err != nil {
			return nil, err
		}
		c.accountingMu.Lock()
		defer c.accountingMu.Unlock()
		// A lifecycle failure racing this scan must still get an immediate retry.
		if failureVersion != c.accountingFailureVersion {
			return nil, nil
		}
		// Bound process-local repair bookkeeping; eviction only adds a repair.
		if c.accountingLast == nil {
			c.accountingLast = make(map[string]time.Time)
		}
		if _, exists := c.accountingLast[ds.Spec.TemplateRef]; !exists && len(c.accountingLast) >= 1024 {
			var oldest string
			for name, repaired := range c.accountingLast {
				if oldest == "" || repaired.Before(c.accountingLast[oldest]) {
					oldest = name
				}
			}
			delete(c.accountingLast, oldest)
		}
		c.accountingLast[ds.Spec.TemplateRef] = time.Now()
		return nil, nil
	})
	return err
}

// lockActiveAccounting serializes scans and metric publication for one template.
// Entries exist only while workers are using or waiting for that template.
func (c *DebugSessionController) lockActiveAccounting(template string) func() {
	c.accountingMu.Lock()
	if c.accountingLocks == nil {
		c.accountingLocks = make(map[string]*accountingLock)
	}
	entry := c.accountingLocks[template]
	if entry == nil {
		entry = &accountingLock{}
		c.accountingLocks[template] = entry
	}
	entry.users++
	c.accountingMu.Unlock()
	entry.mu.Lock()
	return func() {
		entry.mu.Unlock()
		c.accountingMu.Lock()
		entry.users--
		if entry.users == 0 {
			delete(c.accountingLocks, template)
		}
		c.accountingMu.Unlock()
	}
}

// reconcileActiveAccounting derives aggregates from authoritative session state.
// Template CAS retries repeat the list; periodic Active reconciliation repairs
// snapshots raced by a session transition without replaying increment/decrement.
func (c *DebugSessionController) reconcileActiveAccounting(ctx context.Context, ds *breakglassv1alpha1.DebugSession, markUsed bool) (resultErr error) {
	unlock := c.lockActiveAccounting(ds.Spec.TemplateRef)
	defer unlock()
	defer func() {
		if resultErr != nil {
			c.accountingMu.Lock()
			delete(c.accountingLast, ds.Spec.TemplateRef)
			c.accountingFailureVersion++
			c.accountingMu.Unlock()
		}
	}()
	reader := c.approvalReader()
	var templateUID types.UID
	var podTemplateName string
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		template := &breakglassv1alpha1.DebugSessionTemplate{}
		templateExists := ds.Spec.TemplateRef != ""
		if templateExists {
			if err := reader.Get(ctx, ctrlclient.ObjectKey{Name: ds.Spec.TemplateRef}, template); err != nil {
				if !apierrors.IsNotFound(err) {
					return fmt.Errorf("read accounting template: %w", err)
				}
				templateExists = false
			}
			if templateExists {
				if templateUID != "" && template.UID != templateUID {
					return fmt.Errorf("accounting template identity changed")
				}
				templateUID = template.UID
			}
		}
		var total int32
		clusterCounts := map[string]int32{ds.Spec.Cluster: 0}
		var latestStart *metav1.Time
		continuation := ""
		for {
			var sessions breakglassv1alpha1.DebugSessionList
			if err := reader.List(ctx, &sessions, &ctrlclient.ListOptions{Limit: 500, Continue: continuation, Raw: &metav1.ListOptions{FieldSelector: fields.OneTermEqualSelector("spec.templateRef", ds.Spec.TemplateRef).String()}}); err != nil {
				return fmt.Errorf("list accounting sessions: %w", err)
			}
			for i := range sessions.Items {
				session := &sessions.Items[i]
				if session.Spec.TemplateRef != ds.Spec.TemplateRef {
					continue
				}
				if _, ok := clusterCounts[session.Spec.Cluster]; !ok {
					clusterCounts[session.Spec.Cluster] = 0
				}
				if session.Status.State == breakglassv1alpha1.DebugSessionStateActive {
					total++
					clusterCounts[session.Spec.Cluster]++
				}
				if session.Status.StartsAt != nil && (latestStart == nil || latestStart.Before(session.Status.StartsAt)) {
					latestStart = session.Status.StartsAt.DeepCopy()
				}
			}
			continuation = sessions.Continue
			if continuation == "" {
				break
			}
		}
		if templateExists {
			base := template.DeepCopy()
			template.Status.ActiveSessionCount = total
			if latestStart != nil && (template.Status.LastUsedAt == nil || template.Status.LastUsedAt.Before(latestStart)) {
				template.Status.LastUsedAt = latestStart
			}
			if base.Status.ActiveSessionCount != template.Status.ActiveSessionCount || !base.Status.LastUsedAt.Equal(template.Status.LastUsedAt) {
				if err := c.client.Status().Patch(ctx, template, ctrlclient.MergeFromWithOptions(base, ctrlclient.MergeFromWithOptimisticLock{})); err != nil {
					return fmt.Errorf("patch accounting template: %w", err)
				}
			}
			if (markUsed || latestStart != nil) && template.Spec.PodTemplateRef != nil {
				podTemplateName = template.Spec.PodTemplateRef.Name
			}
		}
		for clusterName, count := range clusterCounts {
			metrics.DebugSessionsActive.WithLabelValues(clusterName, ds.Spec.TemplateRef).Set(float64(count))
		}
		return nil
	})
	if err != nil {
		return err
	}
	if podTemplateName != "" {
		if err := c.updatePodTemplateUsedBy(ctx, podTemplateName, ds.Spec.TemplateRef); err != nil {
			c.log.Warnw("Failed to repair optional pod template usage; periodic reconciliation will retry", "podTemplate", podTemplateName, "error", err)
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

// Legacy source-less references still need auxiliary policy resolution before
// generic deletion. Coordinates select the policy lane, never deletion authority.
func auxiliaryResourceCoordinatesKnown(ds *breakglassv1alpha1.DebugSession, ref breakglassv1alpha1.DeployedResourceRef) bool {
	for _, status := range ds.Status.AuxiliaryResourceStatuses {
		if status.Kind == ref.Kind && status.APIVersion == ref.APIVersion && status.ResourceName == ref.Name && status.Namespace == ref.Namespace {
			return true
		}
		for _, child := range status.AdditionalResources {
			if child.Kind == ref.Kind && child.APIVersion == ref.APIVersion && child.ResourceName == ref.Name && child.Namespace == ref.Namespace {
				return true
			}
		}
	}
	return false
}
