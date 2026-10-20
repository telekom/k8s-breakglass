// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/audit"
	"github.com/telekom/k8s-breakglass/pkg/breakglass"
	"github.com/telekom/k8s-breakglass/pkg/metrics"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrl "sigs.k8s.io/controller-runtime"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

// admissionRecipeFinalizer keeps a session until every changed target is reverted.
const admissionRecipeFinalizer = "breakglass.t-caas.telekom.com/admission-recipe-revert"

// admissionRecipeActiveRequeue bounds drift detection latency while a recipe is active.
const admissionRecipeActiveRequeue = 30 * time.Second

func hasAdmissionRecipeFinalizer(ds *breakglassv1alpha1.DebugSession) bool {
	return controllerutil.ContainsFinalizer(ds, admissionRecipeFinalizer)
}

func (c *DebugSessionController) ensureAdmissionRecipeFinalizer(ctx context.Context, ds *breakglassv1alpha1.DebugSession) error {
	if hasAdmissionRecipeFinalizer(ds) {
		return nil
	}
	if !ds.DeletionTimestamp.IsZero() {
		return fmt.Errorf("admissionRecipe session is being deleted")
	}
	base := ds.DeepCopy()
	controllerutil.AddFinalizer(ds, admissionRecipeFinalizer)
	return c.client.Patch(ctx, ds, ctrlclient.MergeFromWithOptions(base, ctrlclient.MergeFromWithOptimisticLock{}))
}

func (c *DebugSessionController) removeAdmissionRecipeFinalizer(ctx context.Context, ds *breakglassv1alpha1.DebugSession) error {
	base := ds.DeepCopy()
	controllerutil.RemoveFinalizer(ds, admissionRecipeFinalizer)
	return c.client.Patch(ctx, ds, ctrlclient.MergeFromWithOptions(base, ctrlclient.MergeFromWithOptimisticLock{}))
}

func admissionRecipeIdentity(value string) string {
	digest := sha256.Sum256([]byte(value))
	return "admission-recipe-" + hex.EncodeToString(digest[:16])
}

// admissionRecipeApprovers mirrors the node-maintenance approval contract:
// explicit approvers, no auto-approval, blocked self-approval and no binding
// overrides that could widen the recipe.
func admissionRecipeApprovers(template *breakglassv1alpha1.DebugSessionTemplate, binding *breakglassv1alpha1.DebugSessionClusterBinding) error {
	if template.Spec.AdmissionRecipe == nil {
		return nil
	}
	approvers := template.Spec.Approvers
	if binding != nil && binding.Spec.Approvers != nil {
		approvers = binding.Spec.Approvers
	}
	if !debugSessionApproversConfigured(approvers) || approvers.AutoApproveFor != nil {
		return fmt.Errorf("admissionRecipe requires explicit independent approvers without auto-approval")
	}
	if !resolveDebugSessionBlockSelfApproval(template.Spec.BlockSelfApproval, binding) {
		return fmt.Errorf("admissionRecipe requires blocked self-approval")
	}
	if binding != nil && (binding.Spec.NamespaceConstraints != nil || len(binding.Spec.ExtraDeployVariables) != 0 ||
		len(binding.Spec.AuxiliaryResourceOverrides) != 0 || len(binding.Spec.RequiredAuxiliaryResourceCategories) != 0 ||
		binding.Spec.SchedulingConstraints != nil || binding.Spec.SchedulingOptions != nil || binding.Spec.Impersonation != nil) {
		return fmt.Errorf("admissionRecipe binding cannot introduce namespace, variable, scheduling, impersonation or auxiliary overrides")
	}
	if binding != nil && binding.Spec.Constraints != nil && binding.Spec.Constraints.IdleTimeout != "" {
		return fmt.Errorf("admissionRecipe binding cannot introduce an idleTimeout")
	}
	// The binding can only narrow durations, but it can enable renewal; check
	// the effective constraints before approval, not only at activation.
	effective := template.Spec.DeepCopy()
	effective.Constraints = effectiveDebugSessionConstraints(template, binding)
	return breakglassv1alpha1.ValidateAdmissionRecipeTemplate(effective)
}

func admissionRecipeGVK(target breakglassv1alpha1.AdmissionRecipeTarget) schema.GroupVersionKind {
	if target.Kind == "ValidatingPolicy" {
		return schema.FromAPIVersionAndKind(target.APIVersion, target.Kind)
	}
	return schema.GroupVersionKind{Group: "admissionregistration.k8s.io", Version: "v1", Kind: target.Kind}
}

func getAdmissionRecipeTarget(ctx context.Context, target ctrlclient.Reader, item breakglassv1alpha1.AdmissionRecipeTarget) (*unstructured.Unstructured, error) {
	obj := &unstructured.Unstructured{}
	obj.SetGroupVersionKind(admissionRecipeGVK(item))
	if err := target.Get(ctx, ctrlclient.ObjectKey{Name: item.Name}, obj); err != nil {
		return nil, err
	}
	return obj, nil
}

// admissionRecipeField returns the JSON of the recipe field and whether the
// object holds the expected starting value for the action.
func admissionRecipeField(action string, item breakglassv1alpha1.AdmissionRecipeTarget, obj *unstructured.Unstructured) (string, bool, error) {
	switch action {
	case breakglassv1alpha1.AdmissionRecipePolicyAudit:
		actions, found, err := unstructured.NestedStringSlice(obj.Object, "spec", "validationActions")
		if err != nil {
			return "", false, fmt.Errorf("read validationActions: %w", err)
		}
		if !found {
			actions = []string{}
		}
		raw, err := json.Marshal(actions)
		if err != nil {
			return "", false, err
		}
		deny := false
		for _, value := range actions {
			if value == "Deny" {
				deny = true
			}
		}
		return string(raw), deny, nil
	case breakglassv1alpha1.AdmissionRecipeWebhookFailOpen:
		webhooks, _, err := unstructured.NestedSlice(obj.Object, "webhooks")
		if err != nil {
			return "", false, fmt.Errorf("read webhooks: %w", err)
		}
		for _, entry := range webhooks {
			webhook, ok := entry.(map[string]interface{})
			if !ok || webhook["name"] != item.Webhook {
				continue
			}
			policy, _ := webhook["failurePolicy"].(string)
			if policy == "" {
				policy = "Fail"
			}
			raw, err := json.Marshal(policy)
			if err != nil {
				return "", false, err
			}
			return string(raw), policy == "Fail", nil
		}
		return "", false, fmt.Errorf("webhook %q not found in %s", item.Webhook, item.Name)
	default:
		return "", false, fmt.Errorf("unsupported admission recipe action %q", action)
	}
}

func admissionRecipeAppliedValue(action string) string {
	if action == breakglassv1alpha1.AdmissionRecipePolicyAudit {
		return `["Audit"]`
	}
	return `"Ignore"`
}

// setAdmissionRecipeField writes a JSON value produced by admissionRecipeField.
func setAdmissionRecipeField(action string, item breakglassv1alpha1.AdmissionRecipeTarget, obj *unstructured.Unstructured, value string) error {
	switch action {
	case breakglassv1alpha1.AdmissionRecipePolicyAudit:
		var actions []string
		if err := json.Unmarshal([]byte(value), &actions); err != nil {
			return err
		}
		return unstructured.SetNestedStringSlice(obj.Object, actions, "spec", "validationActions")
	case breakglassv1alpha1.AdmissionRecipeWebhookFailOpen:
		var policy string
		if err := json.Unmarshal([]byte(value), &policy); err != nil {
			return err
		}
		webhooks, _, err := unstructured.NestedSlice(obj.Object, "webhooks")
		if err != nil {
			return err
		}
		for i, entry := range webhooks {
			webhook, ok := entry.(map[string]interface{})
			if ok && webhook["name"] == item.Webhook {
				webhook["failurePolicy"] = policy
				webhooks[i] = webhook
				return unstructured.SetNestedSlice(obj.Object, webhooks, "webhooks")
			}
		}
		return fmt.Errorf("webhook %q not found in %s", item.Webhook, item.Name)
	default:
		return fmt.Errorf("unsupported admission recipe action %q", action)
	}
}

func admissionRecipeFluxAnnotations() []string {
	return []string{breakglassv1alpha1.FluxHelmDriftDetectionAnnotation, breakglassv1alpha1.FluxKustomizeReconcileAnnotation}
}

// checkAdmissionRecipeTarget refuses denied, foreign-owned or unexpected targets.
func checkAdmissionRecipeTarget(recipe *breakglassv1alpha1.DebugSessionAdmissionRecipe, item breakglassv1alpha1.AdmissionRecipeTarget, obj *unstructured.Unstructured, sessionUID string) error {
	if match, denied := breakglassv1alpha1.AdmissionRecipeDeniedBy(recipe.DeniedTargetLabels, obj.GetLabels()); denied {
		return fmt.Errorf("admissionRecipe target %s is denied by label %s", breakglassv1alpha1.AdmissionRecipeTargetKey(item), match)
	}
	if owner := obj.GetAnnotations()[breakglassv1alpha1.AdmissionRecipeSessionAnnotation]; owner != "" && owner != sessionUID {
		return fmt.Errorf("admissionRecipe target %s is already changed by another session", breakglassv1alpha1.AdmissionRecipeTargetKey(item))
	}
	if !obj.GetDeletionTimestamp().IsZero() {
		return fmt.Errorf("admissionRecipe target %s is being deleted", breakglassv1alpha1.AdmissionRecipeTargetKey(item))
	}
	return nil
}

// validateAdmissionRecipePending checks the request and the live targets
// before the session reaches approval, so an impossible request fails early.
func (c *DebugSessionController) validateAdmissionRecipePending(ctx context.Context, ds *breakglassv1alpha1.DebugSession, template *breakglassv1alpha1.DebugSessionTemplate, binding *breakglassv1alpha1.DebugSessionClusterBinding) error {
	if err := breakglassv1alpha1.ValidateAdmissionRecipeSession(&template.Spec, &ds.Spec); err != nil {
		return err
	}
	if template.Spec.AdmissionRecipe == nil {
		return nil
	}
	if ds.UID != "" && !ds.Status.AuthenticatedUserGroupsCaptured {
		return fmt.Errorf("admissionRecipe requires authenticated API requester provenance")
	}
	if err := admissionRecipeApprovers(template, binding); err != nil {
		return err
	}
	if ds.Status.AdmissionRecipe != nil {
		// Already applied or reverted: the live values are no longer the starting values.
		return nil
	}
	target, fence, release, err := c.maintenanceClient(ctx, ds)
	if err != nil {
		return fmt.Errorf("%w: %w", errMaintenanceTargetUnavailable, err)
	}
	defer release()
	if err := fence(); err != nil {
		return fmt.Errorf("%w: %w", errMaintenanceTargetUnavailable, err)
	}
	recipe := template.Spec.AdmissionRecipe
	for _, item := range ds.Spec.AdmissionRecipe.Targets {
		obj, err := getAdmissionRecipeTarget(ctx, target, item)
		if err != nil {
			if apierrors.IsNotFound(err) {
				return fmt.Errorf("admissionRecipe target %s does not exist", breakglassv1alpha1.AdmissionRecipeTargetKey(item))
			}
			return fmt.Errorf("%w: read admissionRecipe target: %w", errMaintenanceTargetUnavailable, err)
		}
		if err := checkAdmissionRecipeTarget(recipe, item, obj, string(ds.UID)); err != nil {
			return err
		}
		if _, ok, err := admissionRecipeField(recipe.Action, item, obj); err != nil || !ok {
			if err == nil {
				err = fmt.Errorf("admissionRecipe target %s does not have the expected starting value", breakglassv1alpha1.AdmissionRecipeTargetKey(item))
			}
			return err
		}
	}
	return nil
}

// admissionRecipeFence re-reads the live session immediately before a target
// write that widens admission. Reverts do not use it: restoring the original
// value is always allowed.
func (c *DebugSessionController) admissionRecipeFence(ctx context.Context, ds *breakglassv1alpha1.DebugSession, configurationFence func() error) error {
	if c.beforeDebugTargetWrite != nil {
		c.beforeDebugTargetWrite("admission-recipe")
	}
	if err := configurationFence(); err != nil {
		return err
	}
	reader := c.reader
	if reader == nil {
		reader = c.client
	}
	live := &breakglassv1alpha1.DebugSession{}
	if err := reader.Get(ctx, ctrlclient.ObjectKeyFromObject(ds), live); err != nil {
		return err
	}
	if live.UID != ds.UID || !live.DeletionTimestamp.IsZero() || !maintenanceApproved(live) ||
		live.Status.ResolvedTemplate == nil || live.Status.ExpiresAt == nil ||
		!time.Now().UTC().Before(live.Status.ExpiresAt.Time) ||
		(live.Status.State != breakglassv1alpha1.DebugSessionStatePendingApproval && live.Status.State != breakglassv1alpha1.DebugSessionStateActive) {
		return fmt.Errorf("admissionRecipe session is no longer approved and live")
	}
	if err := breakglassv1alpha1.ValidateAdmissionRecipeSession(live.Status.ResolvedTemplate, &live.Spec); err != nil {
		return err
	}
	if !reflect.DeepEqual(live.Spec.AdmissionRecipe, ds.Spec.AdmissionRecipe) ||
		!reflect.DeepEqual(live.Status.Approval, ds.Status.Approval) ||
		!reflect.DeepEqual(live.Status.ResolvedTemplate, ds.Status.ResolvedTemplate) ||
		!reflect.DeepEqual(live.Status.ResolvedBinding, ds.Status.ResolvedBinding) ||
		!reflect.DeepEqual(live.Status.ResolvedBindingSpec, ds.Status.ResolvedBindingSpec) ||
		!reflect.DeepEqual(live.Status.AdmissionRecipe, ds.Status.AdmissionRecipe) {
		return fmt.Errorf("admissionRecipe request or inventory changed before target write")
	}
	return nil
}

func (c *DebugSessionController) patchAdmissionRecipeStatus(ctx context.Context, ds *breakglassv1alpha1.DebugSession, mutate func(*breakglassv1alpha1.AdmissionRecipeStatus)) error {
	reader := c.reader
	if reader == nil {
		reader = c.client
	}
	return breakglass.PatchDebugSessionStatusWithReader(ctx, c.client, reader, ds, func(status *breakglassv1alpha1.DebugSessionStatus) {
		if status.AdmissionRecipe == nil {
			status.AdmissionRecipe = &breakglassv1alpha1.AdmissionRecipeStatus{}
		}
		mutate(status.AdmissionRecipe)
	})
}

func (c *DebugSessionController) auditAdmissionRecipe(ctx context.Context, ds *breakglassv1alpha1.DebugSession, eventType audit.EventType, stage string) error {
	if ds.Status.ResolvedTemplate == nil || ds.Status.ResolvedTemplate.AdmissionRecipe == nil ||
		ds.Status.AdmissionRecipe == nil || ds.Status.Approval == nil {
		return fmt.Errorf("admissionRecipe audit provenance is incomplete")
	}
	targets := make([]map[string]interface{}, 0, len(ds.Status.AdmissionRecipe.Targets))
	for _, item := range ds.Status.AdmissionRecipe.Targets {
		targets = append(targets, map[string]interface{}{
			"target": breakglassv1alpha1.AdmissionRecipeTargetKey(item.Target), "state": item.State,
			"original": item.Original, "applied": item.Applied, "message": item.Message,
		})
	}
	event := &audit.Event{
		ID: ds.Status.AdmissionRecipe.OperationID + "-" + stage, Type: eventType, Timestamp: time.Now().UTC(),
		Severity: audit.SeverityCritical,
		Actor:    audit.Actor{User: ds.Spec.RequestedBy, IdentityProvider: ds.Spec.IdentityProviderName},
		Target:   audit.Target{Kind: "AdmissionRecipe", Name: ds.Status.ResolvedTemplate.AdmissionRecipe.Action, Cluster: ds.Spec.Cluster},
		Details: map[string]interface{}{"sessionUID": string(ds.UID), "operationID": ds.Status.AdmissionRecipe.OperationID,
			"approvedBy": ds.Status.Approval.ApprovedBy, "approvedAt": ds.Status.Approval.ApprovedAt,
			"action": ds.Status.ResolvedTemplate.AdmissionRecipe.Action, "targets": targets},
	}
	if c.auditService != nil {
		return c.auditService.EmitSync(ctx, event)
	}
	if manager := c.currentAuditManager(); manager != nil {
		return manager.EmitSync(ctx, event)
	}
	return fmt.Errorf("admissionRecipe requires a synchronous durable audit sink")
}

// applyAdmissionRecipe performs the approved field transitions. Each target's
// original value and intent are persisted before its write, so a restart or
// an ambiguous write never loses the revert information. A conflict (a
// concurrent writer on the target or the session) is retried by the next
// reconcile instead of failing the session.
func (c *DebugSessionController) applyAdmissionRecipe(ctx context.Context, ds *breakglassv1alpha1.DebugSession) error {
	err := c.applyAdmissionRecipeOnce(ctx, ds)
	if apierrors.IsConflict(err) {
		return &debugSessionStatusConflict{err: err}
	}
	return err
}

func (c *DebugSessionController) applyAdmissionRecipeOnce(ctx context.Context, ds *breakglassv1alpha1.DebugSession) error {
	if ds.Status.ResolvedTemplate == nil || ds.Status.ResolvedTemplate.AdmissionRecipe == nil || !maintenanceApproved(ds) {
		return fmt.Errorf("admissionRecipe requires an independently approved immutable template snapshot")
	}
	recipe := ds.Status.ResolvedTemplate.AdmissionRecipe
	if err := breakglassv1alpha1.ValidateAdmissionRecipeSession(ds.Status.ResolvedTemplate, &ds.Spec); err != nil {
		return err
	}
	if ds.UID == "" || ds.Status.ExpiresAt == nil {
		return fmt.Errorf("admissionRecipe requires a durable session UID and expiry")
	}
	if err := c.ensureAdmissionRecipeFinalizer(ctx, ds); err != nil {
		return err
	}
	target, configurationFence, release, err := c.maintenanceClient(ctx, ds)
	if err != nil {
		return err
	}
	defer release()
	if ds.Status.AdmissionRecipe == nil {
		inventory := &breakglassv1alpha1.AdmissionRecipeStatus{OperationID: admissionRecipeIdentity(string(ds.UID))}
		for _, item := range ds.Spec.AdmissionRecipe.Targets {
			inventory.Targets = append(inventory.Targets, breakglassv1alpha1.AdmissionRecipeTargetStatus{
				Target: item, State: breakglassv1alpha1.AdmissionRecipeTargetNotApplied,
			})
		}
		// The intent receipt precedes the inventory and every widening write. A
		// retry after a failed status patch re-sends the same deterministic event ID.
		receipt := ds.DeepCopy()
		receipt.Status.AdmissionRecipe = inventory
		if err := c.auditAdmissionRecipe(ctx, receipt, audit.EventDebugSessionAdmissionRecipeApplied, "intent"); err != nil {
			return err
		}
		if err := c.patchAdmissionRecipeStatus(ctx, ds, func(status *breakglassv1alpha1.AdmissionRecipeStatus) {
			*status = *inventory.DeepCopy()
		}); err != nil {
			return err
		}
	}
	sessionUID := string(ds.UID)
	applied := admissionRecipeAppliedValue(recipe.Action)
	for i := range ds.Status.AdmissionRecipe.Targets {
		entry := ds.Status.AdmissionRecipe.Targets[i]
		if entry.State != breakglassv1alpha1.AdmissionRecipeTargetNotApplied && entry.State != breakglassv1alpha1.AdmissionRecipeTargetApplying {
			continue
		}
		item := entry.Target
		obj, err := getAdmissionRecipeTarget(ctx, target, item)
		if err != nil {
			return fmt.Errorf("read admissionRecipe target %s: %w", breakglassv1alpha1.AdmissionRecipeTargetKey(item), err)
		}
		if entry.State == breakglassv1alpha1.AdmissionRecipeTargetApplying &&
			obj.GetAnnotations()[breakglassv1alpha1.AdmissionRecipeSessionAnnotation] == sessionUID {
			// The write succeeded before a restart; only the status was lost.
			if err := c.setAdmissionRecipeTargetState(ctx, ds, i, breakglassv1alpha1.AdmissionRecipeTargetApplied, ""); err != nil {
				return err
			}
			continue
		}
		if err := checkAdmissionRecipeTarget(recipe, item, obj, sessionUID); err != nil {
			return err
		}
		current, ok, err := admissionRecipeField(recipe.Action, item, obj)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("admissionRecipe target %s does not have the expected starting value %s", breakglassv1alpha1.AdmissionRecipeTargetKey(item), current)
		}
		originalAnnotations := map[string]string{}
		if recipe.Flux {
			for _, key := range admissionRecipeFluxAnnotations() {
				originalAnnotations[key] = obj.GetAnnotations()[key]
			}
		}
		if err := c.patchAdmissionRecipeStatus(ctx, ds, func(status *breakglassv1alpha1.AdmissionRecipeStatus) {
			status.Targets[i].State = breakglassv1alpha1.AdmissionRecipeTargetApplying
			status.Targets[i].Original = current
			status.Targets[i].Applied = applied
			status.Targets[i].OriginalAnnotations = originalAnnotations
		}); err != nil {
			return err
		}
		if err := setAdmissionRecipeField(recipe.Action, item, obj, applied); err != nil {
			return err
		}
		annotations := obj.GetAnnotations()
		if annotations == nil {
			annotations = map[string]string{}
		}
		annotations[breakglassv1alpha1.AdmissionRecipeSessionAnnotation] = sessionUID
		annotations[breakglassv1alpha1.AdmissionRecipeExpiresAnnotation] = ds.Status.ExpiresAt.UTC().Format(time.RFC3339)
		if recipe.Flux {
			annotations[breakglassv1alpha1.FluxHelmDriftDetectionAnnotation] = "disabled"
			annotations[breakglassv1alpha1.FluxKustomizeReconcileAnnotation] = "disabled"
		}
		obj.SetAnnotations(annotations)
		if err := c.admissionRecipeFence(ctx, ds, configurationFence); err != nil {
			return err
		}
		// Update carries the read resourceVersion, so a concurrent change fails the write.
		if err := target.Update(ctx, obj); err != nil {
			metrics.AdmissionRecipeOperations.WithLabelValues(ds.Spec.Cluster, recipe.Action, "apply", "failure").Inc()
			return fmt.Errorf("apply admissionRecipe target %s: %w", breakglassv1alpha1.AdmissionRecipeTargetKey(item), err)
		}
		metrics.AdmissionRecipeOperations.WithLabelValues(ds.Spec.Cluster, recipe.Action, "apply", "success").Inc()
		if err := c.setAdmissionRecipeTargetState(ctx, ds, i, breakglassv1alpha1.AdmissionRecipeTargetApplied, ""); err != nil {
			return err
		}
	}
	return nil
}

func (c *DebugSessionController) setAdmissionRecipeTargetState(ctx context.Context, ds *breakglassv1alpha1.DebugSession, index int, state, message string) error {
	return c.patchAdmissionRecipeStatus(ctx, ds, func(status *breakglassv1alpha1.AdmissionRecipeStatus) {
		if index < len(status.Targets) {
			status.Targets[index].State = state
			status.Targets[index].Message = message
		}
	})
}

// detectAdmissionRecipeDrift reports, but never overwrites, a target that
// someone else changed during the window.
func (c *DebugSessionController) detectAdmissionRecipeDrift(ctx context.Context, ds *breakglassv1alpha1.DebugSession) error {
	status := ds.Status.AdmissionRecipe
	if status == nil || ds.Status.ResolvedTemplate == nil || ds.Status.ResolvedTemplate.AdmissionRecipe == nil {
		return nil
	}
	recipe := ds.Status.ResolvedTemplate.AdmissionRecipe
	target, configurationFence, release, err := c.maintenanceClient(ctx, ds)
	if err != nil {
		return err
	}
	defer release()
	if err := configurationFence(); err != nil {
		return err
	}
	type drift struct {
		index   int
		message string
	}
	var drifts []drift
	for i, entry := range status.Targets {
		if entry.State != breakglassv1alpha1.AdmissionRecipeTargetApplied {
			continue
		}
		message := ""
		obj, err := getAdmissionRecipeTarget(ctx, target, entry.Target)
		switch {
		case apierrors.IsNotFound(err):
			message = "target object was deleted"
		case err != nil:
			return err
		case obj.GetAnnotations()[breakglassv1alpha1.AdmissionRecipeSessionAnnotation] != string(ds.UID):
			message = "session annotation was removed or replaced"
		default:
			current, _, fieldErr := admissionRecipeField(recipe.Action, entry.Target, obj)
			if fieldErr != nil {
				message = fieldErr.Error()
			} else if current != entry.Applied {
				message = fmt.Sprintf("field changed to %s by another writer", current)
			}
		}
		if message == "" {
			continue
		}
		drifts = append(drifts, drift{index: i, message: message})
	}
	if len(drifts) == 0 {
		return nil
	}
	// The drift receipt precedes the state change, like every other recipe
	// receipt: a failed audit leaves the targets applied, so the next check
	// reports the drift again under the same event ID.
	receipt := ds.DeepCopy()
	keys := make([]string, 0, len(drifts))
	for _, d := range drifts {
		entry := &receipt.Status.AdmissionRecipe.Targets[d.index]
		entry.State, entry.Message = breakglassv1alpha1.AdmissionRecipeTargetDrifted, d.message
		keys = append(keys, breakglassv1alpha1.AdmissionRecipeTargetKey(entry.Target))
	}
	digest := sha256.Sum256([]byte(strings.Join(keys, "\n")))
	if err := c.auditAdmissionRecipe(ctx, receipt, audit.EventDebugSessionAdmissionRecipeDrift, "drift-"+hex.EncodeToString(digest[:8])); err != nil {
		return err
	}
	for _, d := range drifts {
		metrics.AdmissionRecipeOperations.WithLabelValues(ds.Spec.Cluster, recipe.Action, "drift", "detected").Inc()
		if err := c.setAdmissionRecipeTargetState(ctx, ds, d.index, breakglassv1alpha1.AdmissionRecipeTargetDrifted, d.message); err != nil {
			return err
		}
	}
	return nil
}

// revertAdmissionRecipe restores every value that this session still owns.
// It needs no approval fence: restoring the original never widens admission.
func (c *DebugSessionController) revertAdmissionRecipe(ctx context.Context, ds *breakglassv1alpha1.DebugSession) error {
	status := ds.Status.AdmissionRecipe
	if status == nil || status.Reverted {
		return nil
	}
	if ds.Status.ResolvedTemplate == nil || ds.Status.ResolvedTemplate.AdmissionRecipe == nil {
		return fmt.Errorf("admissionRecipe revert provenance is incomplete")
	}
	recipe := ds.Status.ResolvedTemplate.AdmissionRecipe
	target, configurationFence, release, err := c.maintenanceClient(ctx, ds)
	if err != nil {
		return err
	}
	defer release()
	if err := configurationFence(); err != nil {
		return err
	}
	sessionUID := string(ds.UID)
	var errs []error
	for i := range ds.Status.AdmissionRecipe.Targets {
		entry := ds.Status.AdmissionRecipe.Targets[i]
		switch entry.State {
		case breakglassv1alpha1.AdmissionRecipeTargetReverted, breakglassv1alpha1.AdmissionRecipeTargetRevertSkipped,
			breakglassv1alpha1.AdmissionRecipeTargetNotApplied:
			continue
		}
		obj, err := getAdmissionRecipeTarget(ctx, target, entry.Target)
		if apierrors.IsNotFound(err) {
			errs = append(errs, c.setAdmissionRecipeTargetState(ctx, ds, i, breakglassv1alpha1.AdmissionRecipeTargetRevertSkipped, "target object was deleted"))
			continue
		}
		if err != nil {
			errs = append(errs, err)
			continue
		}
		owner := obj.GetAnnotations()[breakglassv1alpha1.AdmissionRecipeSessionAnnotation]
		// A confirmed write whose session annotation alone was stripped is
		// still restored when the field still holds the value this session
		// wrote: restoring the original never widens admission.
		confirmed := entry.State == breakglassv1alpha1.AdmissionRecipeTargetApplied || entry.State == breakglassv1alpha1.AdmissionRecipeTargetDrifted
		if owner != sessionUID && (owner != "" || !confirmed) {
			state, message := breakglassv1alpha1.AdmissionRecipeTargetRevertSkipped, "session annotation was removed or replaced; field left as is"
			if entry.State == breakglassv1alpha1.AdmissionRecipeTargetApplying {
				// Most likely the write never happened; if it did and the
				// annotation was stripped later, the value is not ours to restore.
				state, message = breakglassv1alpha1.AdmissionRecipeTargetNotApplied, "session annotation absent at revert; field left as is"
			}
			errs = append(errs, c.setAdmissionRecipeTargetState(ctx, ds, i, state, message))
			continue
		}
		state, message := breakglassv1alpha1.AdmissionRecipeTargetReverted, ""
		current, _, fieldErr := admissionRecipeField(recipe.Action, entry.Target, obj)
		switch {
		case fieldErr != nil:
			// For example the webhook entry was removed: nothing to restore, but
			// the session annotations must still go so the target is not owned forever.
			state, message = breakglassv1alpha1.AdmissionRecipeTargetRevertSkipped, fieldErr.Error()
		case current == entry.Applied:
			// setAdmissionRecipeField fails only before it mutates obj (decode or
			// webhook lookup), so obj is still the read object if it errors.
			if err := setAdmissionRecipeField(recipe.Action, entry.Target, obj, entry.Original); err != nil {
				state, message = breakglassv1alpha1.AdmissionRecipeTargetRevertSkipped, err.Error()
			}
		case current == entry.Original:
			// An earlier revert wrote the target but could not record it
			// (for example a status conflict): the field is already restored.
		default:
			state, message = breakglassv1alpha1.AdmissionRecipeTargetRevertSkipped, fmt.Sprintf("field was changed to %s by another writer; left as is", current)
		}
		annotations := obj.GetAnnotations()
		delete(annotations, breakglassv1alpha1.AdmissionRecipeSessionAnnotation)
		delete(annotations, breakglassv1alpha1.AdmissionRecipeExpiresAnnotation)
		for key, value := range entry.OriginalAnnotations {
			if value == "" {
				delete(annotations, key)
			} else {
				annotations[key] = value
			}
		}
		obj.SetAnnotations(annotations)
		if err := target.Update(ctx, obj); err != nil {
			metrics.AdmissionRecipeOperations.WithLabelValues(ds.Spec.Cluster, recipe.Action, "revert", "failure").Inc()
			errs = append(errs, fmt.Errorf("revert admissionRecipe target %s: %w", breakglassv1alpha1.AdmissionRecipeTargetKey(entry.Target), err))
			continue
		}
		result := "success"
		if state == breakglassv1alpha1.AdmissionRecipeTargetRevertSkipped {
			result = "skipped"
		}
		metrics.AdmissionRecipeOperations.WithLabelValues(ds.Spec.Cluster, recipe.Action, "revert", result).Inc()
		errs = append(errs, c.setAdmissionRecipeTargetState(ctx, ds, i, state, message))
	}
	if err := errors.Join(errs...); err != nil {
		return err
	}
	if err := c.auditAdmissionRecipe(ctx, ds, audit.EventDebugSessionAdmissionRecipeReverted, "reverted"); err != nil {
		return err
	}
	return c.patchAdmissionRecipeStatus(ctx, ds, func(status *breakglassv1alpha1.AdmissionRecipeStatus) { status.Reverted = true })
}

// handleAdmissionRecipeActive watches for drift and expires the session at its
// hard deadline; the terminal cleanup path then reverts.
func (c *DebugSessionController) handleAdmissionRecipeActive(ctx context.Context, ds *breakglassv1alpha1.DebugSession) (ctrl.Result, error) {
	log := c.log.With("debugSession", ds.Name, "namespace", ds.Namespace)
	if ds.Status.AdmissionRecipe == nil {
		return c.failSession(ctx, ds, "admission recipe inventory is missing")
	}
	if err := c.detectAdmissionRecipeDrift(ctx, ds); err != nil {
		log.Warnw("Admission recipe drift check failed; will retry", "error", err)
	}
	now := time.Now().UTC()
	if isDebugSessionExpired(ds, now) {
		if err := breakglass.PatchDebugSessionStatusWithOptimisticLock(ctx, c.client, ds, func(status *breakglassv1alpha1.DebugSessionStatus) {
			status.State = breakglassv1alpha1.DebugSessionStateExpired
			status.Message = "Session expired; reverting admission recipe"
		}); err != nil {
			if apierrors.IsConflict(err) {
				return ctrl.Result{RequeueAfter: time.Millisecond}, nil
			}
			return ctrl.Result{}, err
		}
		c.sendDebugSessionExpiredEmail(*ds.DeepCopy())
		if c.shouldEmitAudit(ctx, ds) {
			if auditManager := c.currentAuditManager(); auditManager != nil {
				auditManager.DebugSessionExpired(ctx, ds.Name, ds.Namespace, ds.Spec.Cluster, ds.Spec.RequestedBy, ds.Spec.TemplateRef)
			}
		}
		if err := c.reconcileActiveAccounting(ctx, ds, false); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: time.Millisecond}, nil
	}
	requeue := admissionRecipeActiveRequeue
	if ds.Status.ExpiresAt == nil {
		return ctrl.Result{RequeueAfter: requeue}, nil
	}
	if until := ds.Status.ExpiresAt.Sub(now); until < requeue {
		requeue = max(until, time.Millisecond)
	}
	return ctrl.Result{RequeueAfter: requeue}, nil
}

// admissionRecipeTargetsDescription renders the targets for messages.
func admissionRecipeTargetsDescription(targets []breakglassv1alpha1.AdmissionRecipeTarget) string {
	parts := make([]string, 0, len(targets))
	for _, target := range targets {
		parts = append(parts, breakglassv1alpha1.AdmissionRecipeTargetKey(target))
	}
	return strings.Join(parts, ", ")
}
