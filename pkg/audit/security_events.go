// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"

	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
)

// lastFieldManager returns the field manager of the most recent managedFields
// entry. It names the client tool, not the authenticated user.
func lastFieldManager(obj metav1.Object) string {
	var manager string
	var latest *metav1.Time
	for _, entry := range obj.GetManagedFields() {
		if entry.Subresource != "" {
			continue
		}
		if latest == nil || (entry.Time != nil && latest.Before(entry.Time)) {
			manager, latest = entry.Manager, entry.Time
		}
	}
	return manager
}

// EscalationChangeEvent builds an escalation.created, escalation.updated or
// escalation.deleted event for an observed BreakglassEscalation change;
// previousGeneration (0 when unknown) is reported for updates. The
// ID is stable per escalation UID and generation (or deletion), so a
// re-emission after a controller restart is deduplicated by consumers.
func EscalationChangeEvent(eventType EventType, esc *breakglassv1alpha1.BreakglassEscalation, previousGeneration int64) *Event {
	spec, _ := json.Marshal(esc.Spec)
	digest := sha256.Sum256(spec)
	id := fmt.Sprintf("escalation/%s/%d", esc.UID, esc.Generation)
	if eventType == EventEscalationDeleted {
		id = fmt.Sprintf("escalation/%s/deleted", esc.UID)
	}
	details := map[string]interface{}{
		"generation":      esc.Generation,
		"escalatedGroup":  esc.Spec.EscalatedGroup,
		"specSHA256":      hex.EncodeToString(digest[:]),
		"resourceVersion": esc.ResourceVersion,
		"fieldManager":    lastFieldManager(esc),
	}
	if eventType == EventEscalationUpdated && previousGeneration > 0 {
		details["previousGeneration"] = previousGeneration
	}
	return &Event{
		ID:   id,
		Type: eventType,
		// The controller observes the change and cannot name the requester; the
		// Kubernetes API server audit log does (by object UID and generation).
		Actor:          Actor{User: "system"},
		Target:         Target{UID: string(esc.UID), Kind: "BreakglassEscalation", Name: esc.Name, Namespace: esc.Namespace, APIGroup: breakglassv1alpha1.GroupVersion.Group},
		RequestContext: &RequestContext{EscalationName: esc.Name, EscalationUID: string(esc.UID)},
		Details:        details,
	}
}

// DebugSessionAttachOperations are the pod subresources for which an
// authorized debug-session request emits debug_session.attached.
var DebugSessionAttachOperations = []string{"exec", "attach", "portforward"}

// DebugSessionAttachedEvent builds the debug_session.attached event for a
// SubjectAccessReview that a DebugSession authorized for exec, attach or
// port-forward into one of its pods. It returns nil for other requests.
func DebugSessionAttachedEvent(user string, groups []string, cluster string, ra *authorizationv1.ResourceAttributes,
	target Target, sessionNamespace, sessionName, sessionUID string) *Event {
	if ra == nil || ra.Resource != "pods" || !slices.Contains(DebugSessionAttachOperations, ra.Subresource) {
		return nil
	}
	// The caller's target may not be enriched (audit became ready only after
	// the decision started); the request always identifies the Pod.
	if target.Name == "" {
		target.Kind, target.Name, target.Namespace = ra.Resource, ra.Name, ra.Namespace
	}
	target.Cluster = cluster
	return &Event{
		Type:   EventDebugSessionAttached,
		Actor:  Actor{User: user, Groups: groups},
		Target: target,
		RequestContext: &RequestContext{
			DebugSessionName: sessionName, DebugSessionUID: sessionUID,
			SessionName: sessionName, SessionUID: sessionUID,
		},
		Details: map[string]interface{}{
			"operation":        ra.Subresource,
			"verb":             ra.Verb,
			"podName":          ra.Name,
			"podNamespace":     ra.Namespace,
			"cluster":          cluster,
			"sessionNamespace": sessionNamespace,
		},
	}
}
