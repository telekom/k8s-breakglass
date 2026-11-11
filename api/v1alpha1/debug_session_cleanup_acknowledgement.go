// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"context"
	"fmt"

	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

const (
	// DebugSessionCleanupAcknowledgedAbsentAnnotation lists, as a JSON array of
	// exact identities, cleanup residuals that an authorized operator verified
	// are gone (for example objects of an uninstalled CRD).
	DebugSessionCleanupAcknowledgedAbsentAnnotation = "breakglass.t-caas.telekom.com/cleanup-acknowledged-absent"
	// DebugSessionCleanupAcknowledgedByAnnotation names the user who set the
	// acknowledgement. The webhook requires it to equal the requesting user.
	DebugSessionCleanupAcknowledgedByAnnotation = "breakglass.t-caas.telekom.com/cleanup-acknowledged-by"
	// DebugSessionCleanupAcknowledgedReasonAnnotation optionally carries a
	// reason or ticket reference for the audit trail.
	DebugSessionCleanupAcknowledgedReasonAnnotation = "breakglass.t-caas.telekom.com/cleanup-acknowledged-reason"
	// DebugSessionCleanupAcknowledgeVerb is the dedicated RBAC verb on
	// debugsessions that authorizes setting an acknowledgement.
	DebugSessionCleanupAcknowledgeVerb = "acknowledge-cleanup"
)

// DebugSessionCleanupAcknowledgementAnnotations are only writable through an
// authorized update; creates and binding templates must not carry them.
var DebugSessionCleanupAcknowledgementAnnotations = []string{
	DebugSessionCleanupAcknowledgedAbsentAnnotation,
	DebugSessionCleanupAcknowledgedByAnnotation,
	DebugSessionCleanupAcknowledgedReasonAnnotation,
}

func forbidCleanupAcknowledgementAnnotations(annotations map[string]string, path *field.Path) field.ErrorList {
	var errs field.ErrorList
	for _, key := range DebugSessionCleanupAcknowledgementAnnotations {
		if _, ok := annotations[key]; ok {
			errs = append(errs, field.Forbidden(path.Key(key), "cleanup acknowledgements can only be added to an existing DebugSession by an authorized update"))
		}
	}
	return errs
}

// subjectAccessReviewer creates SubjectAccessReviews; tests replace it.
var subjectAccessReviewer = func(ctx context.Context, sar *authorizationv1.SubjectAccessReview) error {
	c := GetWebhookClient()
	if c == nil {
		return fmt.Errorf("webhook client is not initialized")
	}
	return c.Create(ctx, sar)
}

// validateCleanupAcknowledgementUpdate authorizes adding or changing an
// acknowledgement: the requesting user must hold the dedicated verb on this
// session and record themselves as the acknowledging user. Removing it is
// always allowed. The session requester and participants get no exemption.
func validateCleanupAcknowledgementUpdate(ctx context.Context, oldObj, newObj *DebugSession) field.ErrorList {
	path := field.NewPath("metadata").Child("annotations")
	changed := false
	for _, key := range DebugSessionCleanupAcknowledgementAnnotations {
		if newValue, ok := newObj.Annotations[key]; ok && newValue != oldObj.Annotations[key] {
			changed = true
		}
	}
	if !changed {
		return nil
	}
	ackPath := path.Key(DebugSessionCleanupAcknowledgedAbsentAnnotation)
	if newObj.Annotations[DebugSessionCleanupAcknowledgedAbsentAnnotation] == "" {
		return field.ErrorList{field.Required(ackPath, "acknowledgement metadata requires the acknowledgement list")}
	}
	req, err := admission.RequestFromContext(ctx)
	if err != nil || req.UserInfo.Username == "" {
		return field.ErrorList{field.Forbidden(ackPath, "cleanup acknowledgement requires an authenticated admission request")}
	}
	user := req.UserInfo
	if newObj.Annotations[DebugSessionCleanupAcknowledgedByAnnotation] != user.Username {
		return field.ErrorList{field.Invalid(path.Key(DebugSessionCleanupAcknowledgedByAnnotation), newObj.Annotations[DebugSessionCleanupAcknowledgedByAnnotation],
			fmt.Sprintf("must equal the requesting user %q", user.Username))}
	}
	extra := make(map[string]authorizationv1.ExtraValue, len(user.Extra))
	for k, v := range user.Extra {
		extra[k] = authorizationv1.ExtraValue(v)
	}
	sar := &authorizationv1.SubjectAccessReview{Spec: authorizationv1.SubjectAccessReviewSpec{
		User: user.Username, Groups: user.Groups, UID: user.UID, Extra: extra,
		ResourceAttributes: &authorizationv1.ResourceAttributes{
			Group: GroupVersion.Group, Resource: "debugsessions", Verb: DebugSessionCleanupAcknowledgeVerb,
			Namespace: newObj.Namespace, Name: newObj.Name,
		},
	}}
	if err := subjectAccessReviewer(ctx, sar); err != nil {
		return field.ErrorList{field.InternalError(ackPath, fmt.Errorf("authorize cleanup acknowledgement: %w", err))}
	}
	if !sar.Status.Allowed {
		return field.ErrorList{field.Forbidden(ackPath, fmt.Sprintf("user %q may not %s debugsessions %s/%s", user.Username, DebugSessionCleanupAcknowledgeVerb, newObj.Namespace, newObj.Name))}
	}
	return nil
}

// DebugSessionCleanupAcknowledgementStatus records how the controller
// processed the current cleanup acknowledgement.
type DebugSessionCleanupAcknowledgementStatus struct {
	// digest identifies the processed acknowledgement (list and acknowledging
	// user). A changed acknowledgement is processed again.
	Digest string `json:"digest"`
	// acknowledgedBy is the user recorded by the admission webhook.
	AcknowledgedBy string `json:"acknowledgedBy"`
	// reason is the optional reason or ticket reference.
	// +optional
	Reason string `json:"reason,omitempty"`
	// applied is true when every listed identity matched an outstanding
	// residual and was retired.
	Applied bool `json:"applied"`
	// retired lists the identities retired by this acknowledgement.
	// +optional
	Retired []string `json:"retired,omitempty"`
	// message explains a rejected acknowledgement.
	// +optional
	Message string `json:"message,omitempty"`
	// processedAt is when the controller processed the acknowledgement.
	ProcessedAt metav1.Time `json:"processedAt"`
}
