package v1alpha1

import (
	"fmt"

	"k8s.io/apimachinery/pkg/util/validation/field"
)

func validateDebugSessionMonotonicStatusFields(oldObj, newObj *DebugSession) field.ErrorList {
	var errs field.ErrorList
	statusPath := field.NewPath("status")

	if oldObj.Status.StartsAt != nil && !oldObj.Status.StartsAt.IsZero() {
		if newObj.Status.StartsAt == nil || newObj.Status.StartsAt.IsZero() {
			errs = append(errs, field.Invalid(statusPath.Child("startsAt"), nil, "startsAt must not be cleared once set"))
		} else if newObj.Status.StartsAt.Time.Before(oldObj.Status.StartsAt.Time) {
			errs = append(errs, field.Invalid(statusPath.Child("startsAt"), newObj.Status.StartsAt.Time, fmt.Sprintf("startsAt must not move backwards (was %s)", oldObj.Status.StartsAt.Time.Format("2006-01-02T15:04:05Z"))))
		}
	}

	if oldObj.Status.ExpiresAt != nil && !oldObj.Status.ExpiresAt.IsZero() {
		if newObj.Status.ExpiresAt == nil || newObj.Status.ExpiresAt.IsZero() {
			errs = append(errs, field.Invalid(statusPath.Child("expiresAt"), nil, "expiresAt must not be cleared once set"))
		} else if newObj.Status.ExpiresAt.Time.Before(oldObj.Status.ExpiresAt.Time) {
			errs = append(errs, field.Invalid(statusPath.Child("expiresAt"), newObj.Status.ExpiresAt.Time, fmt.Sprintf("expiresAt must not move backwards (was %s)", oldObj.Status.ExpiresAt.Time.Format("2006-01-02T15:04:05Z"))))
		}
	}

	if oldObj.Status.Approval != nil {
		if oldObj.Status.Approval.ApprovedAt != nil && !oldObj.Status.Approval.ApprovedAt.IsZero() {
			if newObj.Status.Approval == nil || newObj.Status.Approval.ApprovedAt == nil || newObj.Status.Approval.ApprovedAt.IsZero() {
				errs = append(errs, field.Invalid(statusPath.Child("approval").Child("approvedAt"), nil, "approvedAt must not be cleared once set"))
			} else if newObj.Status.Approval.ApprovedAt.Time.Before(oldObj.Status.Approval.ApprovedAt.Time) {
				errs = append(errs, field.Invalid(statusPath.Child("approval").Child("approvedAt"), newObj.Status.Approval.ApprovedAt.Time, fmt.Sprintf("approvedAt must not move backwards (was %s)", oldObj.Status.Approval.ApprovedAt.Time.Format("2006-01-02T15:04:05Z"))))
			}
		}

		if oldObj.Status.Approval.RejectedAt != nil && !oldObj.Status.Approval.RejectedAt.IsZero() {
			if newObj.Status.Approval == nil || newObj.Status.Approval.RejectedAt == nil || newObj.Status.Approval.RejectedAt.IsZero() {
				errs = append(errs, field.Invalid(statusPath.Child("approval").Child("rejectedAt"), nil, "rejectedAt must not be cleared once set"))
			} else if newObj.Status.Approval.RejectedAt.Time.Before(oldObj.Status.Approval.RejectedAt.Time) {
				errs = append(errs, field.Invalid(statusPath.Child("approval").Child("rejectedAt"), newObj.Status.Approval.RejectedAt.Time, fmt.Sprintf("rejectedAt must not move backwards (was %s)", oldObj.Status.Approval.RejectedAt.Time.Format("2006-01-02T15:04:05Z"))))
			}
		}
	}

	return errs
}
