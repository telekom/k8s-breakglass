// Package webhook implements the SubjectAccessReview (SAR) webhook controller
// and validating webhook server for breakglass CRDs, handling authorization
// decisions. Ephemeral-container injection is mediated by the authenticated
// DebugSession API rather than a target-cluster admission webhook.
package webhook
