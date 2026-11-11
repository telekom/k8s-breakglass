// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/utils"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// CleanupAcknowledgedAbsentAnnotation lets an authorized operator retire
// cleanup residuals that the controller cannot prove gone. Setting it requires
// the acknowledge-cleanup verb, enforced by the DebugSession webhook.
const CleanupAcknowledgedAbsentAnnotation = breakglassv1alpha1.DebugSessionCleanupAcknowledgedAbsentAnnotation

// CleanupAcknowledgedIdentity names one residual by its full recorded identity.
// UID is empty only for an unresolved create intent.
type CleanupAcknowledgedIdentity struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Namespace  string `json:"namespace,omitempty"`
	Name       string `json:"name"`
	UID        string `json:"uid,omitempty"`
}

func (i CleanupAcknowledgedIdentity) String() string {
	s := i.APIVersion + "/" + i.Kind + "/" + i.Namespace + "/" + i.Name
	if i.UID != "" {
		s += " (uid=" + i.UID + ")"
	}
	return s
}

const acknowledgedAbsentReason = "retired by operator acknowledgement (" + CleanupAcknowledgedAbsentAnnotation + ")"

// pendingCleanupAcknowledgement returns the digest of an acknowledgement that
// has not been processed yet, or "" when there is none.
func pendingCleanupAcknowledgement(ds *breakglassv1alpha1.DebugSession) string {
	raw := ds.Annotations[CleanupAcknowledgedAbsentAnnotation]
	if raw == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(raw + "\x00" + ds.Annotations[breakglassv1alpha1.DebugSessionCleanupAcknowledgedByAnnotation]))
	digest := hex.EncodeToString(sum[:8])
	if processed := ds.Status.CleanupAcknowledgement; processed != nil && processed.Digest == digest {
		return ""
	}
	return digest
}

// applyCleanupAcknowledgement processes a pending acknowledgement once. It
// retires residuals only if every listed identity matches an outstanding
// residual exactly; otherwise nothing is retired and the rejection is
// recorded. The outcome is stored in ds.Status.CleanupAcknowledgement.
// It returns the record when an acknowledgement was processed.
func applyCleanupAcknowledgement(ds *breakglassv1alpha1.DebugSession) *breakglassv1alpha1.DebugSessionCleanupAcknowledgementStatus {
	digest := pendingCleanupAcknowledgement(ds)
	if digest == "" {
		return nil
	}
	record := &breakglassv1alpha1.DebugSessionCleanupAcknowledgementStatus{
		Digest:         digest,
		AcknowledgedBy: ds.Annotations[breakglassv1alpha1.DebugSessionCleanupAcknowledgedByAnnotation],
		Reason:         ds.Annotations[breakglassv1alpha1.DebugSessionCleanupAcknowledgedReasonAnnotation],
		ProcessedAt:    metav1.Now(),
	}
	ds.Status.CleanupAcknowledgement = record
	reject := func(format string, args ...any) *breakglassv1alpha1.DebugSessionCleanupAcknowledgementStatus {
		record.Message = fmt.Sprintf(format, args...)
		return record
	}
	if record.AcknowledgedBy == "" {
		return reject("acknowledgement has no %s; it was not set through the admission webhook", breakglassv1alpha1.DebugSessionCleanupAcknowledgedByAnnotation)
	}
	var acknowledged []CleanupAcknowledgedIdentity
	if err := json.Unmarshal([]byte(ds.Annotations[CleanupAcknowledgedAbsentAnnotation]), &acknowledged); err != nil {
		return reject("invalid acknowledgement: %v", err)
	}
	if len(acknowledged) == 0 {
		return reject("acknowledgement lists no identities")
	}
	for _, id := range acknowledged {
		if id.APIVersion == "" || id.Kind == "" || id.Name == "" {
			return reject("acknowledgement entry %q needs apiVersion, kind and name", id)
		}
	}
	if !cleanupConditionFailed(ds) {
		return reject("cleanup is not failing; acknowledgements apply only to CleanupFailed residuals")
	}

	matched := make([]bool, len(acknowledged))
	find := func(apiVersion, kind, namespace, name, uid string) bool {
		for i, id := range acknowledged {
			if id.APIVersion == apiVersion && id.Kind == kind && id.Namespace == namespace && id.Name == name && id.UID == uid {
				matched[i] = true
				return true
			}
		}
		return false
	}
	status := ds.Status.DeepCopy()
	deployed := status.DeployedResources[:0]
	for _, ref := range status.DeployedResources {
		if !utils.DebugSessionResourceIntentionallyRetained(ds, ref) && find(ref.APIVersion, ref.Kind, ref.Namespace, ref.Name, ref.UID) {
			continue
		}
		deployed = append(deployed, ref)
	}
	status.DeployedResources = deployed
	podTemplates := status.PodTemplateResourceStatuses[:0]
	for _, entry := range status.PodTemplateResourceStatuses {
		if !entry.Deleted && find(entry.APIVersion, entry.Kind, entry.Namespace, entry.ResourceName, entry.UID) {
			continue
		}
		podTemplates = append(podTemplates, entry)
	}
	status.PodTemplateResourceStatuses = podTemplates
	for i := range status.AuxiliaryResourceStatuses {
		entry := &status.AuxiliaryResourceStatuses[i]
		if !entry.Deleted && find(entry.APIVersion, entry.Kind, entry.Namespace, entry.ResourceName, entry.UID) {
			entry.Deleted = true
			entry.Error = acknowledgedAbsentReason
		}
		for j := range entry.AdditionalResources {
			child := &entry.AdditionalResources[j]
			if !child.Deleted && find(child.APIVersion, child.Kind, child.Namespace, child.ResourceName, child.UID) {
				child.Deleted = true
				child.Error = acknowledgedAbsentReason
			}
		}
	}
	var retired, unmatched []string
	for i, id := range acknowledged {
		if matched[i] {
			retired = append(retired, id.String())
		} else {
			unmatched = append(unmatched, id.String())
		}
	}
	if len(unmatched) > 0 {
		return reject("identities are not outstanding cleanup residuals: %s; nothing was retired", strings.Join(unmatched, ", "))
	}
	status.CleanupAcknowledgement = record
	ds.Status = *status
	slices.Sort(retired)
	record.Applied = true
	record.Retired = retired
	return record
}
