// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
)

// CleanupAcknowledgedAbsentAnnotation lets an operator retire cleanup
// residuals that the controller cannot prove gone, for example objects of a
// CRD that was uninstalled (which deletes them) or an unresolved create
// intent. The value is a JSON array of exact residual identities. Only
// entries matching every field are retired; nothing is inferred.
const CleanupAcknowledgedAbsentAnnotation = "breakglass.t-caas.telekom.com/cleanup-acknowledged-absent"

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

// applyCleanupAcknowledgement retires the residuals named in the annotation.
// It applies only while cleanup is failing, and only if every acknowledged
// identity matches an outstanding residual; otherwise it changes nothing and
// returns an error. Identities that match nothing outstanding because an
// earlier attempt already retired them are ignored as a whole. It returns the
// identities retired by this call.
func applyCleanupAcknowledgement(ds *breakglassv1alpha1.DebugSession) ([]string, error) {
	raw := ds.Annotations[CleanupAcknowledgedAbsentAnnotation]
	if raw == "" || !cleanupConditionFailed(ds) {
		return nil, nil
	}
	var acknowledged []CleanupAcknowledgedIdentity
	if err := json.Unmarshal([]byte(raw), &acknowledged); err != nil {
		return nil, fmt.Errorf("invalid %s annotation: %w", CleanupAcknowledgedAbsentAnnotation, err)
	}
	for _, id := range acknowledged {
		if id.APIVersion == "" || id.Kind == "" || id.Name == "" {
			return nil, fmt.Errorf("invalid %s annotation: entry %q needs apiVersion, kind and name", CleanupAcknowledgedAbsentAnnotation, id)
		}
	}

	matches := func(id CleanupAcknowledgedIdentity, apiVersion, kind, namespace, name, uid string) bool {
		return id.APIVersion == apiVersion && id.Kind == kind && id.Namespace == namespace && id.Name == name && id.UID == uid
	}
	matched := make([]bool, len(acknowledged))
	find := func(apiVersion, kind, namespace, name, uid string) bool {
		for i, id := range acknowledged {
			if matches(id, apiVersion, kind, namespace, name, uid) {
				matched[i] = true
				return true
			}
		}
		return false
	}

	status := ds.Status.DeepCopy()
	deployed := status.DeployedResources[:0]
	for _, ref := range status.DeployedResources {
		if find(ref.APIVersion, ref.Kind, ref.Namespace, ref.Name, ref.UID) {
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
	if len(retired) == 0 {
		return nil, nil // Already applied by an earlier attempt.
	}
	if len(unmatched) > 0 {
		return nil, fmt.Errorf("%s annotation names identities that are not outstanding cleanup residuals: %s; nothing was retired",
			CleanupAcknowledgedAbsentAnnotation, strings.Join(unmatched, ", "))
	}
	ds.Status = *status
	slices.Sort(retired)
	return retired, nil
}
