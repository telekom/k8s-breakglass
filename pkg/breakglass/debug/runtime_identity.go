// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
)

// Runtime identity metadata lets runtime security tools (Tetragon, Falco)
// attribute every pod and ephemeral container a DebugSession creates to that
// session. The labels are selectable; the annotations carry free-form values.
const (
	// RuntimeIdentityRequestedByAnnotation is the session requester.
	RuntimeIdentityRequestedByAnnotation = "breakglass.telekom.com/requested-by"
	// RuntimeIdentityApprovedByAnnotation is the session approver, if any.
	RuntimeIdentityApprovedByAnnotation = "breakglass.telekom.com/approved-by"
	// RuntimeIdentityTicketAnnotation is the session's spec.ticketSystemID.
	RuntimeIdentityTicketAnnotation = "breakglass.telekom.com/ticket"
	// EphemeralContainerAnnotationPrefix prefixes the target-pod annotation
	// that maps an injected ephemeral container name to its session UID.
	EphemeralContainerAnnotationPrefix = "breakglass.telekom.com/ephemeral."
)

// runtimeIdentityEnabled reports whether runtime identity metadata applies.
// The global switch and the template's spec.audit.runtimeIdentityMetadata are
// both transitional escape hatches; either one turns the metadata off.
func runtimeIdentityEnabled(globalDisabled bool, template *breakglassv1alpha1.DebugSessionTemplateSpec) bool {
	if globalDisabled {
		return false
	}
	return template == nil || template.Audit == nil || template.Audit.RuntimeIdentityMetadata == nil || *template.Audit.RuntimeIdentityMetadata
}

// ApplyRuntimeIdentityMetadata is the one helper every pod builder of a
// DebugSession calls (workload, pod copy, node debug, artifact collector). It
// sets the controller-owned runtime identity labels and annotations on meta,
// overriding values from templates or users; empty approver or ticket values
// remove the key so no other source can fill it in. It does nothing when the
// global switch or the template turns the metadata off; existing labels stay.
func ApplyRuntimeIdentityMetadata(meta *metav1.ObjectMeta, ds *breakglassv1alpha1.DebugSession, template *breakglassv1alpha1.DebugSessionTemplateSpec, globallyDisabled bool) {
	if !runtimeIdentityEnabled(globallyDisabled, template) {
		return
	}
	if meta.Labels == nil {
		meta.Labels = map[string]string{}
	}
	if meta.Annotations == nil {
		meta.Annotations = map[string]string{}
	}
	meta.Labels[DebugSessionLabelKey] = runtimeIdentityLabelValue(ds.Name)
	meta.Labels[DebugSessionUIDLabelKey] = runtimeIdentityLabelValue(debugSessionIdentity(ds))
	meta.Labels[DebugTemplateLabelKey] = runtimeIdentityLabelValue(ds.Spec.TemplateRef)

	approvedBy := ""
	if ds.Status.Approval != nil {
		approvedBy = ds.Status.Approval.ApprovedBy
	}
	for key, value := range map[string]string{
		RuntimeIdentityRequestedByAnnotation: ds.Spec.RequestedBy,
		RuntimeIdentityApprovedByAnnotation:  approvedBy,
		RuntimeIdentityTicketAnnotation:      ds.Spec.TicketSystemID,
	} {
		if value == "" {
			delete(meta.Annotations, key)
		} else {
			meta.Annotations[key] = value
		}
	}
}

// runtimeIdentityLabelValue returns value unchanged when it is a valid label
// value. Otherwise it keeps a readable prefix and appends a hash, so distinct
// inputs keep distinct labels.
func runtimeIdentityLabelValue(value string) string {
	if len(validation.IsValidLabelValue(value)) == 0 {
		return value
	}
	sum := sha256.Sum256([]byte(value))
	hash := hex.EncodeToString(sum[:])[:10]
	prefix := strings.Map(func(r rune) rune {
		if r < 128 && (r == '-' || r == '_' || r == '.' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z') {
			return r
		}
		return '-'
	}, value)
	if len(prefix) > validation.LabelValueMaxLength-len(hash)-1 {
		prefix = prefix[:validation.LabelValueMaxLength-len(hash)-1]
	}
	prefix = strings.Trim(prefix, "-_.")
	if prefix == "" {
		return hash
	}
	return prefix + "-" + hash
}

// ephemeralContainerNamePrefix is "bg-<first 8 characters of the session UID>-".
func ephemeralContainerNamePrefix(ds *breakglassv1alpha1.DebugSession) string {
	id := strings.ToLower(strings.ReplaceAll(debugSessionIdentity(ds), "-", ""))
	if len(id) < 8 || len(validation.IsDNS1123Label(id[:8])) > 0 {
		sum := sha256.Sum256([]byte(id))
		id = hex.EncodeToString(sum[:])
	}
	return "bg-" + id[:8] + "-"
}

// assignEphemeralContainerName returns the deterministic container name
// bg-<uid8>-<n> for a request. A retry of a request recorded for the same pod
// reuses its name, so retries stay idempotent; otherwise n is one more than
// the highest n of this session in the pod or in the session's operations.
// An operation recorded before runtime identity metadata (no requestedName)
// with the requested name keeps that name, so its replay protection holds.
func assignEphemeralContainerName(ds *breakglassv1alpha1.DebugSession, podUID string, podContainers []string, requested string) string {
	prefix := ephemeralContainerNamePrefix(ds)
	next := 1
	bump := func(name string) {
		if n, err := strconv.Atoi(strings.TrimPrefix(name, prefix)); err == nil && strings.HasPrefix(name, prefix) && n >= next {
			next = n + 1
		}
	}
	for _, name := range podContainers {
		bump(name)
	}
	if status := ds.Status.KubectlDebugStatus; status != nil {
		reused := ""
		for _, operation := range status.Operations {
			if operation.Kind != kubectlDebugOperationKindEphemeralContainer || string(operation.TargetPod.UID) != podUID {
				continue
			}
			intent := operation.EphemeralContainer
			bump(intent.Name)
			if intent.RequestedName == requested && strings.HasPrefix(intent.Name, prefix) ||
				intent.RequestedName == "" && intent.Name == requested {
				reused = intent.Name
			}
		}
		if reused != "" {
			return reused
		}
		for _, ref := range status.EphemeralContainersInjected {
			if ref.PodUID == podUID {
				bump(ref.ContainerName)
			}
		}
	}
	return fmt.Sprintf("%s%d", prefix, next)
}

// ephemeralContainerAnnotationKey is the target-pod annotation key for an
// ephemeral container. The name part of a qualified name is limited to 63
// characters, which assigned names (at most 22 characters) always meet.
func ephemeralContainerAnnotationKey(containerName string) (string, error) {
	key := EphemeralContainerAnnotationPrefix + containerName
	if errs := validation.IsQualifiedName(key); len(errs) > 0 {
		return "", fmt.Errorf("invalid ephemeral container annotation key %q: %s", key, strings.Join(errs, "; "))
	}
	return key, nil
}
