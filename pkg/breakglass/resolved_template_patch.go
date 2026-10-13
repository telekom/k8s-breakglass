// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package breakglass

import (
	"encoding/json"
	"fmt"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// resolvedTemplateFalsePatch keeps explicit false values of CRD default-true
// booleans in status.resolvedTemplate. Those fields are plain bools with
// omitempty, so a JSON merge patch built from the typed status drops false
// and the API server re-defaults the snapshot to true (for example
// requireNonRoot). The spec tags stay unchanged so typed clients that omit
// the fields still receive the documented default.
type resolvedTemplateFalsePatch struct {
	client.Patch
	resolved *breakglassv1alpha1.DebugSessionTemplateSpec
}

func withResolvedTemplateFalseValues(patch client.Patch, resolved *breakglassv1alpha1.DebugSessionTemplateSpec) client.Patch {
	if resolved == nil {
		return patch
	}
	return resolvedTemplateFalsePatch{Patch: patch, resolved: resolved}
}

func (p resolvedTemplateFalsePatch) Data(obj client.Object) ([]byte, error) {
	data, err := p.Patch.Data(obj)
	if err != nil {
		return nil, err
	}
	falses := resolvedTemplateExplicitFalses(p.resolved)
	if len(falses) == 0 {
		return data, nil
	}
	patch := map[string]any{}
	if err := json.Unmarshal(data, &patch); err != nil {
		return nil, fmt.Errorf("decode status merge patch: %w", err)
	}
	mergeInto(patch, map[string]any{"status": map[string]any{"resolvedTemplate": falses}})
	return json.Marshal(patch)
}

// resolvedTemplateExplicitFalses returns the default-true booleans that are
// false in spec, nested by their JSON path below resolvedTemplate.
func resolvedTemplateExplicitFalses(spec *breakglassv1alpha1.DebugSessionTemplateSpec) map[string]any {
	out := map[string]any{}
	set := func(path []string, value bool) {
		if value {
			return
		}
		node := out
		for _, key := range path[:len(path)-1] {
			child, ok := node[key].(map[string]any)
			if !ok {
				child = map[string]any{}
				node[key] = child
			}
			node = child
		}
		node[path[len(path)-1]] = false
	}
	if n := spec.Notification; n != nil {
		set([]string{"notification", "enabled"}, n.Enabled)
		set([]string{"notification", "notifyOnRequest"}, n.NotifyOnRequest)
		set([]string{"notification", "notifyOnApproval"}, n.NotifyOnApproval)
		set([]string{"notification", "notifyOnExpiry"}, n.NotifyOnExpiry)
		set([]string{"notification", "notifyOnTermination"}, n.NotifyOnTermination)
	}
	if r := spec.ApprovalReason; r != nil {
		set([]string{"approvalReason", "mandatoryForRejection"}, r.MandatoryForRejection)
	}
	if q := spec.ResourceQuota; q != nil {
		set([]string{"resourceQuota", "enforceResourceRequests"}, q.EnforceResourceRequests)
		set([]string{"resourceQuota", "enforceResourceLimits"}, q.EnforceResourceLimits)
	}
	if k := spec.KubectlDebug; k != nil {
		if e := k.EphemeralContainers; e != nil {
			set([]string{"kubectlDebug", "ephemeralContainers", "requireNonRoot"}, e.RequireNonRoot)
		}
		if n := k.NodeDebug; n != nil && n.HostNamespaces != nil {
			set([]string{"kubectlDebug", "nodeDebug", "hostNamespaces", "hostNetwork"}, n.HostNamespaces.HostNetwork)
			set([]string{"kubectlDebug", "nodeDebug", "hostNamespaces", "hostPID"}, n.HostNamespaces.HostPID)
		}
	}
	if a := spec.Audit; a != nil {
		set([]string{"audit", "enabled"}, a.Enabled)
		set([]string{"audit", "enableShellHistory"}, a.EnableShellHistory)
	}
	return out
}

func mergeInto(dst, src map[string]any) {
	for key, value := range src {
		srcChild, srcIsMap := value.(map[string]any)
		dstChild, dstIsMap := dst[key].(map[string]any)
		if srcIsMap && dstIsMap {
			mergeInto(dstChild, srcChild)
			continue
		}
		dst[key] = value
	}
}
