// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package output

import (
	"encoding/json"
	"fmt"
	"io"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/bgctl/client"
	"gopkg.in/yaml.v3"
)

type Format string

const (
	FormatTable Format = "table"
	FormatJSON  Format = "json"
	FormatYAML  Format = "yaml"
	FormatWide  Format = "wide"
)

func WriteObject(w io.Writer, format Format, obj any) error {
	switch format {
	case FormatJSON:
		data, err := json.MarshalIndent(obj, "", "  ")
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(w, string(data))
		return err
	case FormatYAML:
		data, err := yaml.Marshal(obj)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(w, string(data))
		return err
	case FormatTable, FormatWide:
		switch v := obj.(type) {
		case *breakglassv1alpha1.BreakglassEscalation:
			WriteEscalationTable(w, []breakglassv1alpha1.BreakglassEscalation{*v})
			return nil
		case *breakglassv1alpha1.BreakglassSession:
			if format == FormatWide {
				WriteSessionTableWide(w, []breakglassv1alpha1.BreakglassSession{*v})
			} else {
				WriteSessionTable(w, []breakglassv1alpha1.BreakglassSession{*v})
			}
			return nil
		case *breakglassv1alpha1.DebugSession:
			summary := client.DebugSessionSummary{
				Name:                 v.Name,
				TemplateRef:          v.Spec.TemplateRef,
				Cluster:              v.Spec.Cluster,
				RequestedBy:          v.Spec.RequestedBy,
				TargetNamespace:      v.Spec.TargetNamespace,
				State:                v.Status.State,
				StartsAt:             v.Status.StartsAt,
				ExpiresAt:            v.Status.ExpiresAt,
				Participants:         len(v.Status.Participants),
				AllowedPods:          len(v.Status.AllowedPods),
				AllowedPodOperations: v.Status.AllowedPodOperations,
			}
			if format == FormatWide {
				WriteDebugSessionTableWide(w, []client.DebugSessionSummary{summary})
			} else {
				WriteDebugSessionTable(w, []client.DebugSessionSummary{summary})
			}
			return nil
		case *breakglassv1alpha1.DebugSessionTemplate:
			summary := client.DebugSessionTemplateSummary{
				Name:                 v.Name,
				DisplayName:          v.Spec.DisplayName,
				Mode:                 v.Spec.Mode,
				TargetNamespace:      v.Spec.TargetNamespace,
				RequiresApproval:     v.Spec.Approvers != nil,
				HasAvailableClusters: false, // Not fully resolvable from single object without API
			}
			WriteDebugTemplateTable(w, []client.DebugSessionTemplateSummary{summary})
			return nil
		case *breakglassv1alpha1.DebugPodTemplate:
			summary := client.DebugPodTemplateSummary{
				Name:        v.Name,
				DisplayName: v.Spec.DisplayName,
				Description: v.Spec.Description,
				Containers: func() int {
					if v.Spec.Template != nil {
						return len(v.Spec.Template.Spec.Containers)
					}
					return 0
				}(),
			}
			WriteDebugPodTemplateTable(w, []client.DebugPodTemplateSummary{summary})
			return nil
		case map[string]interface{}:
			_, _ = fmt.Fprintln(w, "Operation completed successfully.")
			return nil
		}
		if format == FormatTable {
			return fmt.Errorf("table format requires a specific formatter for type %T", obj)
		}
		return fmt.Errorf("wide format requires a specific formatter for type %T", obj)

	default:
		return fmt.Errorf("unknown output format: %q", format)
	}
}
