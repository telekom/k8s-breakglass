package output

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/bgctl/client"
)

func WriteSessionTable(w io.Writer, sessions []v1alpha1.BreakglassSession) {
	tw := tabwriter.NewWriter(w, 2, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "NAME\tCLUSTER\tUSER\tSTATE\tCREATED\tEXPIRES")
	for _, s := range sessions {
		created := formatTime(s.CreationTimestamp.Time)
		expires := "-"
		if !s.Status.ExpiresAt.IsZero() {
			expires = formatTime(s.Status.ExpiresAt.Time)
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", s.Name, s.Spec.Cluster, s.Spec.User, string(s.Status.State), created, expires)
	}
	_ = tw.Flush()
}

func WriteSessionTableWide(w io.Writer, sessions []v1alpha1.BreakglassSession) {
	tw := tabwriter.NewWriter(w, 2, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "NAME\tCLUSTER\tUSER\tGROUP\tSTATE\tCREATED\tAPPROVER\tEXPIRES")
	for _, s := range sessions {
		created := formatTime(s.CreationTimestamp.Time)
		expires := "-"
		if !s.Status.ExpiresAt.IsZero() {
			expires = formatTime(s.Status.ExpiresAt.Time)
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", s.Name, s.Spec.Cluster, s.Spec.User, s.Spec.GrantedGroup, string(s.Status.State), created, s.Status.Approver, expires)
	}
	_ = tw.Flush()
}

func WriteEscalationTable(w io.Writer, escs []v1alpha1.BreakglassEscalation) {
	tw := tabwriter.NewWriter(w, 2, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "NAME\tCLUSTERS\tALLOWED_GROUPS\tESCALATED_GROUP\tAPPROVERS")
	for _, e := range escs {
		clusters := strings.Join(e.Spec.Allowed.Clusters, ",")
		allowedGroups := strings.Join(e.Spec.Allowed.Groups, ",")
		approvers := strings.Join(append(e.Spec.Approvers.Groups, e.Spec.Approvers.Users...), ",")
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", e.Name, clusters, allowedGroups, e.Spec.EscalatedGroup, approvers)
	}
	_ = tw.Flush()
}

func WriteDebugSessionTable(w io.Writer, sessions []client.DebugSessionSummary) {
	tw := tabwriter.NewWriter(w, 2, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "NAME\tTEMPLATE\tCLUSTER\tREQUESTED_BY\tSTATE\tSTARTS\tEXPIRES\tPARTICIPANTS\tALLOWED_PODS")
	for _, s := range sessions {
		starts := "-"
		if s.StartsAt != nil {
			starts = formatTime(s.StartsAt.Time)
		}
		expires := "-"
		if s.ExpiresAt != nil {
			expires = formatTime(s.ExpiresAt.Time)
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%d\t%d\n", s.Name, s.TemplateRef, s.Cluster, s.RequestedBy, string(s.State), starts, expires, s.Participants, s.AllowedPods)
	}
	_ = tw.Flush()
}

func WriteDebugTemplateTable(w io.Writer, templates []v1alpha1.DebugSessionTemplate) {
	tw := tabwriter.NewWriter(w, 2, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "NAME\tDISPLAY_NAME\tMODE\tTARGET_NAMESPACE\tAGE")
	for _, t := range templates {
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", t.Name, t.Spec.DisplayName, t.Spec.Mode, t.Spec.TargetNamespace, formatTime(t.CreationTimestamp.Time))
	}
	_ = tw.Flush()
}

func WriteDebugPodTemplateTable(w io.Writer, templates []v1alpha1.DebugPodTemplate) {
	tw := tabwriter.NewWriter(w, 2, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "NAME\tDISPLAY_NAME\tAGE")
	for _, t := range templates {
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\n", t.Name, t.Spec.DisplayName, formatTime(t.CreationTimestamp.Time))
	}
	_ = tw.Flush()
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.Format(time.RFC3339)
}
