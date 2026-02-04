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
	_, _ = fmt.Fprintln(tw, "NAME\tCLUSTER\tREQUESTED_BY\tSTATE\tEXPIRES")
	for _, s := range sessions {
		expires := "-"
		if s.ExpiresAt != nil {
			expires = formatTime(s.ExpiresAt.Time)
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", s.Name, s.Cluster, s.RequestedBy, string(s.State), expires)
	}
	_ = tw.Flush()
}

// WriteDebugSessionTableWide outputs debug sessions in wide table format with all available fields.
func WriteDebugSessionTableWide(w io.Writer, sessions []client.DebugSessionSummary) {
	tw := tabwriter.NewWriter(w, 2, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "NAME\tTEMPLATE\tCLUSTER\tREQUESTED_BY\tSTATE\tSTARTS\tEXPIRES\tPARTICIPANTS\tALLOWED_PODS\tOPERATIONS")
	for _, s := range sessions {
		starts := "-"
		if s.StartsAt != nil {
			starts = formatTime(s.StartsAt.Time)
		}
		expires := "-"
		if s.ExpiresAt != nil {
			expires = formatTime(s.ExpiresAt.Time)
		}
		ops := formatAllowedPodOperations(s.AllowedPodOperations)
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%d\t%d\t%s\n", s.Name, s.TemplateRef, s.Cluster, s.RequestedBy, string(s.State), starts, expires, s.Participants, s.AllowedPods, ops)
	}
	_ = tw.Flush()
}

// formatAllowedPodOperations returns a short string representation of allowed pod operations.
// Returns a comma-separated list of enabled operations (e.g., "exec,logs,attach").
func formatAllowedPodOperations(ops *v1alpha1.AllowedPodOperations) string {
	if ops == nil {
		// Default behavior when not specified: exec, attach, portforward enabled
		return "exec,attach,portforward"
	}
	var enabled []string
	if ops.IsOperationAllowed("exec") {
		enabled = append(enabled, "exec")
	}
	if ops.IsOperationAllowed("attach") {
		enabled = append(enabled, "attach")
	}
	if ops.IsOperationAllowed("log") {
		enabled = append(enabled, "logs")
	}
	if ops.IsOperationAllowed("portforward") {
		enabled = append(enabled, "portforward")
	}
	if len(enabled) == 0 {
		return "none"
	}
	return strings.Join(enabled, ",")
}

func WriteDebugTemplateTable(w io.Writer, templates []client.DebugSessionTemplateSummary) {
	tw := tabwriter.NewWriter(w, 2, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "NAME\tDISPLAY_NAME\tMODE\tCLUSTERS\tTARGET_NAMESPACE\tREQUIRES_APPROVAL")
	for _, t := range templates {
		var clusterStatus string
		if t.HasAvailableClusters {
			if t.AvailableClusterCount > 0 {
				clusterStatus = fmt.Sprintf("%d", t.AvailableClusterCount)
			} else {
				clusterStatus = "✓"
			}
		} else {
			clusterStatus = "0"
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%v\n", t.Name, t.DisplayName, t.Mode, clusterStatus, t.TargetNamespace, t.RequiresApproval)
	}
	_ = tw.Flush()
}

func WriteDebugPodTemplateTable(w io.Writer, templates []client.DebugPodTemplateSummary) {
	tw := tabwriter.NewWriter(w, 2, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "NAME\tDISPLAY_NAME\tDESCRIPTION\tCONTAINERS")
	for _, t := range templates {
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%d\n", t.Name, t.DisplayName, t.Description, t.Containers)
	}
	_ = tw.Flush()
}

// WriteTemplateClusterTable writes a compact table of available clusters for a template
func WriteTemplateClusterTable(w io.Writer, clusters []client.AvailableClusterDetail) {
	tw := tabwriter.NewWriter(w, 2, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "NAME\tDISPLAY_NAME\tENVIRONMENT\tBINDINGS\tMAX_DURATION\tAPPROVAL")
	for _, c := range clusters {
		bindingsStr := "-"
		if len(c.BindingOptions) > 0 {
			bindingsStr = fmt.Sprintf("%d", len(c.BindingOptions))
		} else if c.BindingRef != nil {
			bindingsStr = "1"
		}
		maxDuration := "-"
		if c.Constraints != nil && c.Constraints.MaxDuration != "" {
			maxDuration = c.Constraints.MaxDuration
		}
		approval := "no"
		if c.Approval != nil && c.Approval.Required {
			approval = "yes"
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
			c.Name, c.DisplayName, c.Environment, bindingsStr, maxDuration, approval)
	}
	_ = tw.Flush()
}

// WriteTemplateClusterTableWide writes an expanded table of available clusters for a template
func WriteTemplateClusterTableWide(w io.Writer, clusters []client.AvailableClusterDetail) {
	tw := tabwriter.NewWriter(w, 2, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "NAME\tDISPLAY_NAME\tENVIRONMENT\tBINDINGS\tMAX_DURATION\tNS_DEFAULT\tSCHEDULING\tIMPERSONATION\tAPPROVAL\tSTATUS")
	for _, c := range clusters {
		bindingsStr := "-"
		if len(c.BindingOptions) > 0 {
			names := make([]string, 0, len(c.BindingOptions))
			for _, opt := range c.BindingOptions {
				names = append(names, opt.BindingRef.Name)
			}
			if len(names) <= 2 {
				bindingsStr = strings.Join(names, ", ")
			} else {
				bindingsStr = fmt.Sprintf("%s, +%d more", names[0], len(names)-1)
			}
		} else if c.BindingRef != nil {
			bindingsStr = c.BindingRef.Name
		}
		maxDuration := "-"
		if c.Constraints != nil && c.Constraints.MaxDuration != "" {
			maxDuration = c.Constraints.MaxDuration
		}
		nsDefault := "-"
		if c.NamespaceConstraints != nil && c.NamespaceConstraints.DefaultNamespace != "" {
			nsDefault = c.NamespaceConstraints.DefaultNamespace
		}
		scheduling := "-"
		if c.SchedulingOptions != nil && len(c.SchedulingOptions.Options) > 0 {
			scheduling = fmt.Sprintf("%d options", len(c.SchedulingOptions.Options))
			if c.SchedulingOptions.Required {
				scheduling += " (required)"
			}
		}
		impersonation := "-"
		if c.Impersonation != nil && c.Impersonation.Enabled {
			impersonation = c.Impersonation.ServiceAccount
		}
		approval := "no"
		if c.Approval != nil && c.Approval.Required {
			approval = "yes"
		}
		status := "-"
		if c.Status != nil {
			if c.Status.Healthy {
				status = "healthy"
			} else {
				status = "unhealthy"
			}
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			c.Name, c.DisplayName, c.Environment, bindingsStr, maxDuration, nsDefault, scheduling, impersonation, approval, status)
	}
	_ = tw.Flush()
}

// WriteBindingOptionsTable writes a detailed table of binding options for a cluster
func WriteBindingOptionsTable(w io.Writer, clusterName string, options []client.BindingOption) {
	if len(options) == 0 {
		_, _ = fmt.Fprintf(w, "No binding options available for cluster '%s'. Using template defaults.\n", clusterName)
		return
	}
	_, _ = fmt.Fprintf(w, "Binding options for cluster '%s':\n\n", clusterName)
	tw := tabwriter.NewWriter(w, 2, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "BINDING\tDISPLAY_NAME\tMAX_DURATION\tNAMESPACE\tSCHEDULING\tIMPERSONATION\tAPPROVAL")
	for _, opt := range options {
		maxDuration := "-"
		if opt.Constraints != nil && opt.Constraints.MaxDuration != "" {
			maxDuration = opt.Constraints.MaxDuration
		}
		nsDefault := "-"
		if opt.NamespaceConstraints != nil && opt.NamespaceConstraints.DefaultNamespace != "" {
			nsDefault = opt.NamespaceConstraints.DefaultNamespace
		}
		scheduling := "-"
		if opt.SchedulingOptions != nil && len(opt.SchedulingOptions.Options) > 0 {
			scheduling = fmt.Sprintf("%d options", len(opt.SchedulingOptions.Options))
		}
		impersonation := "-"
		if opt.Impersonation != nil && opt.Impersonation.Enabled {
			impersonation = "yes"
			if opt.Impersonation.ServiceAccount != "" {
				impersonation = opt.Impersonation.ServiceAccount
			}
		}
		approval := "no"
		if opt.Approval != nil && opt.Approval.Required {
			approval = "yes"
		} else if opt.Approval != nil && opt.Approval.CanAutoApprove {
			approval = "auto"
		}
		_, _ = fmt.Fprintf(tw, "%s/%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			opt.BindingRef.Namespace, opt.BindingRef.Name, opt.DisplayName, maxDuration, nsDefault, scheduling, impersonation, approval)
	}
	_ = tw.Flush()
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.Format(time.RFC3339)
}
