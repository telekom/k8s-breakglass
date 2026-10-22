package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/telekom/k8s-breakglass/pkg/bgctl/output"
)

func NewEscalationCommand() *cobra.Command {
	cmd := newHelpOnlyGroupCommand("escalation", "Manage escalation policies")
	cmd.AddCommand(
		newEscalationListCommand(),
		newEscalationGetCommand(),
		newEscalationListClustersCommand(),
	)
	return cmd
}

func newEscalationListCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List escalations",
		Long: `List the escalation policies available to the current user.

Use the returned Kubernetes resource names when inspecting a policy or selecting
an explicit escalation for a session request.`,
		Example: `  bgctl escalation list
  bgctl escalation list -o json`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			rt, err := getRuntime(cmd)
			if err != nil {
				return err
			}
			apiClient, err := buildClient(context.Background(), rt)
			if err != nil {
				return err
			}
			escs, err := apiClient.Escalations().List(context.Background())
			if err != nil {
				return err
			}
			format := output.Format(rt.OutputFormat())
			switch format {
			case output.FormatJSON, output.FormatYAML:
				return output.WriteObject(rt.Writer(), format, escs)
			case output.FormatTable:
				output.WriteEscalationTable(rt.Writer(), escs)
				return nil
			default:
				return unsupportedOutputFormatError(format, output.FormatTable, output.FormatJSON, output.FormatYAML)
			}
		},
	}
}

func newEscalationGetCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "get NAME",
		Short: "Get an escalation by name",
		Long: `Inspect an escalation policy by its Kubernetes resource name.

Use escalation list to discover names before inspecting a specific policy.`,
		Example: `  bgctl escalation get production-admin
  bgctl escalation get production-admin -o yaml`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			rt, err := getRuntime(cmd)
			if err != nil {
				return err
			}
			apiClient, err := buildClient(context.Background(), rt)
			if err != nil {
				return err
			}
			esc, err := apiClient.Escalations().Get(context.Background(), args[0])
			if err != nil {
				return err
			}
			format := output.Format(rt.OutputFormat())
			switch format {
			case output.FormatJSON, output.FormatYAML:
				return output.WriteObject(rt.Writer(), format, esc)
			case output.FormatTable, output.FormatWide:
				return output.WriteObject(rt.Writer(), format, esc)
			default:
				return unsupportedOutputFormatError(format, output.FormatTable, output.FormatWide, output.FormatJSON, output.FormatYAML)
			}
		},
	}
}

func newEscalationListClustersCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "list-clusters",
		Short: "List available clusters from escalation policies",
		Long: `Show cluster names available through escalation policies.

This command does not request a session or grant access to a cluster.`,
		Example: `  bgctl escalation list-clusters
  bgctl escalation list-clusters -o json`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			rt, err := getRuntime(cmd)
			if err != nil {
				return err
			}
			apiClient, err := buildClient(context.Background(), rt)
			if err != nil {
				return err
			}
			clusters, err := apiClient.Escalations().ListClusters(context.Background())
			if err != nil {
				return err
			}
			format := output.Format(rt.OutputFormat())
			switch format {
			case output.FormatJSON, output.FormatYAML:
				return output.WriteObject(rt.Writer(), format, clusters)
			case output.FormatTable, output.FormatWide:
				for _, c := range clusters {
					_, _ = fmt.Fprintln(rt.Writer(), c)
				}
				return nil
			default:
				return unsupportedOutputFormatError(format, output.FormatTable, output.FormatWide, output.FormatJSON, output.FormatYAML)
			}
		},
	}
}
