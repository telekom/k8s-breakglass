package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/telekom/k8s-breakglass/pkg/bgctl/output"
)

func NewEscalationCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "escalation",
		Short: "Manage escalation policies",
	}
	cmd.AddCommand(
		newEscalationListCommand(),
		newEscalationGetCommand(),
	)
	return cmd
}

func newEscalationListCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List escalations",
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
				return fmt.Errorf("unknown output format: %s", format)
			}
		},
	}
}

func newEscalationGetCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "get NAME",
		Short: "Get an escalation by name",
		Args:  cobra.ExactArgs(1),
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
			return output.WriteObject(rt.Writer(), output.Format(rt.OutputFormat()), esc)
		},
	}
}
