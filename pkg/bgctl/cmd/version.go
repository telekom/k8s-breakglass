package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/telekom/k8s-breakglass/pkg/version"
	"gopkg.in/yaml.v3"
)

func NewVersionCommand() *cobra.Command {
	var outputFormat string

	cmd := &cobra.Command{
		Use:   "version",
		Short: "Show bgctl version",
		RunE: func(cmd *cobra.Command, _ []string) error {
			info := version.GetBuildInfo()

			// Get runtime if available (for custom writer), but don't fail if missing
			rt, _ := getRuntime(cmd)
			writer := cmd.OutOrStdout()
			if rt != nil {
				writer = rt.Writer()
			}

			switch outputFormat {
			case "json":
				encoder := json.NewEncoder(writer)
				encoder.SetIndent("", "  ")
				return encoder.Encode(info)
			case "yaml":
				data, err := yaml.Marshal(info)
				if err != nil {
					return fmt.Errorf("failed to marshal to YAML: %w", err)
				}
				_, _ = fmt.Fprint(writer, string(data))
				return nil
			default:
				_, _ = fmt.Fprintf(writer, "bgctl %s (commit: %s, built: %s)\n", info.Version, info.GitCommit, info.BuildDate)
				return nil
			}
		},
	}

	cmd.Flags().StringVarP(&outputFormat, "output", "o", "", "Output format: json, yaml")

	return cmd
}
