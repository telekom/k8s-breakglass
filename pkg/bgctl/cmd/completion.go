package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

func NewCompletionCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "completion [bash|zsh|fish|powershell]",
		Short: "Generate shell completion",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			rt, err := getRuntime(cmd)
			if err != nil {
				return err
			}
			w := rt.Writer()
			shell := args[0]
			switch shell {
			case "bash":
				return cmd.Root().GenBashCompletion(w)
			case "zsh":
				return cmd.Root().GenZshCompletion(w)
			case "fish":
				return cmd.Root().GenFishCompletion(w, true)
			case "powershell":
				return cmd.Root().GenPowerShellCompletionWithDesc(w)
			default:
				return fmt.Errorf("unsupported shell: %s", shell)
			}
		},
	}
	return cmd
}
