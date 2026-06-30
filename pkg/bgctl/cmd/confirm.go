package cmd

import (
	"bufio"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

func confirmAction(cmd *cobra.Command, rt *runtimeState, action, resourceName string, yes bool) error {
	if yes {
		return nil
	}
	if rt.nonInteractive {
		return fmt.Errorf("confirmation required: run with --yes or omit --non-interactive or unset BGCTL_NON_INTERACTIVE")
	}

	if _, err := fmt.Fprintf(rt.writer, "Are you sure you want to %s %s? [y/N]: ", action, resourceName); err != nil {
		return fmt.Errorf("failed to write prompt: %w", err)
	}
	reader := bufio.NewReader(cmd.InOrStdin())
	response, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	response = strings.TrimSpace(strings.ToLower(response))
	if response != "y" && response != "yes" {
		return fmt.Errorf("canceled")
	}
	return nil
}
