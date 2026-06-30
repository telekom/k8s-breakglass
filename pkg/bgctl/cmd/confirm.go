package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func confirmAction(rt *runtimeState, action, resourceName string, yes bool) error {
	if yes {
		return nil
	}
	if rt.nonInteractive {
		return fmt.Errorf("confirmation required: run with --yes or omit --non-interactive")
	}

	fmt.Fprintf(rt.writer, "Are you sure you want to %s %s? [y/N]: ", action, resourceName)
	reader := bufio.NewReader(os.Stdin)
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
