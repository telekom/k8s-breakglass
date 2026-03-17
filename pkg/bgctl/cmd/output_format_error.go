package cmd

import (
	"fmt"
	"strings"

	"github.com/telekom/k8s-breakglass/pkg/bgctl/output"
)

func unknownOutputFormatError(format output.Format, supported ...output.Format) error {
	if len(supported) == 0 {
		return fmt.Errorf("unknown output format: %s", format)
	}

	choices := make([]string, 0, len(supported))
	for _, value := range supported {
		choices = append(choices, string(value))
	}

	return fmt.Errorf("unknown output format: %s (choose from: %s)", format, strings.Join(choices, ", "))
}
