// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"
	"strings"

	"github.com/telekom/k8s-breakglass/pkg/bgctl/output"
)

func validateOutputFormat(format output.Format, supported ...output.Format) error {
	for _, value := range supported {
		if format == value {
			return nil
		}
	}
	return unsupportedOutputFormatError(format, supported...)
}

func writeRuntimeObject(rt *runtimeState, obj any, supported ...output.Format) error {
	format := output.Format(rt.OutputFormat())
	if err := validateOutputFormat(format, supported...); err != nil {
		return err
	}
	return output.WriteObject(rt.Writer(), format, obj)
}

// unsupportedOutputFormatError returns an error indicating that the given
// format is not supported by the current command, listing the supported choices.
func unsupportedOutputFormatError(format output.Format, supported ...output.Format) error {
	if len(supported) == 0 {
		return fmt.Errorf("unsupported output format: %q", format)
	}

	choices := make([]string, 0, len(supported))
	for _, value := range supported {
		choices = append(choices, string(value))
	}

	return fmt.Errorf("unsupported output format: %q (choose from: %s)", format, strings.Join(choices, ", "))
}
