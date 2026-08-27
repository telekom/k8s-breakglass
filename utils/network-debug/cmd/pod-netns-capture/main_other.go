// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
)

func main() {
	_, err := parseOptions(os.Args[1:])
	if errors.Is(err, flag.ErrHelp) {
		usage(os.Stdout)
		return
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "pod-netns-capture: %s\n", stableError(err))
		usage(os.Stderr)
		os.Exit(2)
	}
	fmt.Fprintln(os.Stderr, "pod-netns-capture: Linux setns support is required")
	os.Exit(1)
}
