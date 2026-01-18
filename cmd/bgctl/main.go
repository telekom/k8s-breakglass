package main

import (
	"os"

	bgctlcmd "github.com/telekom/k8s-breakglass/pkg/bgctl/cmd"
)

func main() {
	root := bgctlcmd.NewRootCommand(bgctlcmd.DefaultConfig())
	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}
