package main

import (
	"os"

	bgctlcmd "github.com/telekom/k8s-breakglass/pkg/bgctl/cmd"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	root := bgctlcmd.NewRootCommand(bgctlcmd.DefaultConfig())
	root.SetArgs(args)
	if err := root.Execute(); err != nil {
		return 1
	}
	return 0
}
