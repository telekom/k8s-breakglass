// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	artifacthost "github.com/telekom/k8s-breakglass/pkg/artifacts/host"
	"github.com/telekom/k8s-breakglass/pkg/config"
)

const artifactsCommand = "artifacts"

var errArtifactsUsage = errors.New("usage: breakglass artifacts provision [--config-path PATH]")

// runArtifactsCommand implements `breakglass artifacts provision`, the
// administrator-initiated provisioning of an empty local artifact volume. It
// reads the same config file as the controller so the roots, owner and
// instance ID match what startup verifies.
func runArtifactsCommand(args []string, stdout io.Writer) error {
	if len(args) == 0 || args[0] != "provision" {
		return errArtifactsUsage
	}
	configPath := os.Getenv("BREAKGLASS_CONFIG_PATH")
	if configPath == "" {
		configPath = "./config.yaml"
	}
	flags := flag.NewFlagSet("breakglass artifacts provision", flag.ContinueOnError)
	flags.SetOutput(stdout)
	flags.StringVar(&configPath, "config-path", configPath, "path to the controller config file (env BREAKGLASS_CONFIG_PATH)")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errArtifactsUsage
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	result, err := artifacthost.ProvisionLocal(cfg.Artifacts)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "local artifact storage %s (instance %s)\n", result, cfg.Artifacts.Local.InstanceID)
	return err
}
