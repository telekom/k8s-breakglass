package cmd

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/telekom/k8s-breakglass/pkg/bgctl/config"
)

type Config struct {
	ConfigPath     string
	OutputWriter   io.Writer
	DefaultContext string
}

type runtimeState struct {
	configPath           string
	cfg                  *config.Config
	contextOverride      string
	outputFormat         string
	serverOverride       string
	tokenOverride        string
	tokenStorageOverride string
	nonInteractive       bool
	verbose              bool
	writer               io.Writer
}

type runtimeKey struct{}

func DefaultConfig() Config {
	return Config{
		ConfigPath:   config.DefaultConfigPath(),
		OutputWriter: os.Stdout,
	}
}

func NewRootCommand(cfg Config) *cobra.Command {
	rt := &runtimeState{configPath: cfg.ConfigPath, writer: cfg.OutputWriter}

	root := &cobra.Command{
		Use:   "bgctl",
		Short: "Breakglass CLI",
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			if rt.writer == nil {
				rt.writer = os.Stdout
			}
			if rt.configPath == "" {
				rt.configPath = config.DefaultConfigPath()
			}
			if rt.contextOverride == "" {
				rt.contextOverride = os.Getenv("BGCTL_CONTEXT")
			}
			if rt.outputFormat == "" {
				rt.outputFormat = os.Getenv("BGCTL_OUTPUT")
			}
			if rt.serverOverride == "" {
				rt.serverOverride = os.Getenv("BGCTL_SERVER")
			}
			if rt.tokenOverride == "" {
				rt.tokenOverride = os.Getenv("BGCTL_TOKEN")
			}
			if rt.tokenStorageOverride == "" {
				rt.tokenStorageOverride = os.Getenv("BGCTL_TOKEN_STORAGE")
			}
			if !rt.nonInteractive {
				rt.nonInteractive = strings.EqualFold(os.Getenv("BGCTL_NON_INTERACTIVE"), "true")
			}
			if !rt.verbose {
				rt.verbose = strings.EqualFold(os.Getenv("BGCTL_VERBOSE"), "true")
			}

			// Skip config loading for commands that don't need it
			if cmd.Name() == "init" && cmd.Parent() != nil && cmd.Parent().Name() == "config" {
				return nil
			}
			if cmd.Name() == "version" || cmd.Name() == "completion" {
				return nil
			}
			// Skip config loading if server and token are both provided via flags or env vars.
			// This allows users to run commands without a config file when they provide
			// all necessary connection info on the command line.
			if rt.serverOverride != "" && rt.tokenOverride != "" {
				// Create a minimal config with an empty context that will be overridden
				rt.cfg = &config.Config{
					Version: config.VersionV1,
				}
				return nil
			}

			cfg, err := config.Load(rt.configPath)
			if err != nil {
				return err
			}
			rt.cfg = cfg
			return nil
		},
	}

	root.PersistentFlags().StringVar(&rt.configPath, "config", rt.configPath, "Path to config file")
	root.PersistentFlags().StringVarP(&rt.contextOverride, "context", "c", "", "Context name override")
	root.PersistentFlags().StringVarP(&rt.outputFormat, "output", "o", "", "Output format: table, json, yaml")
	root.PersistentFlags().StringVar(&rt.serverOverride, "server", "", "Server override (bypass config)")
	root.PersistentFlags().StringVar(&rt.tokenOverride, "token", "", "Bearer token override")
	root.PersistentFlags().StringVar(&rt.tokenStorageOverride, "token-storage", "", "Token storage backend: keychain or file")
	root.PersistentFlags().BoolVar(&rt.nonInteractive, "non-interactive", false, "Fail instead of prompting")
	root.PersistentFlags().BoolVarP(&rt.verbose, "verbose", "v", false, "Enable verbose output with correlation IDs")

	root.SetContext(context.WithValue(context.Background(), runtimeKey{}, rt))

	root.AddCommand(
		NewConfigCommand(),
		NewAuthCommand(),
		NewSessionCommand(),
		NewEscalationCommand(),
		NewDebugCommand(),
		NewCompletionCommand(),
		NewUpdateCommand(),
		NewVersionCommand(),
	)

	return root
}

func getRuntime(cmd *cobra.Command) (*runtimeState, error) {
	rt, ok := cmd.Context().Value(runtimeKey{}).(*runtimeState)
	if !ok || rt == nil {
		return nil, errors.New("runtime not initialized")
	}
	return rt, nil
}

func (rt *runtimeState) ResolveContextName() string {
	if rt.contextOverride != "" {
		return rt.contextOverride
	}
	if rt.cfg != nil {
		return rt.cfg.CurrentContextOrDefault()
	}
	return ""
}

func (rt *runtimeState) OutputFormat() string {
	if rt.outputFormat != "" {
		return rt.outputFormat
	}
	if rt.cfg != nil && rt.cfg.Settings.OutputFormat != "" {
		return rt.cfg.Settings.OutputFormat
	}
	return "table"
}

func (rt *runtimeState) TokenStorage() string {
	if rt.tokenStorageOverride != "" {
		return rt.tokenStorageOverride
	}
	if rt.cfg != nil && rt.cfg.Settings.TokenStorage != "" {
		return rt.cfg.Settings.TokenStorage
	}
	return ""
}

func (rt *runtimeState) Writer() io.Writer {
	if rt.writer != nil {
		return rt.writer
	}
	return os.Stdout
}

func (rt *runtimeState) EnsureConfigLoaded() error {
	if rt.cfg != nil {
		return nil
	}
	cfg, err := config.Load(rt.configPath)
	if err != nil {
		return err
	}
	rt.cfg = cfg
	return nil
}

func (rt *runtimeState) ResolveContext() (*config.Context, error) {
	if rt.cfg == nil {
		return nil, errors.New("config not loaded")
	}
	name := rt.ResolveContextName()
	if name == "" {
		return nil, errors.New("no context configured")
	}
	return rt.cfg.FindContext(name)
}

func (rt *runtimeState) resolveServer(ctx *config.Context) string {
	if rt.serverOverride != "" {
		return rt.serverOverride
	}
	if ctx != nil {
		return ctx.Server
	}
	return ""
}

func (rt *runtimeState) resolveToken() string {
	return rt.tokenOverride
}

func (rt *runtimeState) configPathValue() string {
	if rt.configPath == "" {
		return config.DefaultConfigPath()
	}
	return rt.configPath
}
