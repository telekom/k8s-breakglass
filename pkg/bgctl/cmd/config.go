package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/telekom/k8s-breakglass/pkg/bgctl/config"
	"github.com/telekom/k8s-breakglass/pkg/bgctl/output"
)

func NewConfigCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Manage bgctl configuration",
	}

	cmd.AddCommand(
		newConfigInitCommand(),
		newConfigViewCommand(),
		newConfigContextsCommand(),
		newConfigCurrentContextCommand(),
		newConfigSetContextCommand(),
		newConfigUseContextCommand(),
		newConfigSetValueCommand(),
		newConfigAddContextCommand(),
		newConfigAddOIDCProviderCommand(),
		newConfigGetOIDCProvidersCommand(),
		newConfigDeleteContextCommand(),
		newConfigDeleteOIDCProviderCommand(),
	)

	return cmd
}

func newConfigInitCommand() *cobra.Command {
	var (
		contextName   string
		server        string
		oidcAuthority string
		oidcClientID  string
		oidcProvider  string
		insecure      bool
		force         bool
	)

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize a bgctl config file",
		RunE: func(cmd *cobra.Command, _ []string) error {
			rt, err := getRuntime(cmd)
			if err != nil {
				return err
			}
			path := rt.configPathValue()
			if !force {
				if _, err := os.Stat(path); err == nil {
					return fmt.Errorf("config already exists: %s", path)
				}
			}
			if contextName == "" {
				contextName = "default"
			}
			cfg := config.DefaultConfig()
			cfg.CurrentContext = contextName
			if oidcProvider == "" {
				if oidcAuthority == "" || oidcClientID == "" {
					return errors.New("oidc-authority and oidc-client-id are required when oidc-provider is not set")
				}
				cfg.Contexts = append(cfg.Contexts, config.Context{
					Name:                  contextName,
					Server:                server,
					InsecureSkipTLSVerify: insecure,
					OIDC: &config.InlineOIDC{
						Authority: oidcAuthority,
						ClientID:  oidcClientID,
					},
				})
			} else {
				cfg.Contexts = append(cfg.Contexts, config.Context{
					Name:                  contextName,
					Server:                server,
					InsecureSkipTLSVerify: insecure,
					OIDCProvider:          oidcProvider,
				})
			}
			if err := config.Save(path, &cfg); err != nil {
				return err
			}
			_, _ = fmt.Fprintf(rt.Writer(), "Initialized config at %s\n", path)
			return nil
		},
	}

	cmd.Flags().StringVar(&contextName, "context", "default", "Context name")
	cmd.Flags().StringVar(&server, "server", "", "Breakglass server URL")
	cmd.Flags().StringVar(&oidcAuthority, "oidc-authority", "", "OIDC authority URL")
	cmd.Flags().StringVar(&oidcClientID, "oidc-client-id", "", "OIDC client ID")
	cmd.Flags().StringVar(&oidcProvider, "oidc-provider", "", "OIDC provider name to reference")
	cmd.Flags().BoolVar(&insecure, "insecure-skip-tls-verify", false, "Skip TLS verification")
	cmd.Flags().BoolVar(&force, "force", false, "Overwrite existing config")

	_ = cmd.MarkFlagRequired("server")
	return cmd
}

func newConfigViewCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "view",
		Short: "Show the current configuration",
		RunE: func(cmd *cobra.Command, _ []string) error {
			rt, err := getRuntime(cmd)
			if err != nil {
				return err
			}
			if err := rt.EnsureConfigLoaded(); err != nil {
				return err
			}
			return output.WriteObject(rt.Writer(), output.FormatYAML, rt.cfg)
		},
	}
}

func newConfigContextsCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "get-contexts",
		Short: "List configured contexts",
		RunE: func(cmd *cobra.Command, _ []string) error {
			rt, err := getRuntime(cmd)
			if err != nil {
				return err
			}
			if err := rt.EnsureConfigLoaded(); err != nil {
				return err
			}
			current := rt.cfg.CurrentContext
			for _, ctx := range rt.cfg.Contexts {
				marker := " "
				if ctx.Name == current {
					marker = "*"
				}
				_, _ = fmt.Fprintf(rt.Writer(), "%s %s\t%s\n", marker, ctx.Name, ctx.Server)
			}
			return nil
		},
	}
}

func newConfigSetContextCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "set-context NAME",
		Short: "Set the default context",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			rt, err := getRuntime(cmd)
			if err != nil {
				return err
			}
			if err := rt.EnsureConfigLoaded(); err != nil {
				return err
			}
			name := args[0]
			if _, err := rt.cfg.FindContext(name); err != nil {
				return err
			}
			rt.cfg.CurrentContext = name
			if err := config.Save(rt.configPathValue(), rt.cfg); err != nil {
				return err
			}
			_, _ = fmt.Fprintf(rt.Writer(), "%s\n", name)
			return nil
		},
	}
}

func newConfigUseContextCommand() *cobra.Command {
	cmd := newConfigSetContextCommand()
	cmd.Use = "use-context NAME"
	cmd.Aliases = []string{"use"}
	cmd.Short = "Alias for set-context"
	return cmd
}

func newConfigCurrentContextCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "current-context",
		Short: "Show the current context",
		RunE: func(cmd *cobra.Command, _ []string) error {
			rt, err := getRuntime(cmd)
			if err != nil {
				return err
			}
			if err := rt.EnsureConfigLoaded(); err != nil {
				return err
			}
			_, _ = fmt.Fprintln(rt.Writer(), rt.cfg.CurrentContext)
			return nil
		},
	}
}

func newConfigSetValueCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "set KEY VALUE",
		Short: "Set a configuration value",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			rt, err := getRuntime(cmd)
			if err != nil {
				return err
			}
			if err := rt.EnsureConfigLoaded(); err != nil {
				return err
			}
			key := args[0]
			value := args[1]
			switch key {
			case "settings.output-format":
				rt.cfg.Settings.OutputFormat = value
			case "settings.color":
				rt.cfg.Settings.Color = value
			case "settings.page-size":
				var pageSize int
				_, err := fmt.Sscanf(value, "%d", &pageSize)
				if err != nil {
					return fmt.Errorf("invalid page size: %s", value)
				}
				rt.cfg.Settings.PageSize = pageSize
			default:
				return fmt.Errorf("unsupported key: %s", key)
			}
			if err := config.Save(rt.configPathValue(), rt.cfg); err != nil {
				return err
			}
			return nil
		},
	}
}

func newConfigAddContextCommand() *cobra.Command {
	var (
		server        string
		oidcProvider  string
		oidcAuthority string
		oidcClientID  string
		insecure      bool
	)
	cmd := &cobra.Command{
		Use:   "add-context NAME",
		Short: "Add a new context",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			rt, err := getRuntime(cmd)
			if err != nil {
				return err
			}
			if err := rt.EnsureConfigLoaded(); err != nil {
				return err
			}
			name := args[0]
			if _, err := rt.cfg.FindContext(name); err == nil {
				return fmt.Errorf("context already exists: %s", name)
			}
			ctx := config.Context{
				Name:                  name,
				Server:                server,
				OIDCProvider:          oidcProvider,
				InsecureSkipTLSVerify: insecure,
			}
			if oidcProvider == "" {
				if oidcAuthority == "" || oidcClientID == "" {
					return errors.New("oidc-authority and oidc-client-id are required when oidc-provider is not set")
				}
				ctx.OIDC = &config.InlineOIDC{Authority: oidcAuthority, ClientID: oidcClientID}
			}
			rt.cfg.Contexts = append(rt.cfg.Contexts, ctx)
			if err := config.Save(rt.configPathValue(), rt.cfg); err != nil {
				return err
			}
			_, _ = fmt.Fprintf(rt.Writer(), "Added context %s\n", name)
			return nil
		},
	}
	cmd.Flags().StringVar(&server, "server", "", "Breakglass server URL")
	cmd.Flags().StringVar(&oidcProvider, "oidc-provider", "", "OIDC provider name")
	cmd.Flags().StringVar(&oidcAuthority, "oidc-authority", "", "OIDC authority URL")
	cmd.Flags().StringVar(&oidcClientID, "oidc-client-id", "", "OIDC client ID")
	cmd.Flags().BoolVar(&insecure, "insecure-skip-tls-verify", false, "Skip TLS verification")
	_ = cmd.MarkFlagRequired("server")
	return cmd
}

func newConfigAddOIDCProviderCommand() *cobra.Command {
	var (
		authority        string
		clientID         string
		clientSecret     string
		clientSecretEnv  string
		clientSecretFile string
		grantType        string
		caFile           string
	)
	cmd := &cobra.Command{
		Use:   "add-oidc-provider NAME",
		Short: "Add a reusable OIDC provider",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			rt, err := getRuntime(cmd)
			if err != nil {
				return err
			}
			if err := rt.EnsureConfigLoaded(); err != nil {
				return err
			}
			name := args[0]
			if _, err := rt.cfg.FindOIDCProvider(name); err == nil {
				return fmt.Errorf("oidc provider already exists: %s", name)
			}
			provider := config.OIDCProvider{
				Name:             name,
				Authority:        authority,
				ClientID:         clientID,
				ClientSecret:     clientSecret,
				ClientSecretEnv:  clientSecretEnv,
				ClientSecretFile: clientSecretFile,
				GrantType:        grantType,
				CAFile:           caFile,
			}
			rt.cfg.OIDCProviders = append(rt.cfg.OIDCProviders, provider)
			if err := config.Save(rt.configPathValue(), rt.cfg); err != nil {
				return err
			}
			_, _ = fmt.Fprintf(rt.Writer(), "Added OIDC provider %s\n", name)
			return nil
		},
	}
	cmd.Flags().StringVar(&authority, "authority", "", "OIDC authority URL")
	cmd.Flags().StringVar(&clientID, "client-id", "", "OIDC client ID")
	cmd.Flags().StringVar(&clientSecret, "client-secret", "", "OIDC client secret")
	cmd.Flags().StringVar(&clientSecretEnv, "client-secret-env", "", "OIDC client secret env var")
	cmd.Flags().StringVar(&clientSecretFile, "client-secret-file", "", "OIDC client secret file")
	cmd.Flags().StringVar(&grantType, "grant-type", "authorization-code", "OIDC grant type")
	cmd.Flags().StringVar(&caFile, "ca-file", "", "CA file")
	_ = cmd.MarkFlagRequired("authority")
	_ = cmd.MarkFlagRequired("client-id")
	return cmd
}

func newConfigGetOIDCProvidersCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "get-oidc-providers",
		Short: "List configured OIDC providers",
		RunE: func(cmd *cobra.Command, _ []string) error {
			rt, err := getRuntime(cmd)
			if err != nil {
				return err
			}
			if err := rt.EnsureConfigLoaded(); err != nil {
				return err
			}
			for _, p := range rt.cfg.OIDCProviders {
				_, _ = fmt.Fprintf(rt.Writer(), "%s\t%s\t%s\n", p.Name, p.Authority, p.ClientID)
			}
			return nil
		},
	}
}

func newConfigDeleteContextCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "delete-context NAME",
		Short: "Delete a context",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			rt, err := getRuntime(cmd)
			if err != nil {
				return err
			}
			if err := rt.EnsureConfigLoaded(); err != nil {
				return err
			}
			name := args[0]
			contexts := rt.cfg.Contexts
			filtered := contexts[:0]
			found := false
			for _, ctx := range contexts {
				if ctx.Name == name {
					found = true
					continue
				}
				filtered = append(filtered, ctx)
			}
			if !found {
				return fmt.Errorf("context not found: %s", name)
			}
			rt.cfg.Contexts = filtered
			if rt.cfg.CurrentContext == name {
				rt.cfg.CurrentContext = ""
			}
			if err := config.Save(rt.configPathValue(), rt.cfg); err != nil {
				return err
			}
			_, _ = fmt.Fprintf(rt.Writer(), "Deleted context %s\n", name)
			return nil
		},
	}
}

func newConfigDeleteOIDCProviderCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "delete-oidc-provider NAME",
		Short: "Delete an OIDC provider",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			rt, err := getRuntime(cmd)
			if err != nil {
				return err
			}
			if err := rt.EnsureConfigLoaded(); err != nil {
				return err
			}
			name := args[0]
			for _, ctx := range rt.cfg.Contexts {
				if ctx.OIDCProvider == name {
					return fmt.Errorf("oidc provider %s still referenced by context %s", name, ctx.Name)
				}
			}
			providers := rt.cfg.OIDCProviders
			filtered := providers[:0]
			found := false
			for _, p := range providers {
				if p.Name == name {
					found = true
					continue
				}
				filtered = append(filtered, p)
			}
			if !found {
				return fmt.Errorf("oidc provider not found: %s", name)
			}
			rt.cfg.OIDCProviders = filtered
			if err := config.Save(rt.configPathValue(), rt.cfg); err != nil {
				return err
			}
			_, _ = fmt.Fprintf(rt.Writer(), "Deleted OIDC provider %s\n", name)
			return nil
		},
	}
}
