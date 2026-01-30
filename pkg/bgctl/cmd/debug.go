package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/telekom/k8s-breakglass/pkg/bgctl/client"
	"github.com/telekom/k8s-breakglass/pkg/bgctl/output"
)

func NewDebugCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "debug",
		Short: "Manage debug sessions and templates",
	}

	cmd.AddCommand(
		newDebugSessionCommand(),
		newDebugTemplateCommand(),
		newDebugPodTemplateCommand(),
		newDebugKubectlCommand(),
	)
	return cmd
}

func newDebugSessionCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "session",
		Short: "Manage debug sessions",
	}
	cmd.AddCommand(
		newDebugSessionListCommand(),
		newDebugSessionGetCommand(),
		newDebugSessionCreateCommand(),
		newDebugSessionJoinCommand(),
		newDebugSessionLeaveCommand(),
		newDebugSessionRenewCommand(),
		newDebugSessionTerminateCommand(),
		newDebugSessionApproveCommand(),
		newDebugSessionRejectCommand(),
		newDebugSessionWatchCommand(),
	)
	return cmd
}

func newDebugSessionListCommand() *cobra.Command {
	var (
		cluster  string
		state    string
		user     string
		mine     bool
		page     int
		pageSize int
		allPages bool
	)
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List debug sessions",
		RunE: func(cmd *cobra.Command, _ []string) error {
			rt, err := getRuntime(cmd)
			if err != nil {
				return err
			}
			apiClient, err := buildClient(context.Background(), rt)
			if err != nil {
				return err
			}
			resp, err := apiClient.DebugSessions().List(context.Background(), client.DebugSessionListOptions{
				Cluster: cluster,
				State:   state,
				User:    user,
				Mine:    mine,
			})
			if err != nil {
				return err
			}
			cfgPageSize := pageSize
			if cfgPageSize == 0 && rt.cfg != nil {
				cfgPageSize = rt.cfg.Settings.PageSize
			}
			paged, info := paginate(resp.Sessions, page, cfgPageSize, allPages)
			format := output.Format(rt.OutputFormat())
			switch format {
			case output.FormatJSON, output.FormatYAML:
				return output.WriteObject(rt.Writer(), format, paged)
			case output.FormatTable:
				output.WriteDebugSessionTable(rt.Writer(), paged)
				if info != "" && !allPages {
					_, _ = fmt.Fprintln(rt.Writer(), info)
				}
				return nil
			case output.FormatWide:
				output.WriteDebugSessionTableWide(rt.Writer(), paged)
				if info != "" && !allPages {
					_, _ = fmt.Fprintln(rt.Writer(), info)
				}
				return nil
			default:
				return fmt.Errorf("unknown output format: %s", format)
			}
		},
	}
	cmd.Flags().StringVar(&cluster, "cluster", "", "Filter by cluster")
	cmd.Flags().StringVar(&state, "state", "", "Filter by state")
	cmd.Flags().StringVar(&user, "user", "", "Filter by requesting user")
	cmd.Flags().BoolVar(&mine, "mine", false, "Only sessions requested by current user")
	cmd.Flags().IntVar(&page, "page", 1, "Page number")
	cmd.Flags().IntVar(&pageSize, "page-size", 0, "Items per page")
	cmd.Flags().BoolVar(&allPages, "all", false, "Disable pagination")
	return cmd
}

func newDebugSessionWatchCommand() *cobra.Command {
	var (
		interval time.Duration
		cluster  string
		state    string
		user     string
		mine     bool
		showFull bool
	)
	cmd := &cobra.Command{
		Use:   "watch",
		Short: "Watch debug session changes",
		RunE: func(cmd *cobra.Command, _ []string) error {
			rt, err := getRuntime(cmd)
			if err != nil {
				return err
			}

			// Set up signal handling for graceful exit
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			apiClient, err := buildClient(ctx, rt)
			if err != nil {
				return err
			}
			seen := map[string]string{}
			ticker := time.NewTicker(interval)
			defer ticker.Stop()

			// Run first iteration immediately
			runWatch := func() error {
				resp, err := apiClient.DebugSessions().List(ctx, client.DebugSessionListOptions{
					Cluster: cluster,
					State:   state,
					User:    user,
					Mine:    mine,
				})
				if err != nil {
					return err
				}
				for _, s := range resp.Sessions {
					key := s.Name
					value := string(s.State)
					if prev, ok := seen[key]; !ok || prev != value {
						seen[key] = value
						if showFull {
							_ = output.WriteObject(rt.Writer(), output.FormatJSON, s)
						} else {
							_, _ = fmt.Fprintf(rt.Writer(), "%s\t%s\t%s\t%s\n", s.Name, s.Cluster, s.RequestedBy, s.State)
						}
					}
				}
				return nil
			}

			// First iteration
			if err := runWatch(); err != nil {
				return err
			}

			// Watch loop with graceful exit
			for {
				select {
				case <-ctx.Done():
					_, _ = fmt.Fprintln(rt.Writer(), "\nWatch stopped.")
					return nil
				case <-ticker.C:
					if err := runWatch(); err != nil {
						return err
					}
				}
			}
		},
	}
	cmd.Flags().DurationVar(&interval, "interval", 2*time.Second, "Polling interval")
	cmd.Flags().StringVar(&cluster, "cluster", "", "Filter by cluster")
	cmd.Flags().StringVar(&state, "state", "", "Filter by state")
	cmd.Flags().StringVar(&user, "user", "", "Filter by requesting user")
	cmd.Flags().BoolVar(&mine, "mine", false, "Only sessions requested by current user")
	cmd.Flags().BoolVar(&showFull, "show-full", false, "Show full session JSON on change")
	return cmd
}

func newDebugSessionGetCommand() *cobra.Command {
	var namespace string
	cmd := &cobra.Command{
		Use:   "get NAME",
		Short: "Get a debug session",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			rt, err := getRuntime(cmd)
			if err != nil {
				return err
			}
			apiClient, err := buildClient(context.Background(), rt)
			if err != nil {
				return err
			}
			session, err := apiClient.DebugSessions().Get(context.Background(), args[0], namespace)
			if err != nil {
				return err
			}
			return output.WriteObject(rt.Writer(), output.Format(rt.OutputFormat()), session)
		},
	}
	cmd.Flags().StringVar(&namespace, "namespace", "", "Namespace hint")
	return cmd
}

func newDebugSessionCreateCommand() *cobra.Command {
	var (
		templateRef              string
		cluster                  string
		bindingRef               string
		duration                 string
		namespace                string
		reason                   string
		invitees                 []string
		targetNamespace          string
		selectedSchedulingOption string
	)
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a debug session",
		Long: `Create a new debug session.

When multiple bindings are available for a cluster, use --binding to select
which binding configuration to use. You can list available bindings with:
  bgctl debug template clusters <template-name> -o wide

The --binding flag accepts the format "namespace/name" or just "name".`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			rt, err := getRuntime(cmd)
			if err != nil {
				return err
			}
			apiClient, err := buildClient(context.Background(), rt)
			if err != nil {
				return err
			}
			req := client.CreateDebugSessionRequest{
				TemplateRef:              templateRef,
				Cluster:                  cluster,
				BindingRef:               bindingRef, // Format: "namespace/name" or just "name" (defaults to breakglass/name)
				RequestedDuration:        duration,
				Namespace:                namespace,
				Reason:                   reason,
				InvitedParticipants:      invitees,
				TargetNamespace:          targetNamespace,
				SelectedSchedulingOption: selectedSchedulingOption,
			}

			// Normalize binding reference to namespace/name format if only name provided
			if bindingRef != "" && !strings.Contains(bindingRef, "/") {
				req.BindingRef = "breakglass/" + bindingRef // Default namespace
			}

			session, err := apiClient.DebugSessions().Create(context.Background(), req)
			if err != nil {
				return err
			}
			return output.WriteObject(rt.Writer(), output.Format(rt.OutputFormat()), session)
		},
	}
	cmd.Flags().StringVar(&templateRef, "template", "", "Debug session template name")
	cmd.Flags().StringVar(&cluster, "cluster", "", "Target cluster")
	cmd.Flags().StringVar(&bindingRef, "binding", "", "Binding reference (namespace/name or name) when multiple bindings exist")
	cmd.Flags().StringVar(&duration, "duration", "", "Requested duration (e.g. 1h)")
	cmd.Flags().StringVar(&namespace, "namespace", "", "Namespace to deploy debug pods (legacy, use --target-namespace)")
	cmd.Flags().StringVar(&reason, "reason", "", "Reason for debug session")
	cmd.Flags().StringSliceVar(&invitees, "invite", nil, "Invite participants")
	cmd.Flags().StringVar(&targetNamespace, "target-namespace", "", "Target namespace for debug pods")
	cmd.Flags().StringVar(&selectedSchedulingOption, "scheduling-option", "", "Scheduling option name (from template)")
	_ = cmd.MarkFlagRequired("template")
	_ = cmd.MarkFlagRequired("cluster")
	return cmd
}

func newDebugSessionJoinCommand() *cobra.Command {
	var (
		role      string
		namespace string
	)
	cmd := &cobra.Command{
		Use:   "join NAME",
		Short: "Join a debug session",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			rt, err := getRuntime(cmd)
			if err != nil {
				return err
			}
			apiClient, err := buildClient(context.Background(), rt)
			if err != nil {
				return err
			}
			session, err := apiClient.DebugSessions().Join(context.Background(), args[0], role, namespace)
			if err != nil {
				return err
			}
			return output.WriteObject(rt.Writer(), output.Format(rt.OutputFormat()), session)
		},
	}
	cmd.Flags().StringVar(&role, "role", "participant", "Role: participant|viewer")
	cmd.Flags().StringVar(&namespace, "namespace", "", "Namespace hint")
	return cmd
}

func newDebugSessionLeaveCommand() *cobra.Command {
	var namespace string
	cmd := &cobra.Command{
		Use:   "leave NAME",
		Short: "Leave a debug session",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			rt, err := getRuntime(cmd)
			if err != nil {
				return err
			}
			apiClient, err := buildClient(context.Background(), rt)
			if err != nil {
				return err
			}
			session, err := apiClient.DebugSessions().Leave(context.Background(), args[0], namespace)
			if err != nil {
				return err
			}
			return output.WriteObject(rt.Writer(), output.Format(rt.OutputFormat()), session)
		},
	}
	cmd.Flags().StringVar(&namespace, "namespace", "", "Namespace hint")
	return cmd
}

func newDebugSessionRenewCommand() *cobra.Command {
	var (
		extendBy  string
		namespace string
	)
	cmd := &cobra.Command{
		Use:   "renew NAME",
		Short: "Renew a debug session",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			rt, err := getRuntime(cmd)
			if err != nil {
				return err
			}
			apiClient, err := buildClient(context.Background(), rt)
			if err != nil {
				return err
			}
			session, err := apiClient.DebugSessions().Renew(context.Background(), args[0], extendBy, namespace)
			if err != nil {
				return err
			}
			return output.WriteObject(rt.Writer(), output.Format(rt.OutputFormat()), session)
		},
	}
	cmd.Flags().StringVar(&extendBy, "extend-by", "", "Extend duration by (e.g. 30m)")
	cmd.Flags().StringVar(&namespace, "namespace", "", "Namespace hint")
	_ = cmd.MarkFlagRequired("extend-by")
	return cmd
}

func newDebugSessionTerminateCommand() *cobra.Command {
	var namespace string
	cmd := &cobra.Command{
		Use:   "terminate NAME",
		Short: "Terminate a debug session",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			rt, err := getRuntime(cmd)
			if err != nil {
				return err
			}
			apiClient, err := buildClient(context.Background(), rt)
			if err != nil {
				return err
			}
			session, err := apiClient.DebugSessions().Terminate(context.Background(), args[0], namespace)
			if err != nil {
				return err
			}
			return output.WriteObject(rt.Writer(), output.Format(rt.OutputFormat()), session)
		},
	}
	cmd.Flags().StringVar(&namespace, "namespace", "", "Namespace hint")
	return cmd
}

func newDebugSessionApproveCommand() *cobra.Command {
	var (
		reason    string
		namespace string
	)
	cmd := &cobra.Command{
		Use:   "approve NAME",
		Short: "Approve a debug session",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			rt, err := getRuntime(cmd)
			if err != nil {
				return err
			}
			apiClient, err := buildClient(context.Background(), rt)
			if err != nil {
				return err
			}
			session, err := apiClient.DebugSessions().Approve(context.Background(), args[0], reason, namespace)
			if err != nil {
				return err
			}
			return output.WriteObject(rt.Writer(), output.Format(rt.OutputFormat()), session)
		},
	}
	cmd.Flags().StringVar(&reason, "reason", "", "Approval reason")
	cmd.Flags().StringVar(&namespace, "namespace", "", "Namespace hint")
	return cmd
}

func newDebugSessionRejectCommand() *cobra.Command {
	var (
		reason    string
		namespace string
	)
	cmd := &cobra.Command{
		Use:   "reject NAME",
		Short: "Reject a debug session",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			rt, err := getRuntime(cmd)
			if err != nil {
				return err
			}
			apiClient, err := buildClient(context.Background(), rt)
			if err != nil {
				return err
			}
			session, err := apiClient.DebugSessions().Reject(context.Background(), args[0], reason, namespace)
			if err != nil {
				return err
			}
			return output.WriteObject(rt.Writer(), output.Format(rt.OutputFormat()), session)
		},
	}
	cmd.Flags().StringVar(&reason, "reason", "", "Rejection reason")
	cmd.Flags().StringVar(&namespace, "namespace", "", "Namespace hint")
	return cmd
}

func newDebugTemplateCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "template",
		Short: "Manage debug session templates",
	}
	cmd.AddCommand(newDebugTemplateListCommand(), newDebugTemplateGetCommand(), newDebugTemplateClustersCommand(), newDebugTemplateBindingsCommand())
	return cmd
}

func newDebugTemplateListCommand() *cobra.Command {
	var includeUnavailable bool

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List debug session templates",
		Long: `List debug session templates available to the user.

By default, only templates with available clusters are shown. Use --all to include
templates without any available clusters.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			rt, err := getRuntime(cmd)
			if err != nil {
				return err
			}
			apiClient, err := buildClient(context.Background(), rt)
			if err != nil {
				return err
			}
			resp, err := apiClient.DebugTemplates().List(context.Background(), client.DebugTemplateListOptions{
				IncludeUnavailable: includeUnavailable,
			})
			if err != nil {
				return err
			}
			format := output.Format(rt.OutputFormat())
			switch format {
			case output.FormatJSON, output.FormatYAML:
				return output.WriteObject(rt.Writer(), format, resp.Templates)
			case output.FormatTable:
				output.WriteDebugTemplateTable(rt.Writer(), resp.Templates)
				// Show notice if templates were filtered
				if !includeUnavailable {
					_, _ = fmt.Fprintln(rt.Writer(), "\nNote: Only templates with available clusters are shown. Use --all to see all templates.")
				}
				return nil
			default:
				return fmt.Errorf("unknown output format: %s", format)
			}
		},
	}

	cmd.Flags().BoolVarP(&includeUnavailable, "all", "a", false, "Include templates without available clusters")

	return cmd
}

func newDebugTemplateGetCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "get NAME",
		Short: "Get a debug session template",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			rt, err := getRuntime(cmd)
			if err != nil {
				return err
			}
			apiClient, err := buildClient(context.Background(), rt)
			if err != nil {
				return err
			}
			template, err := apiClient.DebugTemplates().Get(context.Background(), args[0])
			if err != nil {
				return err
			}
			return output.WriteObject(rt.Writer(), output.Format(rt.OutputFormat()), template)
		},
	}
	return cmd
}

func newDebugTemplateClustersCommand() *cobra.Command {
	var (
		environment string
		location    string
		bindingName string
	)
	cmd := &cobra.Command{
		Use:   "clusters NAME",
		Short: "List available clusters for a debug session template",
		Long: `List all clusters that are available for the specified debug session template.

This shows cluster-specific details including:
- Binding references (which ClusterBinding enabled access)
- Scheduling constraints and options
- Namespace constraints
- Impersonation configuration
- Approval requirements`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			rt, err := getRuntime(cmd)
			if err != nil {
				return err
			}
			apiClient, err := buildClient(context.Background(), rt)
			if err != nil {
				return err
			}
			resp, err := apiClient.DebugTemplates().GetClusters(context.Background(), args[0], client.TemplateClustersOptions{
				Environment: environment,
				Location:    location,
				BindingName: bindingName,
			})
			if err != nil {
				return err
			}
			format := output.Format(rt.OutputFormat())
			switch format {
			case output.FormatJSON, output.FormatYAML:
				return output.WriteObject(rt.Writer(), format, resp)
			case output.FormatTable:
				output.WriteTemplateClusterTable(rt.Writer(), resp.Clusters)
				return nil
			case output.FormatWide:
				output.WriteTemplateClusterTableWide(rt.Writer(), resp.Clusters)
				return nil
			default:
				return fmt.Errorf("unknown output format: %s", format)
			}
		},
	}
	cmd.Flags().StringVar(&environment, "environment", "", "Filter by cluster environment")
	cmd.Flags().StringVar(&location, "location", "", "Filter by cluster location")
	cmd.Flags().StringVar(&bindingName, "binding", "", "Filter by binding name")
	return cmd
}

func newDebugTemplateBindingsCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "bindings TEMPLATE CLUSTER",
		Short: "List available binding options for a cluster",
		Long: `List all binding options available for a specific cluster and template.

When multiple ClusterBindings match a cluster, this shows each option with its
specific configuration including constraints, namespace settings, scheduling
options, and approval requirements.

Use this to determine which --binding value to pass to 'debug session create'.`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			rt, err := getRuntime(cmd)
			if err != nil {
				return err
			}
			apiClient, err := buildClient(context.Background(), rt)
			if err != nil {
				return err
			}

			templateName := args[0]
			clusterName := args[1]

			resp, err := apiClient.DebugTemplates().GetClusters(context.Background(), templateName, client.TemplateClustersOptions{})
			if err != nil {
				return err
			}

			// Find the requested cluster
			var clusterDetail *client.AvailableClusterDetail
			for i := range resp.Clusters {
				if resp.Clusters[i].Name == clusterName {
					clusterDetail = &resp.Clusters[i]
					break
				}
			}

			if clusterDetail == nil {
				return fmt.Errorf("cluster '%s' not found for template '%s'", clusterName, templateName)
			}

			format := output.Format(rt.OutputFormat())
			switch format {
			case output.FormatJSON, output.FormatYAML:
				return output.WriteObject(rt.Writer(), format, clusterDetail.BindingOptions)
			case output.FormatTable, output.FormatWide:
				output.WriteBindingOptionsTable(rt.Writer(), clusterName, clusterDetail.BindingOptions)
				return nil
			default:
				return fmt.Errorf("unknown output format: %s", format)
			}
		},
	}
	return cmd
}

func newDebugPodTemplateCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "pod-template",
		Short: "Manage debug pod templates",
	}
	cmd.AddCommand(newDebugPodTemplateListCommand(), newDebugPodTemplateGetCommand())
	return cmd
}

func newDebugPodTemplateListCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List debug pod templates",
		RunE: func(cmd *cobra.Command, _ []string) error {
			rt, err := getRuntime(cmd)
			if err != nil {
				return err
			}
			apiClient, err := buildClient(context.Background(), rt)
			if err != nil {
				return err
			}
			resp, err := apiClient.DebugPodTemplates().List(context.Background())
			if err != nil {
				return err
			}
			format := output.Format(rt.OutputFormat())
			switch format {
			case output.FormatJSON, output.FormatYAML:
				return output.WriteObject(rt.Writer(), format, resp.Templates)
			case output.FormatTable:
				output.WriteDebugPodTemplateTable(rt.Writer(), resp.Templates)
				return nil
			default:
				return fmt.Errorf("unknown output format: %s", format)
			}
		},
	}
	return cmd
}

func newDebugPodTemplateGetCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "get NAME",
		Short: "Get a debug pod template",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			rt, err := getRuntime(cmd)
			if err != nil {
				return err
			}
			apiClient, err := buildClient(context.Background(), rt)
			if err != nil {
				return err
			}
			template, err := apiClient.DebugPodTemplates().Get(context.Background(), args[0])
			if err != nil {
				return err
			}
			return output.WriteObject(rt.Writer(), output.Format(rt.OutputFormat()), template)
		},
	}
	return cmd
}

func newDebugKubectlCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "kubectl",
		Short: "Kubectl-debug operations",
	}
	cmd.AddCommand(
		newDebugKubectlInjectCommand(),
		newDebugKubectlCopyPodCommand(),
		newDebugKubectlNodeDebugCommand(),
	)
	return cmd
}

func newDebugKubectlInjectCommand() *cobra.Command {
	var (
		namespace string
		pod       string
		container string
		image     string
		command   []string
		hintNS    string
	)
	cmd := &cobra.Command{
		Use:   "inject NAME",
		Short: "Inject an ephemeral container",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			rt, err := getRuntime(cmd)
			if err != nil {
				return err
			}
			apiClient, err := buildClient(context.Background(), rt)
			if err != nil {
				return err
			}
			resp, err := apiClient.DebugSessions().InjectEphemeralContainer(context.Background(), args[0], hintNS, client.InjectEphemeralContainerRequest{
				Namespace:     namespace,
				PodName:       pod,
				ContainerName: container,
				Image:         image,
				Command:       command,
			})
			if err != nil {
				return err
			}
			return output.WriteObject(rt.Writer(), output.Format(rt.OutputFormat()), resp)
		},
	}
	cmd.Flags().StringVar(&namespace, "namespace", "", "Target namespace")
	cmd.Flags().StringVar(&pod, "pod", "", "Target pod")
	cmd.Flags().StringVar(&container, "container", "debug", "Ephemeral container name")
	cmd.Flags().StringVar(&image, "image", "", "Ephemeral container image")
	cmd.Flags().StringSliceVar(&command, "command", nil, "Command for container")
	cmd.Flags().StringVar(&hintNS, "session-namespace", "", "Debug session namespace hint")
	_ = cmd.MarkFlagRequired("namespace")
	_ = cmd.MarkFlagRequired("pod")
	_ = cmd.MarkFlagRequired("image")
	return cmd
}

func newDebugKubectlCopyPodCommand() *cobra.Command {
	var (
		namespace string
		pod       string
		image     string
		hintNS    string
	)
	cmd := &cobra.Command{
		Use:   "copy-pod NAME",
		Short: "Create a debug copy of a pod",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			rt, err := getRuntime(cmd)
			if err != nil {
				return err
			}
			apiClient, err := buildClient(context.Background(), rt)
			if err != nil {
				return err
			}
			resp, err := apiClient.DebugSessions().CreatePodCopy(context.Background(), args[0], hintNS, client.CreatePodCopyRequest{
				Namespace:  namespace,
				PodName:    pod,
				DebugImage: image,
			})
			if err != nil {
				return err
			}
			return output.WriteObject(rt.Writer(), output.Format(rt.OutputFormat()), resp)
		},
	}
	cmd.Flags().StringVar(&namespace, "namespace", "", "Target namespace")
	cmd.Flags().StringVar(&pod, "pod", "", "Target pod")
	cmd.Flags().StringVar(&image, "image", "", "Debug image override")
	cmd.Flags().StringVar(&hintNS, "session-namespace", "", "Debug session namespace hint")
	_ = cmd.MarkFlagRequired("namespace")
	_ = cmd.MarkFlagRequired("pod")
	return cmd
}

func newDebugKubectlNodeDebugCommand() *cobra.Command {
	var (
		node   string
		hintNS string
	)
	cmd := &cobra.Command{
		Use:   "node-debug SESSION",
		Short: "Create a node debug pod",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			rt, err := getRuntime(cmd)
			if err != nil {
				return err
			}
			apiClient, err := buildClient(context.Background(), rt)
			if err != nil {
				return err
			}
			resp, err := apiClient.DebugSessions().CreateNodeDebugPod(context.Background(), args[0], hintNS, client.CreateNodeDebugPodRequest{NodeName: node})
			if err != nil {
				return err
			}
			return output.WriteObject(rt.Writer(), output.Format(rt.OutputFormat()), resp)
		},
	}
	cmd.Flags().StringVar(&node, "node", "", "Target node name")
	cmd.Flags().StringVar(&hintNS, "session-namespace", "", "Debug session namespace hint")
	_ = cmd.MarkFlagRequired("node")
	return cmd
}
