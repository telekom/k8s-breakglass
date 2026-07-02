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
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/bgctl/client"
	"github.com/telekom/k8s-breakglass/pkg/bgctl/output"
)

func NewSessionCommand() *cobra.Command {
	cmd := newHelpOnlyGroupCommand("session", "Manage breakglass sessions")

	cmd.AddCommand(
		newSessionListCommand(),
		newSessionGetCommand(),
		newSessionRequestCommand(),
		newSessionApproveCommand(),
		newSessionRejectCommand(),
		newSessionWithdrawCommand(),
		newSessionDropCommand(),
		newSessionCancelCommand(),
		newSessionWatchCommand(),
	)

	return cmd
}

func newSessionWatchCommand() *cobra.Command {
	var (
		interval   time.Duration
		cluster    string
		user       string
		group      string
		state      string
		mine       bool
		showFull   bool
		approver   bool
		activeOnly bool
	)
	cmd := &cobra.Command{
		Use:   "watch",
		Short: "Watch session changes",
		Long: `Watch breakglass session changes by polling the API.

The command prints sessions when they first appear or when their state changes.
Use filters to reduce noise in busy environments.`,
		Example: `  bgctl session watch --mine
  bgctl session watch -C prod -s Pending,Approved -i 5s
  bgctl session watch --show-full -o json`,
		PreRunE: func(cmd *cobra.Command, _ []string) error {
			rt, err := getRuntime(cmd)
			if err != nil {
				return err
			}
			if err := validateOutputFormat(output.Format(rt.OutputFormat()), output.FormatTable, output.FormatWide, output.FormatJSON, output.FormatYAML); err != nil {
				return err
			}
			if interval <= 0 {
				return fmt.Errorf("interval must be greater than 0")
			}
			return nil
		},
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
				opts := client.SessionListOptions{
					Cluster:    cluster,
					User:       user,
					Group:      group,
					Mine:       mine,
					Approver:   sessionApproverOption(cmd, approver),
					ActiveOnly: activeOnly,
				}
				if state != "" {
					opts.State = strings.Split(state, ",")
				}
				sessions, err := apiClient.Sessions().List(ctx, opts)
				if err != nil {
					return err
				}
				for _, s := range sessions {
					key := s.Name
					value := string(s.Status.State)
					if prev, ok := seen[key]; !ok || prev != value {
						seen[key] = value
						if showFull {
							format := output.Format(rt.OutputFormat())
							if format == output.FormatTable || format == output.FormatWide {
								format = output.FormatJSON
							}
							if err := output.WriteObject(rt.Writer(), format, s); err != nil {
								return err
							}
						} else {
							if _, err := fmt.Fprintf(rt.Writer(), "%s\t%s\t%s\t%s\n", s.Name, s.Spec.Cluster, s.Spec.User, s.Status.State); err != nil {
								return err
							}
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
	cmd.Flags().DurationVarP(&interval, "interval", "i", 2*time.Second, "Polling interval (Go duration, e.g. 2s, 1m)")
	cmd.Flags().StringVarP(&cluster, "cluster", "C", "", "Filter by cluster")
	cmd.Flags().StringVarP(&user, "user", "u", "", "Filter by user")
	cmd.Flags().StringVarP(&group, "group", "g", "", "Filter by group")
	cmd.Flags().StringVarP(&state, "state", "s", "", "Filter by state (comma-separated)")
	cmd.Flags().BoolVarP(&mine, "mine", "m", false, "Only show sessions created by the current user")
	cmd.Flags().BoolVar(&approver, "approver", true, "Include sessions where you are an approver")
	cmd.Flags().BoolVarP(&activeOnly, "active", "A", false, "Only show active sessions")
	cmd.Flags().BoolVarP(&showFull, "show-full", "f", false, "Show full session JSON on change")
	return cmd
}

func newSessionListCommand() *cobra.Command {
	var (
		mine         bool
		approver     bool
		approvedByMe bool
		activeOnly   bool
		cluster      string
		user         string
		group        string
		state        string
		page         int
		pageSize     int
		allPages     bool
	)
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List breakglass sessions",
		Long: `List breakglass sessions visible to the current user.

By default the command includes sessions where you are an approver. Use --mine
to show only your own requests, or --approved-by-me for sessions you approved.`,
		Example: `  bgctl session list --mine
  bgctl session list -C prod -s Pending,Approved -o wide
  bgctl session list --approved-by-me --all`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			rt, err := getRuntime(cmd)
			if err != nil {
				return err
			}
			apiClient, err := buildClient(context.Background(), rt)
			if err != nil {
				return err
			}
			opts := client.SessionListOptions{
				Cluster:      cluster,
				User:         user,
				Group:        group,
				Mine:         mine,
				Approver:     sessionApproverOption(cmd, approver),
				ApprovedByMe: approvedByMe,
				ActiveOnly:   activeOnly,
			}
			if state != "" {
				opts.State = strings.Split(state, ",")
			}
			sessions, err := apiClient.Sessions().List(context.Background(), opts)
			if err != nil {
				return err
			}
			cfgPageSize := pageSize
			if cfgPageSize == 0 && rt.cfg != nil {
				cfgPageSize = rt.cfg.Settings.PageSize
			}
			paged, info := paginate(sessions, page, cfgPageSize, allPages)
			format := output.Format(rt.OutputFormat())
			switch format {
			case output.FormatJSON, output.FormatYAML:
				return output.WriteObject(rt.Writer(), format, paged)
			case output.FormatTable:
				output.WriteSessionTable(rt.Writer(), paged)
				if info != "" && !allPages {
					_, _ = fmt.Fprintln(rt.Writer(), info)
				}
				return nil
			case output.FormatWide:
				output.WriteSessionTableWide(rt.Writer(), paged)
				if info != "" && !allPages {
					_, _ = fmt.Fprintln(rt.Writer(), info)
				}
				return nil
			default:
				return unsupportedOutputFormatError(format, output.FormatTable, output.FormatWide, output.FormatJSON, output.FormatYAML)
			}
		},
	}
	cmd.Flags().BoolVarP(&mine, "mine", "m", false, "Only show sessions created by the current user")
	cmd.Flags().BoolVar(&approver, "approver", true, "Include sessions where you are an approver")
	cmd.Flags().BoolVarP(&approvedByMe, "approved-by-me", "M", false, "Only show sessions approved by you")
	cmd.Flags().BoolVarP(&activeOnly, "active", "A", false, "Only show active sessions")
	cmd.Flags().StringVarP(&cluster, "cluster", "C", "", "Filter by cluster name")
	cmd.Flags().StringVarP(&user, "user", "u", "", "Filter by user")
	cmd.Flags().StringVarP(&group, "group", "g", "", "Filter by group")
	cmd.Flags().StringVarP(&state, "state", "s", "", "Filter by state (comma-separated)")
	cmd.Flags().IntVarP(&page, "page", "p", 1, "Page number")
	cmd.Flags().IntVar(&pageSize, "page-size", 0, "Items per page")
	cmd.Flags().BoolVarP(&allPages, "all", "a", false, "Disable pagination")
	return cmd
}

func sessionApproverOption(cmd *cobra.Command, approver bool) *bool {
	if !cmd.Flags().Changed("approver") {
		return nil
	}
	value := approver
	return &value
}

func newSessionGetCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "get NAME",
		Short: "Get a session by name",
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
			session, err := apiClient.Sessions().Get(context.Background(), args[0])
			if err != nil {
				return err
			}
			format := output.Format(rt.OutputFormat())
			if format == output.FormatTable {
				output.WriteSessionTable(rt.Writer(), []breakglassv1alpha1.BreakglassSession{*session})
				return nil
			}
			return writeRuntimeObject(rt, session, output.FormatTable, output.FormatJSON, output.FormatYAML)
		},
	}
}

func newSessionRequestCommand() *cobra.Command {
	var (
		cluster   string
		group     string
		user      string
		reason    string
		duration  int64
		scheduled string
	)
	cmd := &cobra.Command{
		Use:   "request",
		Short: "Request a new breakglass session",
		Long: `Request a new breakglass session for a cluster and group.

The user defaults to the authenticated token identity when available. Provide a
reason when the escalation policy requires one.`,
		Example: `  bgctl session request -C prod -g platform-admin -r "debug incident INC-123"
  bgctl session request --cluster prod --group read-only --duration 3600
  bgctl session request -C prod -g platform-admin --scheduled-start <RFC3339_TIMESTAMP>`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			rt, err := getRuntime(cmd)
			if err != nil {
				return err
			}
			apiClient, err := buildClient(context.Background(), rt)
			if err != nil {
				return err
			}
			if user == "" {
				user = resolveUserFromToken(rt, cmd.Context())
			}
			if user == "" {
				return fmt.Errorf("user is required (use --user or login)")
			}
			req := client.SessionRequest{
				Cluster:          cluster,
				User:             user,
				Group:            group,
				Reason:           reason,
				DurationSeconds:  duration,
				ScheduledStartAt: scheduled,
			}
			session, err := apiClient.Sessions().Request(context.Background(), req)
			if err != nil {
				return err
			}
			format := output.Format(rt.OutputFormat())
			if format == output.FormatTable {
				output.WriteSessionTable(rt.Writer(), []breakglassv1alpha1.BreakglassSession{*session})
				return nil
			}
			return writeRuntimeObject(rt, session, output.FormatTable, output.FormatJSON, output.FormatYAML)
		},
	}
	cmd.Flags().StringVarP(&cluster, "cluster", "C", "", "Target cluster")
	cmd.Flags().StringVarP(&group, "group", "g", "", "Group to request")
	cmd.Flags().StringVarP(&user, "user", "u", "", "User identifier (defaults to token user)")
	cmd.Flags().StringVarP(&reason, "reason", "r", "", "Reason for request")
	cmd.Flags().Int64VarP(&duration, "duration", "d", 0, "Requested duration in seconds")
	cmd.Flags().StringVarP(&scheduled, "scheduled-start", "S", "", "Scheduled start time (RFC3339)")
	_ = cmd.MarkFlagRequired("cluster")
	_ = cmd.MarkFlagRequired("group")
	return cmd
}

func newSessionApproveCommand() *cobra.Command {
	var reason string
	cmd := &cobra.Command{
		Use:   "approve NAME",
		Short: "Approve a session",
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
			session, err := apiClient.Sessions().Approve(context.Background(), args[0], reason)
			if err != nil {
				return err
			}
			format := output.Format(rt.OutputFormat())
			if format == output.FormatTable {
				output.WriteSessionTable(rt.Writer(), []breakglassv1alpha1.BreakglassSession{*session})
				return nil
			}
			return writeRuntimeObject(rt, session, output.FormatTable, output.FormatJSON, output.FormatYAML)
		},
	}
	cmd.Flags().StringVarP(&reason, "reason", "r", "", "Approval reason")
	return cmd
}

func newSessionRejectCommand() *cobra.Command {
	var reason string
	cmd := &cobra.Command{
		Use:   "reject NAME",
		Short: "Reject a session",
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
			session, err := apiClient.Sessions().Reject(context.Background(), args[0], reason)
			if err != nil {
				return err
			}
			format := output.Format(rt.OutputFormat())
			if format == output.FormatTable {
				output.WriteSessionTable(rt.Writer(), []breakglassv1alpha1.BreakglassSession{*session})
				return nil
			}
			return writeRuntimeObject(rt, session, output.FormatTable, output.FormatJSON, output.FormatYAML)
		},
	}
	cmd.Flags().StringVarP(&reason, "reason", "r", "", "Rejection reason")
	return cmd
}

func newSessionWithdrawCommand() *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:   "withdraw NAME",
		Short: "Withdraw your pending session",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			rt, err := getRuntime(cmd)
			if err != nil {
				return err
			}
			if err := confirmAction(cmd, rt, "withdraw", args[0], yes); err != nil {
				return err
			}
			apiClient, err := buildClient(context.Background(), rt)
			if err != nil {
				return err
			}
			session, err := apiClient.Sessions().Withdraw(context.Background(), args[0])
			if err != nil {
				return err
			}
			format := output.Format(rt.OutputFormat())
			if format == output.FormatTable {
				output.WriteSessionTable(rt.Writer(), []breakglassv1alpha1.BreakglassSession{*session})
				return nil
			}
			return writeRuntimeObject(rt, session, output.FormatTable, output.FormatJSON, output.FormatYAML)
		},
	}
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "Confirm destruction")
	return cmd
}

func newSessionDropCommand() *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:   "drop NAME",
		Short: "Drop an approved session",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			rt, err := getRuntime(cmd)
			if err != nil {
				return err
			}
			if err := confirmAction(cmd, rt, "drop", args[0], yes); err != nil {
				return err
			}
			apiClient, err := buildClient(context.Background(), rt)
			if err != nil {
				return err
			}
			session, err := apiClient.Sessions().Drop(context.Background(), args[0])
			if err != nil {
				return err
			}
			format := output.Format(rt.OutputFormat())
			if format == output.FormatTable {
				output.WriteSessionTable(rt.Writer(), []breakglassv1alpha1.BreakglassSession{*session})
				return nil
			}
			return writeRuntimeObject(rt, session, output.FormatTable, output.FormatJSON, output.FormatYAML)
		},
	}
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "Confirm destruction")
	return cmd
}

func newSessionCancelCommand() *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:   "cancel NAME",
		Short: "Cancel a session as approver",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			rt, err := getRuntime(cmd)
			if err != nil {
				return err
			}
			if err := confirmAction(cmd, rt, "cancel", args[0], yes); err != nil {
				return err
			}
			apiClient, err := buildClient(context.Background(), rt)
			if err != nil {
				return err
			}
			session, err := apiClient.Sessions().Cancel(context.Background(), args[0])
			if err != nil {
				return err
			}
			format := output.Format(rt.OutputFormat())
			if format == output.FormatTable {
				output.WriteSessionTable(rt.Writer(), []breakglassv1alpha1.BreakglassSession{*session})
				return nil
			}
			return writeRuntimeObject(rt, session, output.FormatTable, output.FormatJSON, output.FormatYAML)
		},
	}
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "Confirm destruction")
	return cmd
}
