package cmd

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/bgctl/client"
	"github.com/telekom/k8s-breakglass/pkg/bgctl/output"
)

func NewSessionCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "session",
		Short: "Manage breakglass sessions",
	}

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
		RunE: func(cmd *cobra.Command, _ []string) error {
			rt, err := getRuntime(cmd)
			if err != nil {
				return err
			}
			apiClient, err := buildClient(context.Background(), rt)
			if err != nil {
				return err
			}
			seen := map[string]string{}
			for {
				opts := client.SessionListOptions{
					Cluster:    cluster,
					User:       user,
					Group:      group,
					Mine:       mine,
					Approver:   approver,
					ActiveOnly: activeOnly,
				}
				if state != "" {
					opts.State = strings.Split(state, ",")
				}
				sessions, err := apiClient.Sessions().List(context.Background(), opts)
				if err != nil {
					return err
				}
				for _, s := range sessions {
					key := s.Name
					value := string(s.Status.State)
					if prev, ok := seen[key]; !ok || prev != value {
						seen[key] = value
						if showFull {
							_ = output.WriteObject(rt.Writer(), output.FormatJSON, s)
						} else {
							_, _ = fmt.Fprintf(rt.Writer(), "%s\t%s\t%s\t%s\n", s.Name, s.Spec.Cluster, s.Spec.User, s.Status.State)
						}
					}
				}
				time.Sleep(interval)
			}
		},
	}
	cmd.Flags().DurationVar(&interval, "interval", 2*time.Second, "Polling interval")
	cmd.Flags().StringVar(&cluster, "cluster", "", "Filter by cluster")
	cmd.Flags().StringVar(&user, "user", "", "Filter by user")
	cmd.Flags().StringVar(&group, "group", "", "Filter by group")
	cmd.Flags().StringVar(&state, "state", "", "Filter by state (comma-separated)")
	cmd.Flags().BoolVar(&mine, "mine", false, "Only show sessions created by the current user")
	cmd.Flags().BoolVar(&approver, "approver", true, "Include sessions where you are an approver")
	cmd.Flags().BoolVar(&activeOnly, "active", false, "Only show active sessions")
	cmd.Flags().BoolVar(&showFull, "show-full", false, "Show full session JSON on change")
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
				Approver:     approver,
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
				return fmt.Errorf("unknown output format: %s", format)
			}
		},
	}
	cmd.Flags().BoolVar(&mine, "mine", false, "Only show sessions created by the current user")
	cmd.Flags().BoolVar(&approver, "approver", true, "Include sessions where you are an approver")
	cmd.Flags().BoolVar(&approvedByMe, "approved-by-me", false, "Only show sessions approved by you")
	cmd.Flags().BoolVar(&activeOnly, "active", false, "Only show active sessions")
	cmd.Flags().StringVar(&cluster, "cluster", "", "Filter by cluster name")
	cmd.Flags().StringVar(&user, "user", "", "Filter by user")
	cmd.Flags().StringVar(&group, "group", "", "Filter by group")
	cmd.Flags().StringVar(&state, "state", "", "Filter by state (comma-separated)")
	cmd.Flags().IntVar(&page, "page", 1, "Page number")
	cmd.Flags().IntVar(&pageSize, "page-size", 0, "Items per page")
	cmd.Flags().BoolVar(&allPages, "all", false, "Disable pagination")
	return cmd
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
				output.WriteSessionTable(rt.Writer(), []v1alpha1.BreakglassSession{*session})
				return nil
			}
			return output.WriteObject(rt.Writer(), format, session)
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
				output.WriteSessionTable(rt.Writer(), []v1alpha1.BreakglassSession{*session})
				return nil
			}
			return output.WriteObject(rt.Writer(), format, session)
		},
	}
	cmd.Flags().StringVar(&cluster, "cluster", "", "Target cluster")
	cmd.Flags().StringVar(&group, "group", "", "Group to request")
	cmd.Flags().StringVar(&user, "user", "", "User identifier (defaults to token user)")
	cmd.Flags().StringVar(&reason, "reason", "", "Reason for request")
	cmd.Flags().Int64Var(&duration, "duration", 0, "Requested duration in seconds")
	cmd.Flags().StringVar(&scheduled, "scheduled-start", "", "Scheduled start time (RFC3339)")
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
				output.WriteSessionTable(rt.Writer(), []v1alpha1.BreakglassSession{*session})
				return nil
			}
			return output.WriteObject(rt.Writer(), format, session)
		},
	}
	cmd.Flags().StringVar(&reason, "reason", "", "Approval reason")
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
				output.WriteSessionTable(rt.Writer(), []v1alpha1.BreakglassSession{*session})
				return nil
			}
			return output.WriteObject(rt.Writer(), format, session)
		},
	}
	cmd.Flags().StringVar(&reason, "reason", "", "Rejection reason")
	return cmd
}

func newSessionWithdrawCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "withdraw NAME",
		Short: "Withdraw your pending session",
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
			session, err := apiClient.Sessions().Withdraw(context.Background(), args[0])
			if err != nil {
				return err
			}
			format := output.Format(rt.OutputFormat())
			if format == output.FormatTable {
				output.WriteSessionTable(rt.Writer(), []v1alpha1.BreakglassSession{*session})
				return nil
			}
			return output.WriteObject(rt.Writer(), format, session)
		},
	}
}

func newSessionDropCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "drop NAME",
		Short: "Drop an approved session",
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
			session, err := apiClient.Sessions().Drop(context.Background(), args[0])
			if err != nil {
				return err
			}
			format := output.Format(rt.OutputFormat())
			if format == output.FormatTable {
				output.WriteSessionTable(rt.Writer(), []v1alpha1.BreakglassSession{*session})
				return nil
			}
			return output.WriteObject(rt.Writer(), format, session)
		},
	}
}

func newSessionCancelCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "cancel NAME",
		Short: "Cancel a session as approver",
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
			session, err := apiClient.Sessions().Cancel(context.Background(), args[0])
			if err != nil {
				return err
			}
			format := output.Format(rt.OutputFormat())
			if format == output.FormatTable {
				output.WriteSessionTable(rt.Writer(), []v1alpha1.BreakglassSession{*session})
				return nil
			}
			return output.WriteObject(rt.Writer(), format, session)
		},
	}
}
