// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/telekom/k8s-breakglass/pkg/bgctl/client"
	"github.com/telekom/k8s-breakglass/pkg/bgctl/internal/terminal"
	"github.com/telekom/k8s-breakglass/pkg/bgctl/output"
	"github.com/telekom/k8s-breakglass/pkg/bgctl/recording"
)

func newDebugTerminalCommand() *cobra.Command {
	var namespace, pod, container string
	cmd := &cobra.Command{
		Use:   "terminal SESSION --pod NAMESPACE/NAME [--container NAME] [-- COMMAND...]",
		Short: "Open a recorded terminal in a debug session pod",
		Long: `Open an interactive terminal through the controller for a debug session whose
template requires terminal recording. Every byte typed and printed, terminal
resizes and their timing are recorded; direct kubectl exec is denied for such
sessions. The command defaults to "sh".`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			podNamespace, podName, ok := strings.Cut(pod, "/")
			if !ok || podNamespace == "" || podName == "" {
				return errors.New("--pod must be NAMESPACE/NAME")
			}
			command := args[1:]
			if dash := cmd.ArgsLenAtDash(); dash >= 0 {
				if dash != 1 {
					return errors.New("exactly one SESSION is allowed before --")
				}
			} else if len(args) > 1 {
				return errors.New("pass the command after --")
			}
			if len(command) == 0 {
				command = []string{"sh"}
			}
			rt, err := getRuntime(cmd)
			if err != nil {
				return err
			}
			apiClient, err := buildClient(cmd.Context(), rt)
			if err != nil {
				return err
			}
			ctx, cancel := context.WithCancel(cmd.Context())
			defer cancel()
			stdin, stdout, stderr := cmd.InOrStdin(), rt.Writer(), cmd.ErrOrStderr()
			resize := make(chan client.TerminalSize, 4)
			if file, isFile := stdin.(*os.File); isFile && term.IsTerminal(int(file.Fd())) {
				fd := int(file.Fd())
				state, err := term.MakeRaw(fd)
				if err != nil {
					return fmt.Errorf("enable raw terminal: %w", err)
				}
				defer func() { _ = term.Restore(fd, state) }()
				sendSize := func() {
					if width, height, err := term.GetSize(fd); err == nil && width > 0 && height > 0 {
						select {
						case resize <- client.TerminalSize{Width: uint16(width), Height: uint16(height)}: // #nosec G115 -- terminal sizes fit uint16
						default:
						}
					}
				}
				sendSize()
				stop := watchTerminalResize(sendSize)
				defer stop()
			}
			result, err := apiClient.Terminal(ctx, client.TerminalRequest{
				Session: args[0], Namespace: namespace, PodNamespace: podNamespace, PodName: podName,
				Container: container, Command: command, Stdin: stdin, Stdout: stdout, Resize: resize,
			})
			if err != nil {
				return err
			}
			// Raw mode needs explicit carriage returns.
			_, _ = fmt.Fprintf(stderr, "\r\nrecording %s: %s (sha256 %s)\r\n", terminal.SafeText(result.RecordingID), terminal.SafeText(result.Status), terminal.SafeText(result.SHA256))
			if result.Status != "completed" {
				return fmt.Errorf("terminal recording %s is %s", terminal.SafeText(result.RecordingID), terminal.SafeText(result.Status))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&namespace, "namespace", "", "Debug session namespace hint")
	cmd.Flags().StringVar(&pod, "pod", "", "Target pod as NAMESPACE/NAME (must be allowed by the session)")
	cmd.Flags().StringVar(&container, "container", "", "Target container")
	_ = cmd.MarkFlagRequired("pod")
	return cmd
}

// watchTerminalResize calls onResize for every SIGWINCH until the returned
// stop function runs. stop does not depend on any context, so deferred
// cleanup (and the raw-mode restore after it) can never block.
func watchTerminalResize(onResize func()) func() {
	signals := make(chan os.Signal, 1)
	notifyResize(signals)
	quit, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-signals:
				onResize()
			case <-quit:
				return
			}
		}
	}()
	return func() {
		signal.Stop(signals)
		close(quit)
		<-done
	}
}

func newDebugRecordingsCommand() *cobra.Command {
	cmd := newHelpOnlyGroupCommand("recordings", "List, download, verify and export terminal recordings")
	cmd.AddCommand(newRecordingsListCommand(), newRecordingsGetCommand(), newRecordingsVerifyCommand(), newRecordingsExportCommand())
	return cmd
}

func newRecordingsListCommand() *cobra.Command {
	var namespace string
	cmd := &cobra.Command{
		Use:   "list SESSION",
		Short: "List retained terminal recordings of a debug session",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			rt, apiClient, err := runtimeClient(cmd)
			if err != nil {
				return err
			}
			list, err := apiClient.DebugSessions().Recordings(cmd.Context(), args[0], namespace)
			if err != nil {
				return err
			}
			format := output.Format(rt.OutputFormat())
			if format == output.FormatJSON || format == output.FormatYAML {
				return writeRuntimeObject(rt, list, output.FormatJSON, output.FormatYAML, output.FormatTable)
			}
			w := rt.Writer()
			_, _ = fmt.Fprintln(w, "ID\tSTATE\tPOD\tCOMPLETE\tFRAMES\tSIZE\tEXPIRES")
			for _, item := range list {
				pod, complete, frames := "", false, int64(0)
				if item.Recording != nil {
					pod, complete, frames = item.Recording.PodNamespace+"/"+item.Recording.PodName, item.Recording.Complete, item.Recording.Frames
				}
				_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%t\t%d\t%d\t%s\n", terminal.SafeText(item.ArtifactID), terminal.SafeText(item.State), terminal.SafeText(pod), complete, frames, item.Size, item.ExpiresAt.Format(time.RFC3339))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&namespace, "namespace", "", "Debug session namespace hint")
	return cmd
}

func newRecordingsGetCommand() *cobra.Command {
	var namespace, file string
	cmd := &cobra.Command{
		Use:   "get SESSION ID",
		Short: "Download and verify a raw terminal recording",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			rt, apiClient, err := runtimeClient(cmd)
			if err != nil {
				return err
			}
			data, rec, err := downloadVerifiedRecording(cmd.Context(), apiClient, args[0], namespace, args[1])
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "verified %d frames, sha256 %s\n", len(rec.Frames), rec.SHA256)
			return writeRecordingOutput(rt, file, data)
		},
	}
	cmd.Flags().StringVar(&namespace, "namespace", "", "Debug session namespace hint")
	cmd.Flags().StringVarP(&file, "file", "f", "", "Write to this file instead of stdout")
	return cmd
}

func newRecordingsVerifyCommand() *cobra.Command {
	var namespace string
	cmd := &cobra.Command{
		Use:   "verify SESSION ID",
		Short: "Verify a recording's digest, hash chain and timing",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			rt, apiClient, err := runtimeClient(cmd)
			if err != nil {
				return err
			}
			_, rec, err := downloadVerifiedRecording(cmd.Context(), apiClient, args[0], namespace, args[1])
			if err != nil {
				return err
			}
			var duration time.Duration
			if n := len(rec.Frames); n > 0 {
				duration = rec.Frames[n-1].Offset
			}
			_, err = fmt.Fprintf(rt.Writer(), "verified: %d frames, %d bytes, format v%d, duration %s, sha256 %s\n", len(rec.Frames), rec.Bytes, rec.Frames[0].Version, duration.Round(time.Millisecond), rec.SHA256)
			return err
		},
	}
	cmd.Flags().StringVar(&namespace, "namespace", "", "Debug session namespace hint")
	return cmd
}

func newRecordingsExportCommand() *cobra.Command {
	var namespace, file, format string
	var includeInput bool
	cmd := &cobra.Command{
		Use:   "export SESSION ID",
		Short: "Export a verified recording as asciicast v2 (asciinema play) or raw frames",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if format != "asciicast-v2" && format != "raw" {
				return fmt.Errorf("unsupported format %q (asciicast-v2, raw)", format)
			}
			rt, apiClient, err := runtimeClient(cmd)
			if err != nil {
				return err
			}
			data, rec, err := downloadVerifiedRecording(cmd.Context(), apiClient, args[0], namespace, args[1])
			if err != nil {
				return err
			}
			if format == "asciicast-v2" {
				var buf bytes.Buffer
				if err := rec.WriteAsciicast(&buf, recording.AsciicastOptions{IncludeInput: includeInput}); err != nil {
					return err
				}
				data = buf.Bytes()
			}
			return writeRecordingOutput(rt, file, data)
		},
	}
	cmd.Flags().StringVar(&namespace, "namespace", "", "Debug session namespace hint")
	cmd.Flags().StringVarP(&file, "file", "f", "", "Write to this file instead of stdout")
	cmd.Flags().StringVar(&format, "format", "asciicast-v2", "Export format: asciicast-v2 or raw")
	cmd.Flags().BoolVar(&includeInput, "include-input", false, "Include typed input as asciicast \"i\" events")
	return cmd
}

func runtimeClient(cmd *cobra.Command) (*runtimeState, *client.Client, error) {
	rt, err := getRuntime(cmd)
	if err != nil {
		return nil, nil, err
	}
	apiClient, err := buildClient(cmd.Context(), rt)
	return rt, apiClient, err
}

// downloadVerifiedRecording fails unless the hash chain verifies and the
// artifact digest equals the digest the server published.
func downloadVerifiedRecording(ctx context.Context, apiClient *client.Client, session, namespace, id string) ([]byte, *recording.Recording, error) {
	var buf bytes.Buffer
	published, err := apiClient.DebugSessions().DownloadRecording(ctx, session, namespace, id, &buf)
	if err != nil {
		return nil, nil, err
	}
	rec, err := recording.Parse(bytes.NewReader(buf.Bytes()))
	if err != nil {
		return nil, nil, fmt.Errorf("recording %s failed verification: %w", terminal.SafeText(id), err)
	}
	if !strings.EqualFold(rec.SHA256, published) {
		return nil, nil, fmt.Errorf("recording %s digest %s does not match published %s", terminal.SafeText(id), rec.SHA256, terminal.SafeText(published))
	}
	return buf.Bytes(), rec, nil
}

func writeRecordingOutput(rt *runtimeState, file string, data []byte) error {
	if file == "" {
		_, err := io.Copy(rt.Writer(), bytes.NewReader(data))
		return err
	}
	// Recordings can contain secrets typed into the terminal: owner-only, no overwrite.
	f, err := os.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create %s: %w", file, err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("write %s: %w", file, err)
	}
	return f.Close()
}
