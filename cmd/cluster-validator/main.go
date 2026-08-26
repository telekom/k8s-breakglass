// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

// Command cluster-validator runs provider-neutral Kubernetes readiness checks
// and writes the stable ClusterValidationReport contract.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/telekom/k8s-breakglass/pkg/clustervalidator"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const defaultReportDirectory = "/reports"

var (
	version   = "dev"
	gitCommit = "unknown"
	buildDate = "unknown"
)

type options struct {
	mode             string
	reportPath       string
	kubeconfig       string
	contextName      string
	timeout          time.Duration
	includeTimestamp bool
	skipPods         bool
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	opts, err := parseOptions(args)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "cluster-validator:", err)
		return 2
	}

	ctx, cancel := context.WithTimeout(context.Background(), opts.timeout)
	defer cancel()
	config, err := clientConfig(opts)
	if err != nil {
		report := failureReport(opts.mode, "configuration", "could not load Kubernetes client configuration", opts.includeTimestamp)
		return writeResult(report, opts.reportPath, stdout, stderr, 2)
	}
	config.Timeout = opts.timeout
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		report := failureReport(opts.mode, "configuration", "could not create Kubernetes client", opts.includeTimestamp)
		return writeResult(report, opts.reportPath, stdout, stderr, 2)
	}
	discoveryClient, err := discovery.NewDiscoveryClientForConfig(config)
	if err != nil {
		report := failureReport(opts.mode, "configuration", "could not create Kubernetes discovery client", opts.includeTimestamp)
		return writeResult(report, opts.reportPath, stdout, stderr, 2)
	}

	report := clustervalidator.NewValidator(clustervalidator.BuiltinChecks(opts.skipPods)...).Validate(ctx, client, discoveryClient, opts.mode, opts.includeTimestamp)
	if err := writeReport(report, opts.reportPath); err != nil {
		_, _ = fmt.Fprintln(stderr, "cluster-validator:", err)
		return 2
	}
	data, err := clustervalidator.MarshalReport(report)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "cluster-validator:", err)
		return 2
	}
	if _, err := stdout.Write(data); err != nil {
		_, _ = fmt.Fprintln(stderr, "cluster-validator: write report to stdout:", err)
		return 2
	}
	if report.Status != clustervalidator.StatusReady {
		return 1
	}
	return 0
}

func parseOptions(args []string) (options, error) {
	mode := envOr("VALIDATOR_MODE", clustervalidator.ModeOneTime)
	reportPath := os.Getenv("VALIDATOR_REPORT_PATH")
	reportPathProvided := reportPath != ""
	if reportPath == "" {
		reportPath = filepath.Join(defaultReportDirectory, mode+".json")
	}
	timeout := 60 * time.Second
	timeoutValue := timeout.String()
	if value := os.Getenv("VALIDATOR_TIMEOUT"); value != "" {
		timeoutValue = value
	}

	fs := flag.NewFlagSet("cluster-validator", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.StringVar(&mode, "mode", mode, "report mode: one-time or post-upgrade")
	fs.StringVar(&reportPath, "report", reportPath, "path for the JSON report; use '-' to disable the file")
	fs.StringVar(&timeoutValue, "timeout", timeoutValue, "overall Kubernetes API timeout")
	var kubeconfig, contextName string
	fs.StringVar(&kubeconfig, "kubeconfig", os.Getenv("VALIDATOR_KUBECONFIG"), "kubeconfig path (default: in-cluster, then ~/.kube/config)")
	fs.StringVar(&contextName, "context", os.Getenv("VALIDATOR_CONTEXT"), "kubeconfig context")
	includeTimestamp, err := envBool("VALIDATOR_INCLUDE_TIMESTAMP", false)
	if err != nil {
		return options{}, err
	}
	skipPods, err := envBool("VALIDATOR_SKIP_PODS", false)
	if err != nil {
		return options{}, err
	}
	fs.BoolVar(&includeTimestamp, "include-timestamp", includeTimestamp, "include a non-deterministic UTC generatedAt field")
	fs.BoolVar(&skipPods, "skip-pods", skipPods, "skip the cluster-wide pod readiness check")
	if err := fs.Parse(args); err != nil {
		return options{}, err
	}
	parsedTimeout, err := time.ParseDuration(timeoutValue)
	if err != nil {
		return options{}, fmt.Errorf("invalid --timeout %q: %w", timeoutValue, err)
	}
	timeout = parsedTimeout
	if timeout <= 0 {
		return options{}, errors.New("timeout must be positive")
	}
	if mode != clustervalidator.ModeOneTime && mode != clustervalidator.ModePostUpgrade {
		return options{}, fmt.Errorf("invalid mode %q: must be one-time or post-upgrade", mode)
	}
	reportFlagProvided := false
	fs.Visit(func(f *flag.Flag) {
		reportFlagProvided = reportFlagProvided || f.Name == "report"
	})
	if !reportPathProvided && !reportFlagProvided {
		// Derive the default after parsing --mode so post-upgrade runs never
		// overwrite a one-time report.
		reportPath = filepath.Join(defaultReportDirectory, mode+".json")
	}
	return options{mode: mode, reportPath: reportPath, kubeconfig: kubeconfig, contextName: contextName, timeout: timeout, includeTimestamp: includeTimestamp, skipPods: skipPods}, nil
}

func clientConfig(opts options) (*rest.Config, error) {
	if opts.kubeconfig == "" {
		if config, err := rest.InClusterConfig(); err == nil {
			config.UserAgent = buildUserAgent()
			return config, nil
		}
	}
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	if opts.kubeconfig != "" {
		loadingRules.ExplicitPath = opts.kubeconfig
	}
	overrides := &clientcmd.ConfigOverrides{CurrentContext: opts.contextName}
	config, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, overrides).ClientConfig()
	if err != nil {
		return nil, err
	}
	config.UserAgent = buildUserAgent()
	return config, nil
}

func buildUserAgent() string {
	return fmt.Sprintf("cluster-validator/%s (%s; %s)", version, gitCommit, buildDate)
}

func writeReport(report clustervalidator.Report, path string) error {
	if path == "-" || path == "" {
		return nil
	}
	return writeReportAtRoot(report, path, defaultReportDirectory)
}

func writeReportAtRoot(report clustervalidator.Report, path, root string) error {
	path, err := safeReportPath(path, root)
	if err != nil {
		return err
	}
	data, err := clustervalidator.MarshalReport(report)
	if err != nil {
		return err
	}
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".cluster-validator-report-*")
	if err != nil {
		return fmt.Errorf("create temporary report: %w", err)
	}
	temporaryName := temporary.Name()
	defer func() {
		_ = os.Remove(temporaryName) // best effort cleanup after a failed write
	}()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("protect temporary report: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write report: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary report: %w", err)
	}
	// safeReportPath rejects symlink destinations and confines directory to the
	// report volume. Rename does not follow a destination symlink, so replacing
	// an existing regular report is atomic and cannot write outside that volume.
	if err := os.Rename(temporaryName, path); err != nil { // #nosec G703 -- path is confined by safeReportPath
		return fmt.Errorf("install report %q: %w", path, err)
	}
	return nil
}

// safeReportPath resolves report output below root and rejects traversal or
// symlink escapes. The report path is supplied by a CLI flag/environment value,
// so it must not be allowed to select arbitrary files in the container.
func safeReportPath(path, root string) (string, error) {
	root, err := filepath.Abs(filepath.Clean(root))
	if err != nil {
		return "", fmt.Errorf("resolve report root: %w", err)
	}
	if info, statErr := os.Lstat(root); statErr == nil && info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("report root must not be a symlink")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return "", fmt.Errorf("create report directory: %w", err)
	}
	if !filepath.IsAbs(path) {
		path = filepath.Join(root, path)
	}
	path = filepath.Clean(path)
	rel, err := filepath.Rel(root, path)
	if err != nil || !filepath.IsLocal(rel) {
		return "", fmt.Errorf("report path must remain below %s", root)
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return "", fmt.Errorf("create report directory: %w", err)
	}
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", fmt.Errorf("resolve report root: %w", err)
	}
	resolvedDirectory, err := filepath.EvalSymlinks(directory)
	if err != nil {
		return "", fmt.Errorf("resolve report directory: %w", err)
	}
	resolvedRel, err := filepath.Rel(resolvedRoot, resolvedDirectory)
	if err != nil || !filepath.IsLocal(resolvedRel) {
		return "", fmt.Errorf("report directory must remain below %s", root)
	}
	if info, statErr := os.Lstat(path); statErr == nil && info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("report path must not be a symlink")
	}
	return path, nil
}

func writeResult(report clustervalidator.Report, path string, stdout, stderr io.Writer, exitCode int) int {
	if err := writeReport(report, path); err != nil {
		_, _ = fmt.Fprintln(stderr, "cluster-validator:", err)
		return 2
	}
	data, err := clustervalidator.MarshalReport(report)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "cluster-validator:", err)
		return 2
	}
	if _, err := stdout.Write(data); err != nil {
		return 2
	}
	return exitCode
}

func failureReport(mode, name, message string, includeTimestamp bool) clustervalidator.Report {
	return clustervalidator.NewValidator(failureCheck{name: name, message: message}).Validate(context.Background(), nil, nil, mode, includeTimestamp)
}

type failureCheck struct{ name, message string }

func (f failureCheck) Name() string { return f.name }
func (f failureCheck) Run(context.Context, clustervalidator.ReadOnlyClient, clustervalidator.ReadOnlyDiscovery) clustervalidator.CheckResult {
	return clustervalidator.CheckResult{Name: f.name, Status: clustervalidator.StatusNotReady, Message: f.message}
}

func envOr(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func envBool(name string, fallback bool) (bool, error) {
	value := strings.TrimSpace(strings.ToLower(os.Getenv(name)))
	if value == "" {
		return fallback, nil
	}
	switch value {
	case "1", "true", "yes":
		return true, nil
	case "0", "false", "no":
		return false, nil
	default:
		return false, fmt.Errorf("invalid %s %q: expected true/false", name, value)
	}
}
