// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

// Command cluster-validator-extension is an integration-only contract probe.
// It proves that a downstream Check can run against the same restricted
// client/discovery facades as the built-in checks. It is not included in the
// public validator image.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/telekom/k8s-breakglass/pkg/clustervalidator"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

const extensionName = "integration-extension"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("cluster-validator-extension", flag.ContinueOnError)
	fs.SetOutput(stderr)
	kubeconfig := fs.String("kubeconfig", "", "kubeconfig path")
	mode := fs.String("mode", clustervalidator.ModeOneTime, "report mode")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *kubeconfig == "" || (*mode != clustervalidator.ModeOneTime && *mode != clustervalidator.ModePostUpgrade) {
		fmt.Fprintln(stderr, "cluster-validator-extension: kubeconfig and a supported mode are required")
		return 2
	}
	config, err := clientcmd.BuildConfigFromFlags("", *kubeconfig)
	if err != nil {
		fmt.Fprintln(stderr, "cluster-validator-extension: could not load kubeconfig")
		return 2
	}
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		fmt.Fprintln(stderr, "cluster-validator-extension: could not create Kubernetes client")
		return 2
	}
	discoveryClient, err := discovery.NewDiscoveryClientForConfig(config)
	if err != nil {
		fmt.Fprintln(stderr, "cluster-validator-extension: could not create discovery client")
		return 2
	}

	checks := append(clustervalidator.BuiltinChecks(false), extensionCheck{})
	report := clustervalidator.NewValidator(checks...).Validate(context.Background(), client, discoveryClient, *mode, false)
	data, err := clustervalidator.MarshalReport(report)
	if err != nil {
		fmt.Fprintln(stderr, "cluster-validator-extension: could not marshal report")
		return 2
	}
	if _, err := stdout.Write(data); err != nil {
		return 2
	}
	if report.Status != clustervalidator.StatusReady {
		return 1
	}
	return 0
}

type extensionCheck struct{}

func (extensionCheck) Name() string { return extensionName }

func (extensionCheck) Run(ctx context.Context, client clustervalidator.ReadOnlyClient, discoveryClient clustervalidator.ReadOnlyDiscovery) clustervalidator.CheckResult {
	if _, err := client.ListNamespaces(ctx, metav1.ListOptions{Limit: 1}); err != nil {
		return clustervalidator.CheckResult{Name: extensionName, Status: clustervalidator.StatusNotReady, Message: "extension could not list namespaces"}
	}
	if _, err := discoveryClient.ServerGroups(); err != nil {
		return clustervalidator.CheckResult{Name: extensionName, Status: clustervalidator.StatusNotReady, Message: "extension could not discover API groups"}
	}
	return clustervalidator.CheckResult{Name: extensionName, Status: clustervalidator.StatusReady, Message: "extension read-only contract succeeded"}
}
