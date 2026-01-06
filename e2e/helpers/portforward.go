/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package helpers

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"
)

// StartPortForward starts a port-forward to a service and returns the local port and a stop function.
// If localPortRequest is 0, a random free port is chosen.
func StartPortForward(t *testing.T, ctx context.Context, namespace, service string, remotePort int, localPortRequest int) (int, func()) {
	var localPort int
	if localPortRequest == 0 {
		// Find a free local port
		l, err := net.Listen("tcp", "localhost:0")
		if err != nil {
			t.Fatalf("Failed to find free port: %v", err)
		}
		localPort = l.Addr().(*net.TCPAddr).Port
		_ = l.Close()
	} else {
		localPort = localPortRequest
	}

	// Construct kubectl command
	cmd := exec.CommandContext(ctx, "kubectl", "-n", namespace, "port-forward", fmt.Sprintf("svc/%s", service), fmt.Sprintf("%d:%d", localPort, remotePort))

	// Use the kubeconfig from env if available, otherwise use the one from GetKubeconfig
	if os.Getenv("KUBECONFIG") == "" {
		if kubeconfig := GetKubeconfig(); kubeconfig != "" {
			cmd.Env = append(os.Environ(), fmt.Sprintf("KUBECONFIG=%s", kubeconfig))
		}
	}

	if err := cmd.Start(); err != nil {
		t.Fatalf("Failed to start port-forward: %v", err)
	}

	// Wait for port-forward to be ready
	if err := waitForPort(localPort, 10*time.Second); err != nil {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		t.Fatalf("Port-forward failed to become ready: %v", err)
	}

	return localPort, func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	}
}

func waitForPort(port int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("localhost:%d", port), 1*time.Second)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for port %d", port)
}
