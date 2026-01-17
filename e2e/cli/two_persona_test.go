// SPDX-FileCopyrightText: 2024 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	v1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
	bgctlcmd "github.com/telekom/k8s-breakglass/pkg/bgctl/cmd"
)

// TestTwoPersonaShellFlow runs the shell-based two persona test script.
// This is useful for running the test in CI/CD environments where the shell
// script provides more detailed output and logging.
func TestTwoPersonaShellFlow(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("E2E tests disabled. Set E2E_TEST=true")
	}

	// Check if we should run shell tests
	if os.Getenv("RUN_SHELL_TESTS") != "true" {
		t.Skip("Shell tests disabled. Set RUN_SHELL_TESTS=true to enable")
	}

	mcConfig := helpers.GetMultiClusterConfig()

	// Set up environment for the shell script
	env := os.Environ()
	env = append(env,
		"BREAKGLASS_API_URL="+mcConfig.HubAPIURL,
		"CLUSTER_NAME="+mcConfig.HubClusterName,
		"BGCTL_BIN="+getBgctlBinary(t),
	)

	// Add OIDC URL if configured
	if oidcURL := os.Getenv("OIDC_URL"); oidcURL != "" {
		env = append(env, "OIDC_URL="+oidcURL)
	}

	// Run the shell script
	cmd := exec.Command("./two_persona_flow_test.sh")
	cmd.Dir = "."
	cmd.Env = env

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()

	// Log output regardless of success/failure
	t.Logf("Shell test stdout:\n%s", stdout.String())
	if stderr.Len() > 0 {
		t.Logf("Shell test stderr:\n%s", stderr.String())
	}

	require.NoError(t, err, "Shell test script failed")
}

// TestTwoPersonaGoFlow is the Go-native version of the two persona test.
// This provides better integration with Go test tooling and IDE support.
func TestTwoPersonaGoFlow(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("E2E tests disabled. Set E2E_TEST=true")
	}

	ctx := context.Background()
	mcConfig := helpers.GetMultiClusterConfig()

	// Get tokens for both personas
	oidcProvider := helpers.DefaultOIDCProvider()

	requesterToken := oidcProvider.GetToken(t, ctx, helpers.TestUsers.Requester.Username, helpers.TestUsers.Requester.Password)
	approverToken := oidcProvider.GetToken(t, ctx, helpers.TestUsers.Approver.Username, helpers.TestUsers.Approver.Password)

	require.NotEmpty(t, requesterToken, "Failed to get requester OIDC token")
	require.NotEmpty(t, approverToken, "Failed to get approver OIDC token")

	serverURL := mcConfig.HubAPIURL
	if serverURL == "" {
		serverURL = os.Getenv("BREAKGLASS_API_URL")
	}
	require.NotEmpty(t, serverURL, "Hub API URL must be set")

	clusterName := mcConfig.HubClusterName
	if clusterName == "" {
		clusterName = os.Getenv("CLUSTER_NAME")
	}
	require.NotEmpty(t, clusterName, "Cluster name must be set")

	// Create CLI config
	cfg := createCLIConfig(t, serverURL)
	configPath := writeConfigFile(t, cfg)

	// Helper to run command as a specific persona
	runAs := func(token string, args ...string) (string, error) {
		buf := &bytes.Buffer{}
		root := bgctlcmd.NewRootCommand(bgctlcmd.Config{
			ConfigPath:   configPath,
			OutputWriter: buf,
		})
		allArgs := append([]string{"--token", token}, args...)
		root.SetArgs(allArgs)
		err := root.Execute()
		return buf.String(), err
	}

	runAsRequester := func(args ...string) (string, error) {
		return runAs(requesterToken, args...)
	}

	runAsApprover := func(args ...string) (string, error) {
		return runAs(approverToken, args...)
	}

	var sessionName string

	// Flow 1: Complete Approval Workflow
	t.Run("ApprovalWorkflow", func(t *testing.T) {
		// Step 1: Requester lists escalations
		t.Run("RequesterListsEscalations", func(t *testing.T) {
			output, err := runAsRequester("escalation", "list", "-o", "json")
			require.NoError(t, err, "Requester should list escalations")
			t.Logf("Escalations: %s", output)
		})

		// Step 2: Requester creates a session
		t.Run("RequesterCreatesSession", func(t *testing.T) {
			output, err := runAsRequester(
				"session", "request",
				"--cluster", clusterName,
				"--group", "breakglass-create-all",
				"--reason", "Two persona Go test - approval flow",
				"-o", "json",
			)
			require.NoError(t, err, "Requester should create session")

			var session v1alpha1.BreakglassSession
			err = json.Unmarshal([]byte(output), &session)
			require.NoError(t, err, "Should parse session")

			sessionName = session.Name
			require.NotEmpty(t, sessionName, "Session name should be set")
			t.Logf("Created session: %s", sessionName)
		})

		// Step 3: Wait for Pending state
		t.Run("WaitForPendingState", func(t *testing.T) {
			require.NotEmpty(t, sessionName, "Session must be created first")

			deadline := time.Now().Add(30 * time.Second)
			for time.Now().Before(deadline) {
				output, err := runAsRequester("session", "get", sessionName, "-o", "json")
				require.NoError(t, err)

				var session v1alpha1.BreakglassSession
				err = json.Unmarshal([]byte(output), &session)
				require.NoError(t, err)

				if session.Status.State == v1alpha1.SessionStatePending {
					t.Logf("Session %s is Pending", sessionName)
					return
				}
				time.Sleep(1 * time.Second)
			}
			t.Fatalf("Session did not reach Pending state")
		})

		// Step 4: Both personas can see the session
		t.Run("BothPersonasSeeSession", func(t *testing.T) {
			require.NotEmpty(t, sessionName, "Session must be created first")

			// Requester can see it
			output, err := runAsRequester("session", "get", sessionName, "-o", "json")
			require.NoError(t, err, "Requester should see their session")
			t.Logf("Requester view: %s", output)

			// Approver can see it
			output, err = runAsApprover("session", "get", sessionName, "-o", "json")
			require.NoError(t, err, "Approver should see the session")
			t.Logf("Approver view: %s", output)
		})

		// Step 5: Approver approves the session
		t.Run("ApproverApprovesSession", func(t *testing.T) {
			require.NotEmpty(t, sessionName, "Session must be created first")

			output, err := runAsApprover("session", "approve", sessionName)
			require.NoError(t, err, "Approver should approve session")
			t.Logf("Approval response: %s", output)
		})

		// Step 6: Wait for Approved state
		t.Run("WaitForApprovedState", func(t *testing.T) {
			require.NotEmpty(t, sessionName, "Session must be created first")

			deadline := time.Now().Add(30 * time.Second)
			for time.Now().Before(deadline) {
				output, err := runAsRequester("session", "get", sessionName, "-o", "json")
				require.NoError(t, err)

				var session v1alpha1.BreakglassSession
				err = json.Unmarshal([]byte(output), &session)
				require.NoError(t, err)

				if session.Status.State == v1alpha1.SessionStateApproved {
					t.Logf("Session %s is Approved", sessionName)
					assert.NotEmpty(t, session.Status.Approvers, "Approvers should be recorded")
					return
				}
				time.Sleep(1 * time.Second)
			}
			t.Fatalf("Session did not reach Approved state")
		})

		// Step 7: Verify session appears in filtered list
		t.Run("VerifyApprovedInFilteredList", func(t *testing.T) {
			require.NotEmpty(t, sessionName, "Session must be created first")

			output, err := runAsRequester(
				"session", "list",
				"--state", "approved",
				"--cluster", clusterName,
				"-o", "json",
			)
			require.NoError(t, err, "Should list approved sessions")

			var sessions []v1alpha1.BreakglassSession
			err = json.Unmarshal([]byte(output), &sessions)
			require.NoError(t, err)

			found := false
			for _, s := range sessions {
				if s.Name == sessionName {
					found = true
					break
				}
			}
			assert.True(t, found, "Session should appear in approved list")
		})
	})

	// Flow 2: Rejection Workflow
	t.Run("RejectionWorkflow", func(t *testing.T) {
		var rejectedSessionName string

		// Step 1: Requester creates another session
		t.Run("RequesterCreatesSession", func(t *testing.T) {
			output, err := runAsRequester(
				"session", "request",
				"--cluster", clusterName,
				"--group", "breakglass-create-all",
				"--reason", "Two persona Go test - rejection flow",
				"-o", "json",
			)
			require.NoError(t, err, "Requester should create session")

			var session v1alpha1.BreakglassSession
			err = json.Unmarshal([]byte(output), &session)
			require.NoError(t, err)

			rejectedSessionName = session.Name
			require.NotEmpty(t, rejectedSessionName)
			t.Logf("Created session for rejection: %s", rejectedSessionName)
		})

		// Step 2: Wait for Pending
		t.Run("WaitForPendingState", func(t *testing.T) {
			require.NotEmpty(t, rejectedSessionName)

			deadline := time.Now().Add(30 * time.Second)
			for time.Now().Before(deadline) {
				output, err := runAsRequester("session", "get", rejectedSessionName, "-o", "json")
				require.NoError(t, err)

				var session v1alpha1.BreakglassSession
				err = json.Unmarshal([]byte(output), &session)
				require.NoError(t, err)

				if session.Status.State == v1alpha1.SessionStatePending {
					return
				}
				time.Sleep(1 * time.Second)
			}
			t.Fatalf("Session did not reach Pending state")
		})

		// Step 3: Approver rejects with reason
		t.Run("ApproverRejectsSession", func(t *testing.T) {
			require.NotEmpty(t, rejectedSessionName)

			output, err := runAsApprover(
				"session", "reject", rejectedSessionName,
				"--reason", "Test rejection from two persona flow",
			)
			require.NoError(t, err, "Approver should reject session")
			t.Logf("Rejection response: %s", output)
		})

		// Step 4: Verify Rejected state
		t.Run("VerifyRejectedState", func(t *testing.T) {
			require.NotEmpty(t, rejectedSessionName)

			deadline := time.Now().Add(30 * time.Second)
			for time.Now().Before(deadline) {
				output, err := runAsRequester("session", "get", rejectedSessionName, "-o", "json")
				require.NoError(t, err)

				var session v1alpha1.BreakglassSession
				err = json.Unmarshal([]byte(output), &session)
				require.NoError(t, err)

				if session.Status.State == v1alpha1.SessionStateRejected {
					t.Logf("Session %s is Rejected", rejectedSessionName)
					return
				}
				time.Sleep(1 * time.Second)
			}
			t.Fatalf("Session did not reach Rejected state")
		})

		// Step 5: Verify session appears in rejected filter
		t.Run("VerifyRejectedInFilteredList", func(t *testing.T) {
			require.NotEmpty(t, rejectedSessionName)

			output, err := runAsRequester(
				"session", "list",
				"--state", "rejected",
				"-o", "json",
			)
			require.NoError(t, err)

			var sessions []v1alpha1.BreakglassSession
			err = json.Unmarshal([]byte(output), &sessions)
			require.NoError(t, err)

			found := false
			for _, s := range sessions {
				if s.Name == rejectedSessionName {
					found = true
					break
				}
			}
			assert.True(t, found, "Session should appear in rejected list")
		})
	})

	// Flow 3: Cross-persona visibility
	t.Run("CrossPersonaVisibility", func(t *testing.T) {
		// Requester lists their sessions
		t.Run("RequesterListsMine", func(t *testing.T) {
			output, err := runAsRequester("session", "list", "--mine", "-o", "json")
			require.NoError(t, err, "Requester should list their sessions")

			var sessions []v1alpha1.BreakglassSession
			err = json.Unmarshal([]byte(output), &sessions)
			require.NoError(t, err)
			t.Logf("Requester has %d sessions", len(sessions))
		})

		// Approver lists all sessions
		t.Run("ApproverListsAll", func(t *testing.T) {
			output, err := runAsApprover("session", "list", "-o", "json")
			require.NoError(t, err, "Approver should list all sessions")

			var sessions []v1alpha1.BreakglassSession
			err = json.Unmarshal([]byte(output), &sessions)
			require.NoError(t, err)
			t.Logf("Approver sees %d sessions", len(sessions))
		})

		// Both can list escalations (clusters are derived from escalations)
		t.Run("BothListEscalations", func(t *testing.T) {
			output1, err := runAsRequester("escalation", "list", "-o", "json")
			require.NoError(t, err)

			output2, err := runAsApprover("escalation", "list", "-o", "json")
			require.NoError(t, err)

			// Both should see the same escalations
			var escalations1, escalations2 []v1alpha1.BreakglassEscalation
			_ = json.Unmarshal([]byte(output1), &escalations1)
			_ = json.Unmarshal([]byte(output2), &escalations2)

			assert.Equal(t, len(escalations1), len(escalations2), "Both personas should see same escalations")
		})
	})

	t.Logf("✅ Two persona Go flow test completed successfully")
}

// getBgctlBinary returns the path to the bgctl binary
func getBgctlBinary(t *testing.T) string {
	// Check common locations
	locations := []string{
		"../../bin/bgctl",
		"./bin/bgctl",
		os.Getenv("BGCTL_BIN"),
	}

	for _, loc := range locations {
		if loc == "" {
			continue
		}
		if _, err := os.Stat(loc); err == nil {
			return loc
		}
	}

	// Try to find in PATH
	path, err := exec.LookPath("bgctl")
	if err == nil {
		return path
	}

	t.Skip("bgctl binary not found")
	return ""
}
