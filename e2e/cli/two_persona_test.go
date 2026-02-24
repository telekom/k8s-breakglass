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

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
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

	// Construct OIDC URL from KEYCLOAK_HOST and KEYCLOAK_REALM if not already set
	oidcURL := os.Getenv("OIDC_URL")
	if oidcURL == "" {
		keycloakHost := os.Getenv("KEYCLOAK_HOST")
		keycloakRealm := os.Getenv("KEYCLOAK_REALM")
		if keycloakHost != "" && keycloakRealm != "" {
			oidcURL = keycloakHost + "/realms/" + keycloakRealm
		}
	}
	if oidcURL != "" {
		env = append(env, "OIDC_URL="+oidcURL)
	}

	// Pass KEYCLOAK_ISSUER_HOST so the shell script can set the Host header
	// This makes Keycloak issue tokens with the correct issuer claim
	keycloakIssuerHost := os.Getenv("KEYCLOAK_ISSUER_HOST")
	if keycloakIssuerHost != "" {
		env = append(env, "KEYCLOAK_ISSUER_HOST="+keycloakIssuerHost)
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

	// Delay to allow the API server to settle after shell test's cleanup.
	// The shell test creates sessions with ~9 approvers, generating many notification
	// emails that queue up. This gives the mail queue time to drain and prevents
	// transient timeouts when the server is under load.
	time.Sleep(5 * time.Second)

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

	// Helper to drop any existing approved sessions for the given group/cluster.
	// This is necessary because Breakglass only allows one approved session per user/group/cluster.
	dropExistingApprovedSessions := func(t *testing.T, group, cluster string) {
		t.Helper()

		// Use --mine flag to list sessions owned by the requester user
		// Without --mine, the API defaults to approver view which won't show requester's sessions
		output, err := runAsRequester("session", "list", "--mine", "-o", "json")
		if err != nil {
			t.Logf("Warning: Failed to list sessions for cleanup: %v", err)
			return
		}

		var sessions []breakglassv1alpha1.BreakglassSession
		if err := json.Unmarshal([]byte(output), &sessions); err != nil {
			t.Logf("Warning: Failed to parse sessions for cleanup: %v", err)
			return
		}

		t.Logf("Cleanup: Found %d sessions, looking for group=%s cluster=%s", len(sessions), group, cluster)
		for _, s := range sessions {
			t.Logf("  Session: %s state=%s group=%s cluster=%s user=%s",
				s.Name, s.Status.State, s.Spec.GrantedGroup, s.Spec.Cluster, s.Spec.User)

			// Only match on group and cluster - let the user be whatever the requester's identity is
			if s.Spec.GrantedGroup == group && s.Spec.Cluster == cluster {
				switch s.Status.State {
				case breakglassv1alpha1.SessionStateApproved:
					t.Logf("Dropping existing approved session: %s", s.Name)
					if _, err := runAsRequester("session", "drop", s.Name); err != nil {
						t.Logf("Warning: Failed to drop session %s: %v", s.Name, err)
					}
				case breakglassv1alpha1.SessionStatePending:
					t.Logf("Withdrawing existing pending session: %s", s.Name)
					if _, err := runAsRequester("session", "withdraw", s.Name); err != nil {
						t.Logf("Warning: Failed to withdraw session %s: %v", s.Name, err)
					}
				default:
					t.Logf("Skipping session %s in state %s", s.Name, s.Status.State)
				}
			}
		}
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
			// Drop any existing approved sessions for this group/cluster first
			dropExistingApprovedSessions(t, "breakglass-create-all", clusterName)

			// Retry session creation with backoff to handle transient timeouts
			var output string
			var err error
			for attempt := 1; attempt <= 3; attempt++ {
				output, err = runAsRequester(
					"session", "request",
					"--cluster", clusterName,
					"--group", "breakglass-create-all",
					"--reason", "Two persona Go test - approval flow",
					"-o", "json",
				)
				if err == nil {
					break
				}
				t.Logf("Session creation attempt %d failed: %v", attempt, err)
				if attempt < 3 {
					time.Sleep(time.Duration(attempt*2) * time.Second)
				}
			}
			require.NoError(t, err, "Requester should create session")

			var session breakglassv1alpha1.BreakglassSession
			err = json.Unmarshal([]byte(output), &session)
			require.NoError(t, err, "Should parse session")

			sessionName = session.Name
			require.NotEmpty(t, sessionName, "Session name should be set")
			t.Logf("Created session: %s", sessionName)
		})

		// Step 3: Wait for Pending state
		t.Run("WaitForPendingState", func(t *testing.T) {
			require.NotEmpty(t, sessionName, "Session must be created first")

			deadline := time.Now().Add(helpers.WaitForStateTimeout)
			for time.Now().Before(deadline) {
				output, err := runAsRequester("session", "get", sessionName, "-o", "json")
				require.NoError(t, err)

				var session breakglassv1alpha1.BreakglassSession
				err = json.Unmarshal([]byte(output), &session)
				require.NoError(t, err)

				if session.Status.State == breakglassv1alpha1.SessionStatePending {
					t.Logf("Session %s is Pending", sessionName)
					return
				}
				time.Sleep(helpers.PollInterval)
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

			deadline := time.Now().Add(helpers.WaitForStateTimeout)
			for time.Now().Before(deadline) {
				output, err := runAsRequester("session", "get", sessionName, "-o", "json")
				require.NoError(t, err)

				var session breakglassv1alpha1.BreakglassSession
				err = json.Unmarshal([]byte(output), &session)
				require.NoError(t, err)

				if session.Status.State == breakglassv1alpha1.SessionStateApproved {
					t.Logf("Session %s is Approved", sessionName)
					assert.NotEmpty(t, session.Status.Approvers, "Approvers should be recorded")
					return
				}
				time.Sleep(helpers.PollInterval)
			}
			t.Fatalf("Session did not reach Approved state")
		})

		// Step 7: Verify session appears in filtered list
		t.Run("VerifyApprovedInFilteredList", func(t *testing.T) {
			require.NotEmpty(t, sessionName, "Session must be created first")

			// Include --mine to see own sessions (--approver defaults to true which
			// only shows sessions user can approve, not their own sessions)
			output, err := runAsRequester(
				"session", "list",
				"--state", "approved",
				"--cluster", clusterName,
				"--mine",
				"-o", "json",
			)
			require.NoError(t, err, "Should list approved sessions")

			var sessions []breakglassv1alpha1.BreakglassSession
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

		// Step 8: Drop the approved session to allow subsequent tests
		t.Run("DropApprovedSession", func(t *testing.T) {
			require.NotEmpty(t, sessionName, "Session must be created first")

			output, err := runAsRequester("session", "drop", sessionName)
			if err != nil {
				t.Logf("Drop session result (may be expected to fail): %v, output: %s", err, output)
			} else {
				t.Logf("Session %s dropped successfully", sessionName)
			}
		})
	})

	// Flow 2: Rejection Workflow
	t.Run("RejectionWorkflow", func(t *testing.T) {
		var rejectedSessionName string

		// Step 1: Requester creates another session
		t.Run("RequesterCreatesSession", func(t *testing.T) {
			// Drop any existing approved sessions for this group/cluster first
			dropExistingApprovedSessions(t, "breakglass-create-all", clusterName)

			// Retry session creation with backoff to handle transient timeouts
			var output string
			var err error
			for attempt := 1; attempt <= 3; attempt++ {
				output, err = runAsRequester(
					"session", "request",
					"--cluster", clusterName,
					"--group", "breakglass-create-all",
					"--reason", "Two persona Go test - rejection flow",
					"-o", "json",
				)
				if err == nil {
					break
				}
				t.Logf("Session creation attempt %d failed: %v", attempt, err)
				if attempt < 3 {
					time.Sleep(time.Duration(attempt*2) * time.Second)
				}
			}
			require.NoError(t, err, "Requester should create session")

			var session breakglassv1alpha1.BreakglassSession
			err = json.Unmarshal([]byte(output), &session)
			require.NoError(t, err)

			rejectedSessionName = session.Name
			require.NotEmpty(t, rejectedSessionName)
			t.Logf("Created session for rejection: %s", rejectedSessionName)
		})

		// Step 2: Wait for Pending
		t.Run("WaitForPendingState", func(t *testing.T) {
			require.NotEmpty(t, rejectedSessionName)

			deadline := time.Now().Add(helpers.WaitForStateTimeout)
			for time.Now().Before(deadline) {
				output, err := runAsRequester("session", "get", rejectedSessionName, "-o", "json")
				require.NoError(t, err)

				var session breakglassv1alpha1.BreakglassSession
				err = json.Unmarshal([]byte(output), &session)
				require.NoError(t, err)

				if session.Status.State == breakglassv1alpha1.SessionStatePending {
					return
				}
				time.Sleep(helpers.PollInterval)
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

			deadline := time.Now().Add(helpers.WaitForStateTimeout)
			for time.Now().Before(deadline) {
				output, err := runAsRequester("session", "get", rejectedSessionName, "-o", "json")
				require.NoError(t, err)

				var session breakglassv1alpha1.BreakglassSession
				err = json.Unmarshal([]byte(output), &session)
				require.NoError(t, err)

				if session.Status.State == breakglassv1alpha1.SessionStateRejected {
					t.Logf("Session %s is Rejected", rejectedSessionName)
					return
				}
				time.Sleep(helpers.PollInterval)
			}
			t.Fatalf("Session did not reach Rejected state")
		})

		// Step 5: Verify session appears in rejected filter
		t.Run("VerifyRejectedInFilteredList", func(t *testing.T) {
			require.NotEmpty(t, rejectedSessionName)

			// Include --mine to see own sessions (--approver defaults to true which
			// only shows sessions user can approve, not their own sessions)
			output, err := runAsRequester(
				"session", "list",
				"--state", "rejected",
				"--mine",
				"-o", "json",
			)
			require.NoError(t, err)

			var sessions []breakglassv1alpha1.BreakglassSession
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

			var sessions []breakglassv1alpha1.BreakglassSession
			err = json.Unmarshal([]byte(output), &sessions)
			require.NoError(t, err)
			t.Logf("Requester has %d sessions", len(sessions))
		})

		// Approver lists all sessions
		t.Run("ApproverListsAll", func(t *testing.T) {
			output, err := runAsApprover("session", "list", "-o", "json")
			require.NoError(t, err, "Approver should list all sessions")

			var sessions []breakglassv1alpha1.BreakglassSession
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

			// Both should see escalations (may differ based on group membership)
			var escalations1, escalations2 []breakglassv1alpha1.BreakglassEscalation
			_ = json.Unmarshal([]byte(output1), &escalations1)
			_ = json.Unmarshal([]byte(output2), &escalations2)

			// Each user should see at least one escalation
			assert.NotEmpty(t, escalations1, "Requester should see at least one escalation")
			assert.NotEmpty(t, escalations2, "Approver should see at least one escalation")
			t.Logf("Requester sees %d escalations, approver sees %d escalations", len(escalations1), len(escalations2))
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

	require.Fail(t, "bgctl binary not found - run 'make bgctl' to build it")
	return ""
}
