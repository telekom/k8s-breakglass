//go:build multicluster

// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
)

const authorizationConfigPath = "/etc/kubernetes/authorization-config.yaml"
const authorizationKubeconfigPath = "/etc/kubernetes/breakglass-webhook.kubeconfig"

func (s *SpokeHubAuthorizationSuite) nodeCommand(ctx context.Context, args ...string) ([]byte, error) {
	node := s.mcCtx.Config.SpokeAClusterName + "-control-plane"
	return exec.CommandContext(ctx, "docker", append([]string{"exec", node}, args...)...).CombinedOutput()
}

func (s *SpokeHubAuthorizationSuite) writeNodeFile(ctx context.Context, path string, data []byte) error {
	node := s.mcCtx.Config.SpokeAClusterName + "-control-plane"
	output, err := exec.CommandContext(ctx, "docker", "inspect", "--format", "{{json .Mounts}}", node).Output()
	if err != nil {
		return fmt.Errorf("inspect Kind mounts: %w", err)
	}
	var mounts []struct{ Type, Source, Destination string }
	if err := json.Unmarshal(output, &mounts); err != nil {
		return err
	}
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	// go test runs this package from <checkout>/e2e/api.
	root, err := filepath.EvalSymlinks(filepath.Join(cwd, "..", ".."))
	if err != nil {
		return err
	}
	for _, mount := range mounts {
		if mount.Destination != path || mount.Type != "bind" {
			continue
		}
		info, statErr := os.Lstat(mount.Source)
		if statErr != nil {
			return statErr
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("Kind fixture is not a regular file: %s", mount.Source)
		}
		source, resolveErr := filepath.EvalSymlinks(mount.Source)
		if resolveErr != nil {
			return resolveErr
		}
		relative, relErr := filepath.Rel(root, source)
		if relErr != nil {
			return relErr
		}
		if relative == ".." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
			return fmt.Errorf("Kind fixture must belong to this checkout: %s", source)
		}
		writePath, pathErr := filepath.Rel(cwd, source)
		if pathErr != nil {
			return pathErr
		}
		// Kind mounts these files read-only. Truncate the host fixture in place so
		// the existing bind mount observes the update without replacing its inode.
		return os.WriteFile(writePath, data, info.Mode().Perm())
	}
	return fmt.Errorf("no dedicated bind-mounted Kind fixture found: %s", path)
}

func (s *SpokeHubAuthorizationSuite) restartSpokeAPIServer(ctx context.Context) error {
	output, err := s.nodeCommand(ctx, "crictl", "--runtime-endpoint", "unix:///run/containerd/containerd.sock", "ps", "--name", "kube-apiserver", "-q")
	if err != nil {
		return fmt.Errorf("list spoke apiserver: %w: %s", err, output)
	}
	ids := strings.Fields(string(output))
	if len(ids) != 1 {
		return fmt.Errorf("expected one running spoke apiserver, got %d", len(ids))
	}
	_, err = s.nodeCommand(ctx, "crictl", "--runtime-endpoint", "unix:///run/containerd/containerd.sock", "stop", ids[0])
	if err != nil {
		return fmt.Errorf("stop spoke apiserver: %w", err)
	}
	return wait.PollUntilContextTimeout(ctx, time.Second, 2*time.Minute, true, func(ctx context.Context) (bool, error) {
		out, requestErr := s.runKubectlWithKubeconfig(ctx, s.mcCtx.Config.SpokeAKubeconfig, "get", "--raw=/readyz")
		return requestErr == nil && strings.TrimSpace(out) == "ok", nil
	})
}

// These suite methods run serially. Only spoke A is changed, not the hub service.
// Restore exact file bytes and restart on success or assertion failure.
func (s *SpokeHubAuthorizationSuite) configureSpokeAuthorization(cache bool, outage bool) {
	authz, err := s.nodeCommand(s.ctx, "cat", authorizationConfigPath)
	s.Require().NoError(err)
	kubeconfig, err := s.nodeCommand(s.ctx, "cat", authorizationKubeconfigPath)
	s.Require().NoError(err)
	s.T().Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		restoreErr := errors.Join(
			s.writeNodeFile(ctx, authorizationConfigPath, authz),
			s.writeNodeFile(ctx, authorizationKubeconfigPath, kubeconfig),
			s.restartSpokeAPIServer(ctx),
		)
		s.Assert().NoError(restoreErr, "all spoke restoration steps must be attempted even after a failure")
	})
	var config map[string]interface{}
	s.Require().NoError(yaml.Unmarshal(authz, &config))
	authorizers, ok := config["authorizers"].([]interface{})
	s.Require().True(ok)
	s.Require().Len(authorizers, 3)
	for i, expected := range []string{"Node", "RBAC", "Webhook"} {
		authorizer, valid := authorizers[i].(map[string]interface{})
		s.Require().True(valid)
		s.Require().Equal(expected, authorizer["type"])
	}
	webhook := authorizers[2].(map[string]interface{})["webhook"].(map[string]interface{})
	s.Require().Equal("NoOpinion", webhook["failurePolicy"])
	webhook["authorizedTTL"] = "20s"
	webhook["unauthorizedTTL"] = "1s"
	webhook["cacheAuthorizedRequests"] = cache
	webhook["cacheUnauthorizedRequests"] = false
	updated, err := json.Marshal(config)
	s.Require().NoError(err)
	s.Require().NoError(s.writeNodeFile(s.ctx, authorizationConfigPath, updated))
	if outage {
		cfg, loadErr := clientcmd.Load(kubeconfig)
		s.Require().NoError(loadErr)
		for _, cluster := range cfg.Clusters {
			cluster.Server = "http://127.0.0.1:1"
		}
		updatedKubeconfig, writeErr := clientcmd.Write(*cfg)
		s.Require().NoError(writeErr)
		s.Require().NoError(s.writeNodeFile(s.ctx, authorizationKubeconfigPath, updatedKubeconfig))
		probe, probeErr := s.nodeCommand(s.ctx, "bash", "-c", "exec 3<>/dev/tcp/127.0.0.1/1")
		s.Require().Error(probeErr, "the configured outage endpoint must be unreachable")
		s.Require().Contains(strings.ToLower(string(probe)), "connection refused")
	}
	s.Require().NoError(s.restartSpokeAPIServer(s.ctx))
}

func (s *SpokeHubAuthorizationSuite) approvedResilienceSession() (*breakglassv1alpha1.BreakglassSession, string, *helpers.APIClient) {
	token := s.mcCtx.GetEmployeeToken(s.T(), s.ctx)
	apiClient := helpers.NewAPIClientWithAuth(token)
	apiClient.BaseURL = s.mcCtx.Config.HubAPIURL
	apiClient.WithCleanupClient(s.hubClient, s.namespace)
	session, err := apiClient.CreateSessionAndWaitForPending(s.ctx, s.T(), helpers.SessionRequest{
		Cluster: s.mcCtx.Config.SpokeAClusterName, User: helpers.MultiClusterTestUsers.Employee.Email,
		Group: "breakglass-read-only", Reason: "Authorization resilience test",
	}, helpers.WaitForStateTimeout)
	s.Require().NoError(err)
	s.cleanup.Add(session)
	s.Require().NoError(s.approverAPI.ApproveSessionViaAPI(s.ctx, s.T(), session.Name, session.Namespace))
	helpers.WaitForSessionState(s.T(), s.ctx, s.hubClient, session.Name, session.Namespace,
		breakglassv1alpha1.SessionStateApproved, helpers.WaitForStateTimeout)
	return session, token, apiClient
}

func (s *SpokeHubAuthorizationSuite) TestCachedAuthorizationRevocation() {
	s.configureSpokeAuthorization(true, false)
	session, token, apiClient := s.approvedResilienceSession()
	kubeconfig := s.getOIDCKubeconfig(s.mcCtx.Config.SpokeAClusterName)
	// A real list operation populates the Kubernetes apiserver's webhook cache.
	out, err := s.runKubectlWithToken(kubeconfig, token, "get", "pods", "-n", "default")
	s.Require().NoError(err, out)
	revokedAt := time.Now()
	s.Require().NoError(apiClient.DropSessionViaAPI(s.ctx, s.T(), session.Name, session.Namespace))
	helpers.WaitForSessionState(s.T(), s.ctx, s.hubClient, session.Name, session.Namespace,
		breakglassv1alpha1.SessionStateExpired, helpers.WaitForStateTimeout)
	out, err = s.runKubectlWithToken(kubeconfig, token, "get", "pods", "-n", "default")
	s.Require().NoError(err, "warm cached allow must be observed after revocation: %s", out)
	s.Require().Eventually(func() bool {
		out, requestErr := s.runKubectlWithToken(kubeconfig, token, "get", "pods", "-n", "default")
		return requestErr != nil && strings.Contains(strings.ToLower(out), "forbidden")
	}, 25*time.Second, time.Second, "revocation must remove cached permission within TTL plus bounded polling")
	s.Require().LessOrEqual(time.Since(revokedAt), 30*time.Second, "measure from actual API revocation, not the first poll")
}

func (s *SpokeHubAuthorizationSuite) TestWebhookOutageNoOpinionPreservesRBAC() {
	_, token, _ := s.approvedResilienceSession()
	kubeconfig := s.getOIDCKubeconfig(s.mcCtx.Config.SpokeAClusterName)
	out, err := s.runKubectlWithToken(kubeconfig, token, "get", "pods", "-n", "default")
	s.Require().NoError(err, "permitted control must succeed before the outage: %s", out)
	adminConfig, err := clientcmd.BuildConfigFromFlags("", s.mcCtx.Config.SpokeAKubeconfig)
	s.Require().NoError(err)
	spoke, err := client.New(adminConfig, client.Options{})
	s.Require().NoError(err)
	namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: helpers.GenerateUniqueName("outage-rbac")}}
	s.Require().NoError(spoke.Create(s.ctx, namespace))
	s.T().Cleanup(func() { s.Require().NoError(spoke.Delete(context.Background(), namespace)) })
	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{Name: "read-configmaps", Namespace: namespace.Name},
		Rules:      []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"configmaps"}, Verbs: []string{"list"}}},
	}
	binding := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: role.Name, Namespace: namespace.Name},
		RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: role.Name},
		Subjects:   []rbacv1.Subject{{Kind: "User", Name: helpers.MultiClusterTestUsers.Employee.Email}},
	}
	s.Require().NoError(spoke.Create(s.ctx, role))
	s.Require().NoError(spoke.Create(s.ctx, binding))
	s.configureSpokeAuthorization(false, true)
	// The webhook points at a closed local port and caching is disabled. RBAC
	// must still grant its narrow rule; NoOpinion must never grant other verbs.
	out, err = s.runKubectlWithToken(kubeconfig, token, "get", "configmaps", "-n", namespace.Name)
	s.Require().NoError(err, "RBAC allow remains effective during outage: %s", out)
	out, err = s.runKubectlWithToken(kubeconfig, token, "get", "pods", "-n", "default")
	s.Require().Error(err, "a live approved session cannot grant uncached access through an unreachable webhook")
	s.Require().Contains(strings.ToLower(out), "forbidden", "setup/network failures do not count as a policy denial")

	// In production order RBAC allows short-circuit before the webhook. A
	// temporary downstream RBAC control distinguishes NoOpinion from Deny.
	authz, err := s.nodeCommand(s.ctx, "cat", authorizationConfigPath)
	s.Require().NoError(err)
	var config map[string]interface{}
	s.Require().NoError(yaml.Unmarshal(authz, &config))
	authorizers := config["authorizers"].([]interface{})
	authorizers[1], authorizers[2] = authorizers[2], authorizers[1]
	updated, err := json.Marshal(config)
	s.Require().NoError(err)
	s.Require().NoError(s.writeNodeFile(s.ctx, authorizationConfigPath, updated))
	s.Require().NoError(s.restartSpokeAPIServer(s.ctx))
	out, err = s.runKubectlWithToken(kubeconfig, token, "get", "configmaps", "-n", namespace.Name)
	s.Require().NoError(err, "NoOpinion must continue past the failed webhook to a downstream RBAC allow: %s", out)
	out, err = s.runKubectlWithToken(kubeconfig, token, "get", "pods", "-n", "default")
	s.Require().Error(err)
	s.Require().Contains(strings.ToLower(out), "forbidden")
}
