// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
	bgctlcmd "github.com/telekom/k8s-breakglass/pkg/bgctl/cmd"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"k8s.io/client-go/util/retry"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestEscalationNativeWildcardPrivilegeLifecycle(t *testing.T) {
	s := helpers.SetupTest(t, helpers.WithTimeout(20*time.Minute))
	user := helpers.TestUsers.PlatformIdentityRequester
	peer := helpers.TestUsers.SecurityApprover
	requester := s.TC.ClientForUser(user)
	token := s.TC.OIDCProvider().GetTokenForUser(t, s.Ctx, user)
	parts := strings.Split(token, ".")
	require.Len(t, parts, 3)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var claims struct {
		Issuer string   `json:"iss"`
		Email  string   `json:"email"`
		Groups []string `json:"groups"`
	}
	require.NoError(t, json.Unmarshal(payload, &claims))
	require.Contains(t, claims.Issuer, "/auth/realms/")
	require.Equal(t, user.Email, claims.Email)
	require.True(t, slices.Contains(claims.Groups, "dttcaas-platform_poweruser"))
	targets := []struct {
		name       string
		kubeconfig string
	}{
		{name: s.Cluster, kubeconfig: helpers.GetKubeconfig()},
	}
	if helpers.IsMultiClusterEnabled() {
		targets[0].kubeconfig = helpers.GetSpokeAKubeconfig()
		targets = append(targets, struct {
			name       string
			kubeconfig string
		}{name: helpers.GetSpokeBClusterName(), kubeconfig: helpers.GetSpokeBKubeconfig()})
		require.NotEmpty(t, targets[0].kubeconfig)
		require.NotEmpty(t, targets[1].kubeconfig, "Multi must exercise both real targets")
	}
	admins := make([]kubernetes.Interface, len(targets))
	bearerConfigs := make([]*rest.Config, len(targets))
	nativeUser := func(i int) kubernetes.Interface {
		config := rest.CopyConfig(bearerConfigs[i])
		config.BearerToken = s.TC.OIDCProvider().GetTokenForUser(t, s.Ctx, user)
		kube, err := kubernetes.NewForConfig(config)
		require.NoError(t, err)
		return kube
	}
	for i, target := range targets {
		adminConfig, err := clientcmd.BuildConfigFromFlags("", target.kubeconfig)
		require.NoError(t, err)
		admins[i], err = kubernetes.NewForConfig(adminConfig)
		require.NoError(t, err)
		// The bearer-only client must never inherit the admin client certificate.
		bearerConfigs[i] = &rest.Config{
			Host: adminConfig.Host,
			TLSClientConfig: rest.TLSClientConfig{
				CAData: adminConfig.CAData, CAFile: adminConfig.CAFile,
				Insecure: adminConfig.Insecure, ServerName: adminConfig.ServerName,
			},
		}

		var cluster breakglassv1alpha1.ClusterConfig
		key := client.ObjectKey{Namespace: s.Namespace, Name: target.name}
		require.NoError(t, s.Client.Get(s.Ctx, key, &cluster))
		originalSpec := cluster.Spec.DeepCopy()
		t.Cleanup(func() {
			require.NoError(t, retry.RetryOnConflict(retry.DefaultRetry, func() error {
				var current breakglassv1alpha1.ClusterConfig
				if err := s.Client.Get(context.Background(), key, &current); err != nil {
					return err
				}
				current.Spec = *originalSpec
				return s.Client.Update(context.Background(), &current)
			}))
		})
		if helpers.IsMultiClusterEnabled() {
			raw, err := clientcmd.LoadFromFile(target.kubeconfig)
			require.NoError(t, err)
			require.NoError(t, clientcmdapi.MinifyConfig(raw))
			require.NoError(t, clientcmdapi.FlattenConfig(raw))
			require.NotNil(t, cluster.Spec.OIDCAuth)
			for _, entry := range raw.Clusters {
				entry.Server = cluster.Spec.OIDCAuth.Server
			}
			data, err := clientcmd.Write(*raw)
			require.NoError(t, err)
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: helpers.GenerateUniqueName("native-kubeconfig"), Namespace: s.Namespace},
				Data:       map[string][]byte{"value": data},
			}
			require.NoError(t, s.Client.Create(s.Ctx, secret))
			s.Cleanup.Add(secret)
			require.NoError(t, retry.RetryOnConflict(retry.DefaultRetry, func() error {
				if err := s.Client.Get(s.Ctx, key, &cluster); err != nil {
					return err
				}
				cluster.Spec.AuthType = breakglassv1alpha1.ClusterAuthTypeKubeconfig
				cluster.Spec.OIDCAuth = nil
				cluster.Spec.KubeconfigSecretRef = &breakglassv1alpha1.SecretKeyReference{
					Name: secret.Name, Namespace: s.Namespace, Key: "value",
				}
				return s.Client.Update(s.Ctx, &cluster)
			}))
		} else {
			require.NoError(t, retry.RetryOnConflict(retry.DefaultRetry, func() error {
				if err := s.Client.Get(s.Ctx, key, &cluster); err != nil {
					return err
				}
				cluster.Spec.AuthType = breakglassv1alpha1.ClusterAuthTypeKubeconfig
				return s.Client.Update(s.Ctx, &cluster)
			}))
		}
		require.Equal(t, breakglassv1alpha1.ClusterAuthTypeKubeconfig, cluster.Spec.AuthType)
	}

	for _, end := range []string{"drop-yes", "natural-expiry", "owner-prune"} {
		t.Run(end, func(t *testing.T) {
			group := helpers.GenerateUniqueName("native-privilege")
			policy := helpers.NewEscalationBuilder(helpers.GenerateUniqueName("wildcard-policy"), s.Namespace).
				WithAllowedClusters("*").WithAllowedGroups("dttcaas-platform_poweruser").
				WithEscalatedGroup(group).WithApproverUsers(peer.Email).
				WithMaxValidFor("10m").Build()
			policy.Spec.SessionLimitsOverride = &breakglassv1alpha1.SessionLimitsOverride{
				MaxActiveSessionsPerUser: ptr.To(int32(2)),
				MaxActiveSessionsTotal:   ptr.To(int32(2)),
			}
			require.NoError(t, s.CreateResource(policy))
			helpers.WaitForEscalationReady(t, s.Ctx, s.Client, policy.Name, s.Namespace, helpers.WaitForStateTimeout)
			sessions := make([]*breakglassv1alpha1.BreakglassSession, len(targets))
			for i, target := range targets {
				binding := &rbacv1.ClusterRoleBinding{
					ObjectMeta: metav1.ObjectMeta{Name: helpers.GenerateUniqueName("native-grant")},
					RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "cluster-admin"},
					Subjects: []rbacv1.Subject{
						{APIGroup: rbacv1.GroupName, Kind: "Group", Name: group},
						{APIGroup: rbacv1.GroupName, Kind: "Group", Name: "oidc:" + group},
					},
				}
				_, err := admins[i].RbacV1().ClusterRoleBindings().Create(s.Ctx, binding, metav1.CreateOptions{})
				require.NoError(t, err)
				t.Cleanup(func() {
					_ = admins[i].RbacV1().ClusterRoleBindings().Delete(context.Background(), binding.Name, metav1.DeleteOptions{})
				})
				_, err = nativeUser(i).RbacV1().ClusterRoleBindings().Get(s.Ctx, helpers.GenerateUniqueName("baseline-denied"), metav1.GetOptions{})
				require.True(t, apierrors.IsForbidden(err), "native privilege must be denied before approval: %v", err)
				duration := int64(600)
				if end == "natural-expiry" {
					duration = 180
				}
				session, err := requester.CreateSessionAndWaitForPending(s.Ctx, t, helpers.SessionRequest{
					Cluster: target.name, User: user.Email, Group: group, Duration: duration, Reason: end,
				}, helpers.WaitForStateTimeout)
				require.NoError(t, err)
				s.Cleanup.Add(session)
				require.Equal(t, user.Email, session.Spec.User, "target user identifier must use email with no prefix")
				owner := metav1.GetControllerOf(session)
				require.NotNil(t, owner)
				require.Equal(t, policy.Name, owner.Name)
				require.Equal(t, policy.UID, owner.UID)
				require.NoError(t, s.TC.ClientForUser(peer).ApproveSessionViaAPI(s.Ctx, t, session.Name, session.Namespace))
				sessions[i] = helpers.WaitForSessionState(t, s.Ctx, s.Client, session.Name, session.Namespace, breakglassv1alpha1.SessionStateApproved, helpers.WaitForStateTimeout)
				require.Eventually(t, func() bool {
					_, err := nativeUser(i).RbacV1().ClusterRoleBindings().Get(s.Ctx, helpers.GenerateUniqueName("active-allowed"), metav1.GetOptions{})
					return apierrors.IsNotFound(err)
				}, helpers.WaitForStateTimeout, time.Second, "real target handler must be reachable after authorization, not just a patched status")
			}
			if end == "owner-prune" {
				for _, session := range sessions {
					require.True(t, time.Now().Before(session.Status.ExpiresAt.Time))
				}
				require.NoError(t, s.Client.Delete(s.Ctx, policy))
			}
			for i := range targets {
				session := sessions[i]
				switch end {
				case "drop-yes":
					probe := &rbacv1.ClusterRoleBinding{
						ObjectMeta: metav1.ObjectMeta{Name: helpers.GenerateUniqueName("dryrun-privileged")},
						RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "cluster-admin"},
						Subjects:   []rbacv1.Subject{{Kind: "User", APIGroup: rbacv1.GroupName, Name: "not-a-real-user"}},
					}
					if i == 0 {
						_, err := nativeUser(i).RbacV1().ClusterRoleBindings().Create(s.Ctx, probe, metav1.CreateOptions{DryRun: []string{metav1.DryRunAll}})
						require.NoError(t, err, "approved grant must authorize a real privileged server dry-run")
					}
					var output bytes.Buffer
					command := bgctlcmd.NewRootCommand(bgctlcmd.Config{OutputWriter: &output})
					command.SetArgs([]string{"--server", helpers.GetAPIBaseURL(), "--token", s.TC.OIDCProvider().GetTokenForUser(t, s.Ctx, user), "--token-storage", "file",
						"--non-interactive", "session", "drop", session.Name, "--yes"})
					require.NoError(t, command.ExecuteContext(s.Ctx), output.String())
					helpers.WaitForSessionState(t, s.Ctx, s.Client, session.Name, session.Namespace, breakglassv1alpha1.SessionStateExpired, helpers.WaitForStateTimeout)
					if i == 0 {
						require.Eventually(t, func() bool {
							_, err := nativeUser(i).RbacV1().ClusterRoleBindings().Create(s.Ctx, probe, metav1.CreateOptions{DryRun: []string{metav1.DryRunAll}})
							return apierrors.IsForbidden(err)
						}, helpers.WaitForStateTimeout, 2*time.Second, "same CREATE must revoke within bounded propagation; fixtures explicitly disable positive caching")
						_, err := admins[i].RbacV1().ClusterRoleBindings().Get(s.Ctx, probe.Name, metav1.GetOptions{})
						require.True(t, apierrors.IsNotFound(err), "server dry-run must leave zero persisted probe resources")
					}
				case "natural-expiry":
					helpers.WaitForSessionState(t, s.Ctx, s.Client, session.Name, session.Namespace, breakglassv1alpha1.SessionStateExpired, 4*time.Minute)
					require.False(t, time.Now().Before(session.Status.ExpiresAt.Time))
				case "owner-prune":
					require.Eventually(t, func() bool {
						return apierrors.IsNotFound(s.Client.Get(s.Ctx, client.ObjectKeyFromObject(session), &breakglassv1alpha1.BreakglassSession{}))
					}, helpers.WaitForStateTimeout, time.Second, "Kubernetes must GC the live dependent before its lease expires")
				}
				require.Eventually(t, func() bool {
					_, err := nativeUser(i).RbacV1().ClusterRoleBindings().Get(s.Ctx, helpers.GenerateUniqueName("fresh-revoked"), metav1.GetOptions{})
					return apierrors.IsForbidden(err)
				}, helpers.WaitForStateTimeout, time.Second, "fresh native privileged request must be revoked")
			}
		})
	}
}
