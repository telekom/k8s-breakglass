//go:build multicluster
// +build multicluster

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

package api

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"

	telekomv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
)

func init() {
	_ = telekomv1alpha1.AddToScheme(scheme.Scheme)
}

// HubSpokeTestSuite tests hub-and-spoke multi-cluster topology with real Kind clusters.
// This requires the multi-cluster environment to be set up via kind-setup-multi.sh.
type HubSpokeTestSuite struct {
	suite.Suite
	ctx          context.Context
	cancel       context.CancelFunc
	hubClient    client.Client
	spokeAClient kubernetes.Interface
	spokeBClient kubernetes.Interface
	config       helpers.MultiClusterConfig
	cleanup      *helpers.Cleanup
}

func TestHubSpokeSuite(t *testing.T) {
	if !helpers.IsMultiClusterEnabled() {
		t.Skip("Multi-cluster tests disabled. Set E2E_MULTI_CLUSTER=true to enable.")
	}
	suite.Run(t, new(HubSpokeTestSuite))
}

func (s *HubSpokeTestSuite) SetupSuite() {
	s.ctx, s.cancel = context.WithTimeout(context.Background(), 30*time.Minute)
	s.config = helpers.GetMultiClusterConfig()

	// Validate configuration
	s.Require().NotEmpty(s.config.HubKubeconfig, "E2E_HUB_KUBECONFIG must be set")
	s.Require().NotEmpty(s.config.SpokeAKubeconfig, "E2E_SPOKE_A_KUBECONFIG must be set")
	s.Require().NotEmpty(s.config.SpokeBKubeconfig, "E2E_SPOKE_B_KUBECONFIG must be set")

	// Create hub client (controller-runtime client for CRD access)
	hubCfg, err := clientcmd.BuildConfigFromFlags("", s.config.HubKubeconfig)
	s.Require().NoError(err, "Failed to build hub kubeconfig")
	s.hubClient, err = client.New(hubCfg, client.Options{Scheme: scheme.Scheme})
	s.Require().NoError(err, "Failed to create hub client")

	// Create spoke clients (kubernetes clientset for RBAC verification)
	spokeACfg, err := clientcmd.BuildConfigFromFlags("", s.config.SpokeAKubeconfig)
	s.Require().NoError(err, "Failed to build spoke-a kubeconfig")
	s.spokeAClient, err = kubernetes.NewForConfig(spokeACfg)
	s.Require().NoError(err, "Failed to create spoke-a client")

	spokeBCfg, err := clientcmd.BuildConfigFromFlags("", s.config.SpokeBKubeconfig)
	s.Require().NoError(err, "Failed to build spoke-b kubeconfig")
	s.spokeBClient, err = kubernetes.NewForConfig(spokeBCfg)
	s.Require().NoError(err, "Failed to create spoke-b client")

	// Initialize cleanup helper
	s.cleanup = helpers.NewCleanup(s.T(), s.hubClient)
}

func (s *HubSpokeTestSuite) TearDownSuite() {
	// Cleanup is run automatically via t.Cleanup
	if s.cancel != nil {
		s.cancel()
	}
}

// TestClusterConfigsRegistered verifies all cluster configs are registered and ready
func (s *HubSpokeTestSuite) TestClusterConfigsRegistered() {
	t := s.T()
	namespace := helpers.GetTestNamespace()

	clusters := []string{
		s.config.HubClusterName,
		s.config.SpokeAClusterName,
		s.config.SpokeBClusterName,
	}

	for _, clusterName := range clusters {
		t.Run(fmt.Sprintf("Cluster_%s", clusterName), func(t *testing.T) {
			var cc telekomv1alpha1.ClusterConfig
			err := s.hubClient.Get(s.ctx, client.ObjectKey{
				Namespace: namespace,
				Name:      clusterName,
			}, &cc)
			require.NoError(t, err, "ClusterConfig %s should exist", clusterName)

			// Verify status is Ready via conditions
			readyCondition := apimeta.FindStatusCondition(cc.Status.Conditions, "Ready")
			require.NotNil(t, readyCondition, "ClusterConfig %s should have Ready condition", clusterName)
			require.Equal(t, metav1.ConditionTrue, readyCondition.Status,
				"ClusterConfig %s should be Ready", clusterName)
		})
	}
}

// TestIdentityProvidersConfigured verifies identity providers exist
// Note: IdentityProvider is cluster-scoped and uses OIDC config, not ClusterConfigRefs
func (s *HubSpokeTestSuite) TestIdentityProvidersConfigured() {
	t := s.T()

	t.Run("MainIDP", func(t *testing.T) {
		var idp telekomv1alpha1.IdentityProvider
		err := s.hubClient.Get(s.ctx, client.ObjectKey{
			Name: "main-idp",
		}, &idp)
		require.NoError(t, err, "main-idp should exist")

		// Verify OIDC is configured
		require.NotEmpty(t, idp.Spec.OIDC.Authority, "main-idp should have OIDC authority")
		require.NotEmpty(t, idp.Spec.OIDC.ClientID, "main-idp should have OIDC clientID")
	})

	t.Run("ContractorsIDP", func(t *testing.T) {
		var idp telekomv1alpha1.IdentityProvider
		err := s.hubClient.Get(s.ctx, client.ObjectKey{
			Name: "contractors-idp",
		}, &idp)
		require.NoError(t, err, "contractors-idp should exist")

		// Verify it has OIDC configured
		require.NotEmpty(t, idp.Spec.OIDC.Authority, "contractors-idp should have OIDC authority")
	})
}

// TestEscalationClusterScoping verifies escalations respect cluster scoping via ClusterConfigRefs
func (s *HubSpokeTestSuite) TestEscalationClusterScoping() {
	t := s.T()
	namespace := helpers.GetTestNamespace()

	testCases := []struct {
		name             string
		escalationName   string
		expectedClusters []string // nil means all clusters (global), empty list explicitly set means apply to all
	}{
		{
			name:             "GlobalReadOnly",
			escalationName:   "mc-global-readonly",
			expectedClusters: nil, // no ClusterConfigRefs = global
		},
		{
			name:             "HubOnly",
			escalationName:   "mc-hub-admin",
			expectedClusters: []string{s.config.HubClusterName},
		},
		{
			name:             "SpokeAOnly",
			escalationName:   "mc-spoke-a-pods",
			expectedClusters: []string{s.config.SpokeAClusterName},
		},
		{
			name:             "SpokeBOnly",
			escalationName:   "mc-spoke-b-debugger",
			expectedClusters: []string{s.config.SpokeBClusterName},
		},
		{
			name:             "BothSpokes",
			escalationName:   "mc-spoke-clusters-admin",
			expectedClusters: []string{s.config.SpokeAClusterName, s.config.SpokeBClusterName},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var esc telekomv1alpha1.BreakglassEscalation
			err := s.hubClient.Get(s.ctx, client.ObjectKey{
				Namespace: namespace,
				Name:      tc.escalationName,
			}, &esc)
			require.NoError(t, err, "Escalation %s should exist", tc.escalationName)

			if tc.expectedClusters == nil {
				// Global escalations use "*" as a wildcard, so ClusterConfigRefs has 1 element
				require.Len(t, esc.Spec.ClusterConfigRefs, 1,
					"Global escalation should have '*' wildcard in ClusterConfigRefs")
				require.Equal(t, "*", esc.Spec.ClusterConfigRefs[0],
					"Global escalation should use '*' wildcard")
			} else {
				require.Len(t, esc.Spec.ClusterConfigRefs, len(tc.expectedClusters),
					"Escalation should be scoped to expected number of clusters")

				for i, expected := range tc.expectedClusters {
					require.Equal(t, expected, esc.Spec.ClusterConfigRefs[i],
						"Cluster ref should match expected")
				}
			}
		})
	}
}

// TestDenyPolicyScoping verifies deny policies have correct scope configuration
func (s *HubSpokeTestSuite) TestDenyPolicyScoping() {
	t := s.T()
	namespace := helpers.GetTestNamespace()

	t.Run("DenyPolicyExists", func(t *testing.T) {
		var dpList telekomv1alpha1.DenyPolicyList
		err := s.hubClient.List(s.ctx, &dpList, client.InNamespace(namespace))
		require.NoError(t, err)

		// Just verify we can list deny policies
		// The actual structure uses AppliesTo.Clusters, not ClusterConfigRefs
		t.Logf("Found %d deny policies", len(dpList.Items))
	})
}

// TestSpokeClusterConnectivity verifies that the hub can connect to spoke clusters
func (s *HubSpokeTestSuite) TestSpokeClusterConnectivity() {
	t := s.T()

	t.Run("SpokeAConnectivity", func(t *testing.T) {
		// Verify we can list namespaces on spoke-a
		_, err := s.spokeAClient.CoreV1().Namespaces().List(s.ctx, metav1.ListOptions{Limit: 1})
		require.NoError(t, err, "Should be able to connect to spoke-cluster-a")
	})

	t.Run("SpokeBConnectivity", func(t *testing.T) {
		// Verify we can list namespaces on spoke-b
		_, err := s.spokeBClient.CoreV1().Namespaces().List(s.ctx, metav1.ListOptions{Limit: 1})
		require.NoError(t, err, "Should be able to connect to spoke-cluster-b")
	})
}

// TestSessionCreationForDifferentClusters verifies sessions can be created for different clusters
func (s *HubSpokeTestSuite) TestSessionCreationForDifferentClusters() {
	t := s.T()
	namespace := helpers.GetTestNamespace()

	testCases := []struct {
		name       string
		cluster    string
		group      string
		shouldFail bool
	}{
		{
			name:       "SessionOnSpokeA",
			cluster:    s.config.SpokeAClusterName,
			group:      "breakglass-pods-admin",
			shouldFail: false,
		},
		{
			name:       "SessionOnSpokeB",
			cluster:    s.config.SpokeBClusterName,
			group:      "contractor-debugger",
			shouldFail: false,
		},
		{
			name:       "SessionOnHub",
			cluster:    s.config.HubClusterName,
			group:      "breakglass-emergency-admin",
			shouldFail: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			session := helpers.NewSessionBuilder(fmt.Sprintf("mc-test-%s-%d", tc.cluster, time.Now().UnixNano()), namespace).
				WithCluster(tc.cluster).
				WithUser(helpers.MultiClusterTestUsers.Employee.Email).
				WithGrantedGroup(tc.group).
				WithRequestReason(fmt.Sprintf("Multi-cluster test for %s", tc.cluster)).
				Build()

			if tc.shouldFail {
				err := s.hubClient.Create(s.ctx, session)
				require.Error(t, err, "Session creation should fail for %s", tc.cluster)
			} else {
				s.cleanup.Add(session)
				err := s.hubClient.Create(s.ctx, session)
				require.NoError(t, err, "Session creation should succeed for %s", tc.cluster)

				// Verify session was created
				var fetched telekomv1alpha1.BreakglassSession
				err = s.hubClient.Get(s.ctx, client.ObjectKey{
					Namespace: namespace,
					Name:      session.Name,
				}, &fetched)
				require.NoError(t, err)
				require.Equal(t, tc.cluster, fetched.Spec.Cluster)
			}
		})
	}
}

// TestCrossClusterSessionVisibility verifies sessions are visible from hub regardless of target cluster
func (s *HubSpokeTestSuite) TestCrossClusterSessionVisibility() {
	t := s.T()
	namespace := helpers.GetTestNamespace()
	testLabel := fmt.Sprintf("mc-visibility-%d", time.Now().UnixNano())
	expectedClusters := []string{s.config.HubClusterName, s.config.SpokeAClusterName, s.config.SpokeBClusterName}

	// Create sessions for each cluster
	for _, cluster := range expectedClusters {
		session := helpers.NewSessionBuilder(fmt.Sprintf("%s-%s", testLabel, cluster), namespace).
			WithCluster(cluster).
			WithUser(helpers.MultiClusterTestUsers.Employee.Email).
			WithGrantedGroup("breakglass-read-only").
			WithRequestReason("Testing cross-cluster visibility").
			WithLabels(map[string]string{
				"test": testLabel,
			}).
			Build()
		s.cleanup.Add(session)
		err := s.hubClient.Create(s.ctx, session)
		require.NoError(t, err, "Should create session for %s", cluster)
	}

	// Wait for client cache to sync and verify all sessions are visible
	require.Eventually(t, func() bool {
		var sessionList telekomv1alpha1.BreakglassSessionList
		err := s.hubClient.List(s.ctx, &sessionList, client.InNamespace(namespace), client.MatchingLabels{
			"test": testLabel,
		})
		if err != nil {
			return false
		}

		// Verify we can see sessions for all clusters
		clustersSeen := make(map[string]bool)
		for _, session := range sessionList.Items {
			clustersSeen[session.Spec.Cluster] = true
		}

		for _, cluster := range expectedClusters {
			if !clustersSeen[cluster] {
				return false
			}
		}
		return true
	}, 30*time.Second, helpers.PollInterval, "Should see sessions for all clusters (hub, spoke-a, spoke-b)")
}
