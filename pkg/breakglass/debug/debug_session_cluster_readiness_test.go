package debug

import (
	"testing"

	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func readyDebugClusterConfig(namespace, name string, labels map[string]string) breakglassv1alpha1.ClusterConfig {
	return breakglassv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
			Labels:    labels,
		},
		Status: breakglassv1alpha1.ClusterConfigStatus{
			Conditions: []metav1.Condition{{
				Type:   string(breakglassv1alpha1.ClusterConfigConditionReady),
				Status: metav1.ConditionTrue,
			}},
		},
	}
}

func TestDebugClusterConfigMapsExcludeDuplicateNames(t *testing.T) {
	items := []breakglassv1alpha1.ClusterConfig{
		readyDebugClusterConfig("team-a", "shared", map[string]string{"env": "prod"}),
		readyDebugClusterConfig("team-b", "shared", map[string]string{"env": "prod"}),
		readyDebugClusterConfig("team-a", "unique", map[string]string{"env": "prod"}),
	}

	allMap := debugClusterConfigMap(items)
	require.NotContains(t, allMap, "shared")
	require.Contains(t, allMap, "unique")

	readyMap, readyNames := readyDebugClusterConfigMap(items)
	require.NotContains(t, readyMap, "shared")
	require.Contains(t, readyMap, "unique")
	require.ElementsMatch(t, []string{"unique"}, readyNames)
}

func TestFindDebugClusterConfigByNameReportsDuplicateNamesAsAmbiguous(t *testing.T) {
	items := []breakglassv1alpha1.ClusterConfig{
		readyDebugClusterConfig("team-a", "shared", nil),
		readyDebugClusterConfig("team-b", "shared", nil),
	}

	cc, ambiguous := findDebugClusterConfigByNameOrTenant(items, "shared")
	require.True(t, ambiguous)
	require.Nil(t, cc)
}

func TestResolveClustersFromBindingSkipsAmbiguousClusterConfigNames(t *testing.T) {
	items := []breakglassv1alpha1.ClusterConfig{
		readyDebugClusterConfig("team-a", "shared", map[string]string{"env": "prod"}),
		readyDebugClusterConfig("team-b", "shared", map[string]string{"env": "prod"}),
		readyDebugClusterConfig("team-a", "unique", map[string]string{"env": "prod"}),
	}
	clusterMap, _ := readyDebugClusterConfigMap(items)
	binding := &breakglassv1alpha1.DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "binding", Namespace: "team-a"},
		Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
			Clusters: []string{"shared", "unique"},
			ClusterSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"env": "prod"},
			},
		},
	}
	controller := &DebugSessionAPIController{log: zap.NewNop().Sugar()}

	clusters := controller.resolveClustersFromBinding(binding, clusterMap)
	require.ElementsMatch(t, []string{"unique"}, clusters)
	require.NotContains(t, clusters, "shared")
}
