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

func TestFindDebugClusterConfigByNameReportsDuplicateNamesAsNameAmbiguity(t *testing.T) {
	items := []breakglassv1alpha1.ClusterConfig{
		readyDebugClusterConfig("team-a", "shared", nil),
		readyDebugClusterConfig("team-b", "shared", nil),
	}

	cc, ambiguity := findDebugClusterConfigByNameOrTenant(items, "shared")
	require.Equal(t, debugClusterConfigAmbiguityName, ambiguity)
	require.Nil(t, cc)
}

func TestFindDebugClusterConfigByTenantReportsDuplicateMatchedNameAsNameAmbiguity(t *testing.T) {
	items := []breakglassv1alpha1.ClusterConfig{
		readyDebugClusterConfig("team-a", "shared", nil),
		readyDebugClusterConfig("team-b", "shared", nil),
	}
	items[0].Spec.Tenant = "tenant-a"
	items[1].Spec.Tenant = "tenant-b"

	cc, ambiguity := findDebugClusterConfigByNameOrTenant(items, "tenant-a")
	require.Equal(t, debugClusterConfigAmbiguityName, ambiguity)
	require.NotNil(t, cc)
	require.Equal(t, "shared", cc.Name)
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

	clusters := controller.resolveClustersFromBinding(binding, clusterMap, nil)
	require.ElementsMatch(t, []string{"unique"}, clusters)
	require.NotContains(t, clusters, "shared")
}

func TestResolveClustersFromBindingEmptySelectorKeepsExplicitOnly(t *testing.T) {
	clusterMap, _ := readyDebugClusterConfigMap([]breakglassv1alpha1.ClusterConfig{
		readyDebugClusterConfig("team-a", "explicit", nil),
		readyDebugClusterConfig("team-a", "other", nil),
	})
	binding := &breakglassv1alpha1.DebugSessionClusterBinding{Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
		Clusters: []string{"explicit"}, ClusterSelector: &metav1.LabelSelector{},
	}}
	controller := &DebugSessionAPIController{log: zap.NewNop().Sugar()}
	require.Equal(t, []string{"explicit"}, controller.resolveClustersFromBinding(binding, clusterMap, nil))
}

func TestResolveClustersFromBindingExpandsUniqueTenantAlias(t *testing.T) {
	cluster := readyDebugClusterConfig("team-a", "canonical", nil)
	cluster.Spec.Tenant = "tenant-a"
	clusterMap, _ := readyDebugClusterConfigMap([]breakglassv1alpha1.ClusterConfig{cluster})
	controller := &DebugSessionAPIController{log: zap.NewNop().Sugar()}

	binding := &breakglassv1alpha1.DebugSessionClusterBinding{Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
		Clusters: []string{"tenant-a"},
	}}

	require.Equal(t, []string{"canonical"}, controller.resolveClustersFromBinding(binding, clusterMap, []breakglassv1alpha1.ClusterConfig{cluster}))
}

func TestDirectTemplateAllowsClusterReferenceUsesTenantAlias(t *testing.T) {
	cluster := readyDebugClusterConfig("team-a", "canonical", nil)
	cluster.Spec.Tenant = "tenant-a"
	template := &breakglassv1alpha1.DebugSessionTemplate{Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
		Allowed: &breakglassv1alpha1.DebugSessionAllowed{Clusters: []string{"tenant-a"}},
	}}

	require.True(t, directTemplateAllowsClusterReference(template, "canonical", &cluster, []breakglassv1alpha1.ClusterConfig{cluster}))
}

func TestClusterReferenceChecksNamespaceBeforeCanonicalGrant(t *testing.T) {
	cluster := readyDebugClusterConfig("team-a", "canonical", map[string]string{"env": "prod"})
	cluster.Spec.Tenant = "tenant-a"
	configured := []breakglassv1alpha1.ClusterConfig{cluster}
	controller := &DebugSessionController{}
	for _, selector := range []bool{false, true} {
		template := &breakglassv1alpha1.DebugSessionTemplate{Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			Allowed: &breakglassv1alpha1.DebugSessionAllowed{Clusters: []string{"canonical"}},
		}}
		binding := &breakglassv1alpha1.DebugSessionClusterBinding{Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{Clusters: []string{"canonical"}}}
		if selector {
			template.Spec.Allowed.Clusters = nil
			template.Spec.Allowed.ClusterSelector = &metav1.LabelSelector{MatchLabels: map[string]string{"env": "prod"}}
			binding.Spec.Clusters = nil
			binding.Spec.ClusterSelector = template.Spec.Allowed.ClusterSelector
		}
		for reference, allowed := range map[string]bool{
			"canonical": true, "tenant-a": true, "team-a/canonical": true,
			"team-a/tenant-a": true, "other/canonical": false, "other/tenant-a": false,
			"missing": false, "team-a/missing": false,
		} {
			require.Equal(t, allowed, directTemplateAllowsClusterReference(template, reference, &cluster, configured), reference)
			require.Equal(t, allowed, controller.bindingMatchesClusterReference(binding, reference, &cluster, configured), reference)
		}
		for _, otherName := range []string{"other", "tenant-a", "canonical"} {
			other := readyDebugClusterConfig("team-b", otherName, cluster.Labels)
			other.Spec.Tenant = cluster.Spec.Tenant
			snapshot := []breakglassv1alpha1.ClusterConfig{cluster, other}
			for _, reference := range []string{"tenant-a", "team-a/tenant-a"} {
				require.False(t, directTemplateAllowsClusterReference(template, reference, &cluster, snapshot), otherName+"/"+reference)
				require.False(t, controller.bindingMatchesClusterReference(binding, reference, &cluster, snapshot), otherName+"/"+reference)
			}
		}
	}
}
