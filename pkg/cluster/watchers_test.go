package cluster

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientcache "k8s.io/client-go/tools/cache"

	"github.com/stretchr/testify/assert"
	telekomv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
)

func TestExtractClusterConfigHandlesDeletedFinalState(t *testing.T) {
	cfg := &telekomv1alpha1.ClusterConfig{}
	wrapped := clientcache.DeletedFinalStateUnknown{Obj: cfg}

	assert.Same(t, cfg, extractClusterConfig(wrapped))
}

func TestExtractClusterConfigReturnsNilForUnknownTypes(t *testing.T) {
	assert.Nil(t, extractClusterConfig("not-a-cluster"))
}

func TestExtractSecretHandlesDeletedFinalState(t *testing.T) {
	sec := &corev1.Secret{}
	wrapped := clientcache.DeletedFinalStateUnknown{Obj: sec}

	assert.Same(t, sec, extractSecret(wrapped))
}

func TestExtractSecretReturnsNilForUnknownTypes(t *testing.T) {
	assert.Nil(t, extractSecret(v1.Now()))
}
