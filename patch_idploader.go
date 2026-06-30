package main

import (
	"io/ioutil"
	"strings"
)

func main() {
	f, _ := ioutil.ReadFile("pkg/config/identity_provider_loader.go")
	s := string(f)
	
	s = strings.Replace(s, "type IdentityProviderLoader struct {\n\tkubeClient      client.Client\n\tlogger          *zap.SugaredLogger\n\tmetricsRecorder ConversionErrorMetricsRecorder\n}", "type IdentityProviderLoader struct {\n\tkubeClient      client.Client\n\tlogger          *zap.SugaredLogger\n\tmetricsRecorder ConversionErrorMetricsRecorder\n\n\tmu       sync.RWMutex\n\tcached   []breakglassv1alpha1.IdentityProvider\n}", 1)

	s = strings.Replace(s, "\"strings\"", "\"strings\"\n\t\"sync\"", 1)
	
	newMethods := `// UpdateCache fetches all IdentityProviders and updates the read-only cache.
// Should be called from a reconciler to avoid List calls on the webhook hot path.
func (l *IdentityProviderLoader) UpdateCache(ctx context.Context) error {
	idpList := &breakglassv1alpha1.IdentityProviderList{}
	if err := l.kubeClient.List(ctx, idpList); err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.cached = idpList.Items
	return nil
}

// GetCachedIdentityProviders returns a read-only list of IdentityProviders without deep-copying.
func (l *IdentityProviderLoader) GetCachedIdentityProviders() []breakglassv1alpha1.IdentityProvider {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.cached
}
`
	s = s + "\n" + newMethods
	ioutil.WriteFile("pkg/config/identity_provider_loader.go", []byte(s), 0644)
}
