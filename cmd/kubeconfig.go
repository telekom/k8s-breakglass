package main

import (
	"fmt"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	ctrl "sigs.k8s.io/controller-runtime"
)

// getKubeConfig resolves the REST configuration based on the provided context name.
// If contextName is not empty, it forces clientcmd to load that specific context.
// Otherwise, it falls back to the standard controller-runtime behavior.
func getKubeConfig(contextName string) (*rest.Config, error) {
	if contextName != "" {
		loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
		configOverrides := &clientcmd.ConfigOverrides{CurrentContext: contextName}
		kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, configOverrides)
		restConfig, err := kubeConfig.ClientConfig()
		if err != nil {
			return nil, fmt.Errorf("load specific kubeconfig context %q: %w", contextName, err)
		}
		return restConfig, nil
	}

	restConfig, err := ctrl.GetConfig()
	if err != nil {
		return nil, fmt.Errorf("get default kubernetes config: %w", err)
	}
	return restConfig, nil
}
