/*
Copyright 2026 Deutsche Telekom AG

SPDX-License-Identifier: Apache-2.0
*/

package config

import (
	"bytes"
	"os"
	"path/filepath"
	stdRuntime "runtime"
	"strings"
	"testing"

	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apimachinery/pkg/util/yaml"
	apiserver "k8s.io/apiserver/pkg/apis/apiserver"
	apiserverinstall "k8s.io/apiserver/pkg/apis/apiserver/install"
	"k8s.io/apiserver/pkg/apis/apiserver/validation"
	"k8s.io/apiserver/pkg/authorization/cel"
)

func TestShippedAuthorizationConfigurationsParseAndValidate(t *testing.T) {
	root := repositoryRoot(t)
	paths := []string{
		"README.md",
		"docs/auth-operator-integration.md",
		"docs/cluster-config.md",
		"docs/end-to-end-example.md",
		"docs/installation.md",
		"docs/quickstart.md",
		"docs/webhook-setup.md",
		"utils/config/authorization-configuration.yaml",
	}

	scheme := k8sruntime.NewScheme()
	apiserverinstall.Install(scheme)
	codecs := serializer.NewCodecFactory(scheme)
	knownTypes := sets.New[string]("Node", "RBAC", "Webhook")
	repeatableTypes := sets.New[string]()
	kubeconfig, err := os.CreateTemp("", "breakglass-authz-kubeconfig-")
	if err != nil {
		t.Fatal(err)
	}
	kubeconfigPath := kubeconfig.Name()
	if err := kubeconfig.Close(); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(kubeconfigPath)

	for _, relativePath := range paths {
		t.Run(relativePath, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(root, relativePath))
			if err != nil {
				t.Fatal(err)
			}
			blocks := authorizationConfigurationBlocks(data, strings.HasSuffix(relativePath, ".yaml"))
			if len(blocks) == 0 {
				t.Fatal("no AuthorizationConfiguration document found")
			}
			for index, block := range blocks {
				var internal apiserver.AuthorizationConfiguration
				jsonData, err := yaml.ToJSON(block)
				if err != nil {
					t.Fatalf("convert block %d to JSON: %v", index, err)
				}
				if err := k8sruntime.DecodeInto(codecs.UniversalDecoder(), jsonData, &internal); err != nil {
					t.Fatalf("decode block %d: %v", index, err)
				}
				scheme.Default(&internal)
				webhook := findWebhook(&internal)
				if webhook == nil {
					t.Fatal("configuration has no webhook authorizer")
				}
				// Kubernetes validation checks that the referenced file exists. The
				// snippets intentionally use deployment-specific absolute paths, so
				// point the decoded object at a disposable file for semantic validation.
				webhook.ConnectionInfo.KubeConfigFile = &kubeconfigPath
				if errors := validation.ValidateAuthorizationConfiguration(
					cel.NewDefaultCompiler(),
					field.NewPath("authorization"), &internal, knownTypes, repeatableTypes,
				); len(errors) != 0 {
					t.Fatalf("revalidate block %d with test kubeconfig: %v", index, errors)
				}
				if webhook.CacheAuthorizedRequests {
					t.Fatalf("positive authorization cache must be explicitly disabled after decode/defaulting")
				}
			}
		})
	}
}

func TestAuthorizationConfigurationDefaultingDoesNotDisablePositiveCache(t *testing.T) {
	scheme := k8sruntime.NewScheme()
	apiserverinstall.Install(scheme)
	codecs := serializer.NewCodecFactory(scheme)
	var internal apiserver.AuthorizationConfiguration
	data := []byte(`apiVersion: apiserver.config.k8s.io/v1
kind: AuthorizationConfiguration
authorizers:
- type: Webhook
  name: breakglass
  webhook:
    authorizedTTL: 5m
    unauthorizedTTL: 30s
    timeout: 3s
    subjectAccessReviewVersion: v1
    failurePolicy: Deny
    connectionInfo:
      type: KubeConfigFile
      kubeConfigFile: /etc/kubernetes/breakglass-webhook.kubeconfig
`)
	jsonData, err := yaml.ToJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	if err := k8sruntime.DecodeInto(codecs.UniversalDecoder(), jsonData, &internal); err != nil {
		t.Fatal(err)
	}
	scheme.Default(&internal)
	webhook := findWebhook(&internal)
	if webhook == nil || !webhook.CacheAuthorizedRequests {
		t.Fatal("Kubernetes defaults omitted positive cache control to enabled; shipped configs must set false explicitly")
	}
}

func findWebhook(configuration *apiserver.AuthorizationConfiguration) *apiserver.WebhookConfiguration {
	for index := range configuration.Authorizers {
		if configuration.Authorizers[index].Type == apiserver.TypeWebhook {
			return configuration.Authorizers[index].Webhook
		}
	}
	return nil
}

func authorizationConfigurationBlocks(data []byte, rawYAML bool) [][]byte {
	if rawYAML {
		return [][]byte{data}
	}
	var blocks [][]byte
	for _, part := range bytes.Split(data, []byte("```yaml")) {
		if !bytes.Contains(part, []byte("kind: AuthorizationConfiguration")) {
			continue
		}
		if end := bytes.Index(part, []byte("```")); end >= 0 {
			blocks = append(blocks, bytes.TrimSpace(part[:end]))
		}
	}
	return blocks
}

func repositoryRoot(t *testing.T) string {
	_, filename, _, ok := stdRuntime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(filename), "..", ".."))
}
