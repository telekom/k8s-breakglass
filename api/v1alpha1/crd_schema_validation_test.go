// SPDX-FileCopyrightText: 2025 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apiextensionsinternal "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	apiextensionsinstall "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/install"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextensionsvalidation "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/validation"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

// crdBasesDir returns the path to config/crd/bases relative to the test file.
func crdBasesDir() string {
	return filepath.Join("..", "..", "config", "crd", "bases")
}

// TestCRDSchemaValidation validates all generated CRD manifests using the same
// Kubernetes API server validation logic that runs during kubectl apply. This
// catches issues like CEL expression cost budget overruns, invalid schemas, and
// structural errors — without requiring a running cluster.
func TestCRDSchemaValidation(t *testing.T) {
	scheme := runtime.NewScheme()
	apiextensionsinstall.Install(scheme)
	codecs := serializer.NewCodecFactory(scheme)

	crdDir := crdBasesDir()

	entries, err := os.ReadDir(crdDir)
	if err != nil {
		t.Fatalf("cannot read CRD directory %s (run 'make manifests' first): %v", crdDir, err)
	}

	var crdFiles []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".yaml") {
			crdFiles = append(crdFiles, filepath.Join(crdDir, entry.Name()))
		}
	}

	if len(crdFiles) == 0 {
		t.Fatal("no CRD YAML files found; run 'make manifests' first")
	}

	for _, crdFile := range crdFiles {
		name := filepath.Base(crdFile)
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(crdFile)
			if err != nil {
				t.Fatalf("failed to read %s: %v", crdFile, err)
			}

			// Decode the v1 CRD
			obj, gvk, err := codecs.UniversalDeserializer().Decode(data, nil, nil)
			if err != nil {
				t.Fatalf("failed to decode CRD YAML: %v", err)
			}

			v1CRD, ok := obj.(*apiextensionsv1.CustomResourceDefinition)
			if !ok {
				t.Fatalf("decoded object is %T (GVK: %v), expected *v1.CustomResourceDefinition", obj, gvk)
			}

			// Convert v1 → internal type for validation
			internalCRD := &apiextensionsinternal.CustomResourceDefinition{}
			if err := scheme.Convert(v1CRD, internalCRD, nil); err != nil {
				t.Fatalf("failed to convert CRD to internal type: %v", err)
			}

			// Set required metadata that the validator expects
			if internalCRD.Name == "" {
				internalCRD.Name = fmt.Sprintf("%s.%s", internalCRD.Spec.Names.Plural, internalCRD.Spec.Group)
			}

			// Run the full Kubernetes CRD validation (includes CEL cost estimation)
			errs := apiextensionsvalidation.ValidateCustomResourceDefinition(context.Background(), internalCRD)

			// Filter for actionable errors (skip metadata/status warnings from offline validation)
			var serious []field.Error
			for _, e := range errs {
				// Skip errors about status.storedVersions — not populated offline
				if strings.Contains(e.Field, "status.storedVersions") {
					continue
				}
				serious = append(serious, *e)
			}

			if len(serious) > 0 {
				t.Errorf("CRD %s has %d validation error(s):", name, len(serious))
				for _, e := range serious {
					t.Errorf("  [%s] %s: %s", e.Type, e.Field, e.Detail)
				}
			}
		})
	}
}

// TestCRDInstallation installs all CRDs into a real envtest API server to
// validate that they are accepted (CEL cost, structural schema, conversion).
// This is the canonical validation — identical to what happens during
// kubectl apply or Helm install against a real cluster.
//
// Requires KUBEBUILDER_ASSETS to be set (run: make validate-crds).
// Skips gracefully when envtest binaries are not available.
func TestCRDInstallation(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("KUBEBUILDER_ASSETS not set; run 'make validate-crds' or set up envtest")
	}

	crdDir := crdBasesDir()

	entries, err := os.ReadDir(crdDir)
	if err != nil {
		t.Fatalf("cannot read CRD directory %s (run 'make manifests' first): %v", crdDir, err)
	}

	var crdCount int
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".yaml") {
			crdCount++
		}
	}

	if crdCount == 0 {
		t.Fatal("no CRD YAML files found; run 'make manifests' first")
	}

	testEnv := &envtest.Environment{
		CRDDirectoryPaths:     []string{crdDir},
		ErrorIfCRDPathMissing: true,
	}

	cfg, err := testEnv.Start()
	if err != nil {
		t.Fatalf("failed to start envtest / install CRDs: %v", err)
	}

	t.Cleanup(func() {
		if stopErr := testEnv.Stop(); stopErr != nil {
			t.Errorf("failed to stop envtest: %v", stopErr)
		}
	})

	if cfg == nil {
		t.Fatal("envtest returned nil config")
	}

	t.Logf("envtest API server started — all %d CRDs installed successfully", crdCount)

	t.Run("binding hidden field survives create and update", func(t *testing.T) {
		scheme := runtime.NewScheme()
		require.NoError(t, corev1.AddToScheme(scheme))
		require.NoError(t, AddToScheme(scheme))
		apiClient, err := client.New(cfg, client.Options{Scheme: scheme})
		require.NoError(t, err)
		ctx := context.Background()
		namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{GenerateName: "binding-schema-"}}
		require.NoError(t, apiClient.Create(ctx, namespace))
		binding := &DebugSessionClusterBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "hidden-binding", Namespace: namespace.Name},
			Spec: DebugSessionClusterBindingSpec{
				TemplateRef: &TemplateReference{Name: "test-template"},
				Clusters:    []string{"test-cluster"},
				Hidden:      true,
			},
		}
		require.NoError(t, apiClient.Create(ctx, binding))
		var stored DebugSessionClusterBinding
		require.NoError(t, apiClient.Get(ctx, client.ObjectKeyFromObject(binding), &stored))
		require.True(t, stored.Spec.Hidden, "API server must preserve hidden on creation")
		stored.Spec.Hidden = false
		require.NoError(t, apiClient.Update(ctx, &stored))
		require.NoError(t, apiClient.Get(ctx, client.ObjectKeyFromObject(binding), &stored))
		require.False(t, stored.Spec.Hidden, "API server must preserve hidden on update")
	})
	t.Run("template and binding duration admission", func(t *testing.T) {
		scheme := runtime.NewScheme()
		require.NoError(t, corev1.AddToScheme(scheme))
		require.NoError(t, AddToScheme(scheme))
		apiClient, err := client.New(cfg, client.Options{Scheme: scheme})
		require.NoError(t, err)
		ctx := context.Background()
		namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{GenerateName: "duration-schema-"}}
		require.NoError(t, apiClient.Create(ctx, namespace))
		for _, value := range []string{"1w", "1y", "1.5h", ".5h", "1d1.5h", "500µs", "500μs", "1d500µs", "-1h", "1.5d", "1.5w", "1d.5h", "1d500μs"} {
			t.Run(value, func(t *testing.T) {
				valid := value != "-1h" && value != "1.5d" && value != "1.5w" && value != "1d.5h" && value != "1d500μs"
				constraints := &DebugSessionConstraints{MaxDuration: value, DefaultDuration: value}
				template := &DebugSessionTemplate{
					ObjectMeta: metav1.ObjectMeta{GenerateName: "duration-template-"},
					Spec:       DebugSessionTemplateSpec{PodTemplateRef: &DebugPodTemplateReference{Name: "debug-pod"}, Constraints: constraints},
				}
				result := ValidateDebugSessionTemplate(template)
				require.Equal(t, valid, result.IsValid(), result.ErrorMessage())
				binding := &DebugSessionClusterBinding{
					ObjectMeta: metav1.ObjectMeta{GenerateName: "duration-binding-", Namespace: namespace.Name},
					Spec:       DebugSessionClusterBindingSpec{TemplateRef: &TemplateReference{Name: "debug-template"}, Clusters: []string{"test-cluster"}, Constraints: constraints},
				}
				for _, object := range []client.Object{template, binding} {
					err := apiClient.Create(ctx, object)
					if valid {
						require.NoError(t, err)
					} else {
						require.Error(t, err)
						require.Contains(t, err.Error(), "constraints")
					}
				}
			})
		}
	})
}
