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

	apiextensionsinternal "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	apiextensionsinstall "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/install"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextensionsvalidation "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/validation"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/util/validation/field"
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
}
