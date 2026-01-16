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

package helpers

import (
	"os"
	"path/filepath"
	"testing"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"sigs.k8s.io/controller-runtime/pkg/client"

	telekomv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
)

var (
	fixtureScheme  *runtime.Scheme
	fixtureDecoder runtime.Decoder
)

func init() {
	fixtureScheme = runtime.NewScheme()
	_ = telekomv1alpha1.AddToScheme(fixtureScheme)
	fixtureDecoder = serializer.NewCodecFactory(fixtureScheme).UniversalDeserializer()
}

// FixturesDir returns the path to the fixtures directory.
// It searches relative to the test file location.
func FixturesDir() string {
	// Try common paths
	paths := []string{
		"fixtures",
		"../fixtures",
		"e2e/fixtures",
		"../../e2e/fixtures",
	}

	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			abs, _ := filepath.Abs(p)
			return abs
		}
	}

	// Default to fixtures in current directory
	return "fixtures"
}

// LoadFixture loads a YAML fixture file and returns the decoded object.
// The fixture path is relative to the fixtures directory.
//
// Example:
//
//	escalation := helpers.LoadFixture[*telekomv1alpha1.BreakglassEscalation](t, "escalations/pod-debug.yaml")
func LoadFixture[T client.Object](t *testing.T, relativePath string) T {
	t.Helper()

	fullPath := filepath.Join(FixturesDir(), relativePath)
	data, err := os.ReadFile(fullPath)
	if err != nil {
		t.Fatalf("Failed to read fixture %s: %v", fullPath, err)
	}

	obj, _, err := fixtureDecoder.Decode(data, nil, nil)
	if err != nil {
		t.Fatalf("Failed to decode fixture %s: %v", fullPath, err)
	}

	result, ok := obj.(T)
	if !ok {
		t.Fatalf("Fixture %s is not of expected type, got %T", fullPath, obj)
	}

	return result
}

// LoadFixtureWithName loads a fixture and sets a custom name.
// Useful for creating unique resources from a template fixture.
//
// Example:
//
//	escalation := helpers.LoadFixtureWithName[*telekomv1alpha1.BreakglassEscalation](
//	    t, "escalations/pod-debug.yaml", helpers.GenerateUniqueName("test"))
func LoadFixtureWithName[T client.Object](t *testing.T, relativePath, name string) T {
	t.Helper()

	obj := LoadFixture[T](t, relativePath)
	obj.SetName(name)
	return obj
}

// LoadFixtureWithNamespace loads a fixture and sets a custom namespace.
func LoadFixtureWithNamespace[T client.Object](t *testing.T, relativePath, namespace string) T {
	t.Helper()

	obj := LoadFixture[T](t, relativePath)
	obj.SetNamespace(namespace)
	return obj
}

// LoadFixtureCustomized loads a fixture and applies a customization function.
// This is the most flexible option for modifying loaded fixtures.
//
// Example:
//
//	escalation := helpers.LoadFixtureCustomized(t, "escalations/pod-debug.yaml",
//	    func(e *telekomv1alpha1.BreakglassEscalation) {
//	        e.Name = helpers.GenerateUniqueName("test")
//	        e.Spec.Allowed.Clusters = []string{"my-cluster"}
//	    })
func LoadFixtureCustomized[T client.Object](t *testing.T, relativePath string, customize func(T)) T {
	t.Helper()

	obj := LoadFixture[T](t, relativePath)
	customize(obj)
	return obj
}

// MustLoadFixture is like LoadFixture but returns the object directly.
// Panics if loading fails (suitable for init or package-level vars).
func MustLoadFixture[T client.Object](relativePath string) T {
	fullPath := filepath.Join(FixturesDir(), relativePath)
	data, err := os.ReadFile(fullPath)
	if err != nil {
		panic("Failed to read fixture " + fullPath + ": " + err.Error())
	}

	obj, _, err := fixtureDecoder.Decode(data, nil, nil)
	if err != nil {
		panic("Failed to decode fixture " + fullPath + ": " + err.Error())
	}

	result, ok := obj.(T)
	if !ok {
		panic("Fixture " + fullPath + " is not of expected type")
	}

	return result
}
