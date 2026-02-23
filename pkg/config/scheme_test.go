// SPDX-FileCopyrightText: 2025 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
)

// Scheme is a test-only runtime.Scheme with all required types registered.
// Production code receives the scheme via dependency injection.
var Scheme = runtime.NewScheme()

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(Scheme))
	utilruntime.Must(breakglassv1alpha1.AddToScheme(Scheme))
}
