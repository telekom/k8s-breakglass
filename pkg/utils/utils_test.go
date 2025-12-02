package utils

import (
	"testing"

	"github.com/telekom/k8s-breakglass/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
)

func TestSetupLogger_DebugMode(t *testing.T) {
	// debug true should return a non-nil logger
	logger, _ := SetupLogger(true)
	if logger == nil {
		t.Fatalf("expected non-nil logger for debug mode")
	}
	// best-effort flush
	_ = logger.Sync()
}

func TestSetupLogger_ProductionMode(t *testing.T) {
	// debug false should return a non-nil logger
	logger, _ := SetupLogger(false)
	if logger == nil {
		t.Fatalf("expected non-nil logger for production mode")
	}
	_ = logger.Sync()
}

func TestCreateScheme(t *testing.T) {
	// Create scheme once and reuse across all subtests for better performance
	scheme, err := CreateScheme()
	if err != nil {
		t.Fatalf("CreateScheme() error = %v", err)
	}
	if scheme == nil {
		t.Fatal("CreateScheme() returned nil scheme")
	}

	t.Run("scheme contains corev1 types", func(t *testing.T) {
		// Check that corev1.Secret is known to the scheme
		gvk := corev1.SchemeGroupVersion.WithKind("Secret")
		if !scheme.Recognizes(gvk) {
			t.Errorf("scheme does not recognize corev1.Secret")
		}
	})

	t.Run("scheme contains v1alpha1 types", func(t *testing.T) {
		// Check that BreakglassSession is known to the scheme
		gvk := v1alpha1.GroupVersion.WithKind("BreakglassSession")
		if !scheme.Recognizes(gvk) {
			t.Errorf("scheme does not recognize BreakglassSession")
		}
	})

	t.Run("scheme contains IdentityProvider type", func(t *testing.T) {
		gvk := v1alpha1.GroupVersion.WithKind("IdentityProvider")
		if !scheme.Recognizes(gvk) {
			t.Errorf("scheme does not recognize IdentityProvider")
		}
	})

	t.Run("scheme contains ClusterConfig type", func(t *testing.T) {
		gvk := v1alpha1.GroupVersion.WithKind("ClusterConfig")
		if !scheme.Recognizes(gvk) {
			t.Errorf("scheme does not recognize ClusterConfig")
		}
	})

	t.Run("scheme contains BreakglassEscalation type", func(t *testing.T) {
		gvk := v1alpha1.GroupVersion.WithKind("BreakglassEscalation")
		if !scheme.Recognizes(gvk) {
			t.Errorf("scheme does not recognize BreakglassEscalation")
		}
	})

	t.Run("scheme contains DenyPolicy type", func(t *testing.T) {
		gvk := v1alpha1.GroupVersion.WithKind("DenyPolicy")
		if !scheme.Recognizes(gvk) {
			t.Errorf("scheme does not recognize DenyPolicy")
		}
	})

	t.Run("scheme contains MailProvider type", func(t *testing.T) {
		gvk := v1alpha1.GroupVersion.WithKind("MailProvider")
		if !scheme.Recognizes(gvk) {
			t.Errorf("scheme does not recognize MailProvider")
		}
	})
}
