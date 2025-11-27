package config

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestValidateMailProviderRef(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))

	enabledProvider := &breakglassv1alpha1.MailProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "mail-enabled"},
		Spec: breakglassv1alpha1.MailProviderSpec{
			SMTP:   breakglassv1alpha1.SMTPConfig{Host: "smtp.enabled", Port: 587},
			Sender: breakglassv1alpha1.SenderConfig{Address: "noreply@enabled"},
		},
	}

	disabledProvider := &breakglassv1alpha1.MailProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "mail-disabled"},
		Spec: breakglassv1alpha1.MailProviderSpec{
			Disabled: true,
			SMTP:     breakglassv1alpha1.SMTPConfig{Host: "smtp.disabled", Port: 587},
			Sender:   breakglassv1alpha1.SenderConfig{Address: "noreply@disabled"},
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(enabledProvider, disabledProvider).Build()
	reconciler := &EscalationReconciler{client: fakeClient}

	tests := []struct {
		name         string
		mailProvider string
		expectErr    bool
	}{
		{name: "no mail provider configured", mailProvider: "", expectErr: false},
		{name: "enabled provider", mailProvider: "mail-enabled", expectErr: false},
		{name: "missing provider", mailProvider: "does-not-exist", expectErr: true},
		{name: "disabled provider", mailProvider: "mail-disabled", expectErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			esc := &breakglassv1alpha1.BreakglassEscalation{
				Spec: breakglassv1alpha1.BreakglassEscalationSpec{MailProvider: tt.mailProvider},
			}

			err := reconciler.validateMailProviderRef(context.Background(), esc)
			if tt.expectErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
