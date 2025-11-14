package cert

import (
	"fmt"
	"time"

	"github.com/open-policy-agent/cert-controller/pkg/rotator"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
)

// SetupRotator configures and registers the certificate rotator with the manager.
// It returns a channel that will be closed when the certificates are ready.
// The returned channel should be waited on before setting up webhooks.
func SetupRotator(
	mgr ctrl.Manager,
	webhookName string,
	restartOnRefresh bool,
	certCompleted chan struct{},
	namespace string,
	secretName string,
) (chan struct{}, error) {
	if mgr == nil {
		return nil, fmt.Errorf("manager is nil")
	}

	// Apply defaults if not provided
	if namespace == "" {
		namespace = "default"
	}
	if secretName == "" {
		secretName = "breakglass-webhook-certs"
	}

	serviceName := "breakglass-webhook-service"
	dnsName := serviceName + "." + namespace + ".svc"

	log := ctrl.Log.WithName("cert-rotator")
	log.Info("Setting up certificate rotation",
		"webhook", webhookName,
		"namespace", namespace,
		"serviceName", serviceName,
		"secretName", secretName,
		"dnsName", dnsName,
		"restartOnRefresh", restartOnRefresh)

	webhooks := []rotator.WebhookInfo{
		{
			Name: "breakglass-validating-webhook-configuration",
			Type: rotator.Validating,
		},
	}

	certRotator := &rotator.CertRotator{
		SecretKey: types.NamespacedName{
			Namespace: namespace,
			Name:      secretName,
		},
		CertDir:        "/tmp/k8s-webhook-server/serving-certs",
		CAName:         "breakglass-webhook-ca",
		CAOrganization: "Deutsche Telekom, Breakglass",
		DNSName:        dnsName,
		ExtraDNSNames: []string{
			serviceName + "." + namespace,
			serviceName,
		},
		IsReady:                certCompleted,
		RestartOnSecretRefresh: true,
		RequireLeaderElection:  false,
		Webhooks:               webhooks,
		// Certificate durations
		CaCertDuration:     10 * 365 * 24 * time.Hour, // 10 years
		ServerCertDuration: 365 * 24 * time.Hour,      // 1 year
		// Rotation check every 12 hours, rotate if within 30 days of expiration
		RotationCheckFrequency: 12 * time.Hour,
		LookaheadInterval:      30 * 24 * time.Hour,
	}

	if err := rotator.AddRotator(mgr, certRotator); err != nil {
		log.Error(err, "Failed to setup certificate rotator")
		return nil, fmt.Errorf("failed to add rotator: %w", err)
	}

	log.Info("✓ Certificate rotator added to manager successfully",
		"secretKey", fmt.Sprintf("%s/%s", certRotator.SecretKey.Namespace, certRotator.SecretKey.Name),
		"certDir", certRotator.CertDir,
		"dnsName", certRotator.DNSName,
		"webhookNames", fmt.Sprintf("%d webhooks", len(certRotator.Webhooks)),
		"caCertDuration", certRotator.CaCertDuration,
		"serverCertDuration", certRotator.ServerCertDuration,
		"rotationCheckFrequency", certRotator.RotationCheckFrequency,
		"lookaheadInterval", certRotator.LookaheadInterval)

	log.Info("Certificate rotator is now monitoring for cert-rotator controller to generate certificates",
		"isReady_channel", "waiting for signal",
		"note", "certCompleted channel will be closed when certificates are ready")

	return certCompleted, nil
}
