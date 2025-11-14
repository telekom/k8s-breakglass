package cert

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/open-policy-agent/cert-controller/pkg/rotator"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
)

// SetupRotator configures and registers the certificate rotator with the manager.
// It returns a channel that will be closed when the certificates are ready.
// The returned channel should be waited on before setting up webhooks.
// The webhook secret name can be customized via WEBHOOK_SECRET_NAME environment variable (defaults to "webhook-certs").
func SetupRotator(
	mgr ctrl.Manager,
	webhookName string,
	restartOnRefresh bool,
	certCompleted chan struct{},
) (chan struct{}, error) {
	if mgr == nil {
		return nil, fmt.Errorf("manager is nil")
	}

	podNamespace := getEnvOrDefault("POD_NAMESPACE", "system")
	secretName := getEnvOrDefault("WEBHOOK_SECRET_NAME", "webhook-certs")
	dnsName := "webhook-service." + podNamespace + ".svc"

	log := ctrl.Log.WithName("cert-rotator")
	log.Info("Setting up certificate rotation",
		"webhook", webhookName,
		"namespace", podNamespace,
		"secretName", secretName,
		"dnsName", dnsName,
		"restartOnRefresh", restartOnRefresh)

	certRotator := &rotator.CertRotator{
		SecretKey: types.NamespacedName{
			Namespace: podNamespace,
			Name:      secretName,
		},
		CertDir:        "/tmp/k8s-webhook-server/serving-certs",
		CAName:         "breakglass-webhook-ca",
		CAOrganization: "Deutsche Telekom, Breakglass",
		DNSName:        dnsName,
		ExtraDNSNames: []string{
			"webhook-service." + podNamespace,
			"webhook-service",
		},
		IsReady:                certCompleted,
		RestartOnSecretRefresh: restartOnRefresh,
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

	log.Info("Certificate rotator configured successfully",
		"secretKey", fmt.Sprintf("%s/%s", certRotator.SecretKey.Namespace, certRotator.SecretKey.Name),
		"certDir", certRotator.CertDir,
		"dnsName", certRotator.DNSName,
		"caCertDuration", certRotator.CaCertDuration,
		"serverCertDuration", certRotator.ServerCertDuration,
		"rotationCheckFrequency", certRotator.RotationCheckFrequency,
		"lookaheadInterval", certRotator.LookaheadInterval)
	return certCompleted, nil
}

// WaitForExit waits for either setup or manager errors and handles graceful shutdown.
func WaitForExit(setupErr, mgrErr chan error, cancel context.CancelFunc) error {
	log := ctrl.Log.WithName("cert-controller")

	for {
		select {
		case err := <-setupErr:
			if err != nil {
				log.Error(err, "Setup failed")
				cancel()
				return err
			}
			log.Info("Setup completed successfully")
		case err := <-mgrErr:
			if err != nil {
				log.Error(err, "Manager error")
				return err
			}
			log.Info("Manager stopped")
			return nil
		}
	}
}

// getEnvOrDefault gets an environment variable or returns the default value.
func getEnvOrDefault(key, defaultValue string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return defaultValue
}
