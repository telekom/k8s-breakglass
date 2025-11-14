package cert

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/go-logr/logr"
	"github.com/open-policy-agent/cert-controller/pkg/rotator"
	corev1 "k8s.io/api/core/v1"
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
	serviceName := "breakglass-webhook-service"
	dnsName := serviceName + "." + podNamespace + ".svc"

	log := ctrl.Log.WithName("cert-rotator")
	log.Info("Setting up certificate rotation",
		"webhook", webhookName,
		"namespace", podNamespace,
		"serviceName", serviceName,
		"secretName", secretName,
		"dnsName", dnsName,
		"restartOnRefresh", restartOnRefresh)

	webhooks := []rotator.WebhookInfo{
		{
			Name: "breakglass-validating-session-webhook",
			Type: rotator.Validating,
		},
		{
			Name: "breakglass-validating-escalation-webhook",
			Type: rotator.Validating,
		},
		{
			Name: "breakglass-validating-clusterconfig-webhook",
			Type: rotator.Validating,
		},
		{
			Name: "breakglass-validating-identityprovider-webhook",
			Type: rotator.Validating,
		},
	}

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
			serviceName + "." + podNamespace,
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

	// Start background goroutine to monitor certificate readiness status
	go monitorCertificateReadiness(mgr, log, podNamespace, secretName)

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

// monitorCertificateReadiness monitors the certificate secret and logs diagnostic information
func monitorCertificateReadiness(mgr ctrl.Manager, log logr.Logger, namespace, secretName string) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		secret := &corev1.Secret{}
		secretKey := types.NamespacedName{
			Name:      secretName,
			Namespace: namespace,
		}

		if err := mgr.GetClient().Get(context.Background(), secretKey, secret); err != nil {
			log.Error(err, "Failed to check certificate secret status",
				"secret", secretName,
				"namespace", namespace,
				"check_reason", "monitoring_certificate_generation")
		} else {
			// Check if secret has certificate data
			hasTLSCrt := len(secret.Data["tls.crt"]) > 0
			hasTLSKey := len(secret.Data["tls.key"]) > 0
			hasCACrt := len(secret.Data["ca.crt"]) > 0
			hasCAKey := len(secret.Data["ca.key"]) > 0

			if hasTLSCrt && hasTLSKey && hasCACrt && hasCAKey {
				log.V(1).Info("✓ Certificate secret contains all required certificate data",
					"secret", secretName,
					"namespace", namespace,
					"tls.crt_size", len(secret.Data["tls.crt"]),
					"tls.key_size", len(secret.Data["tls.key"]),
					"ca.crt_size", len(secret.Data["ca.crt"]),
					"ca.key_size", len(secret.Data["ca.key"]))
			} else {
				log.Info("⚠️  Certificate secret missing some certificate data",
					"secret", secretName,
					"namespace", namespace,
					"has_tls.crt", hasTLSCrt,
					"has_tls.key", hasTLSKey,
					"has_ca.crt", hasCACrt,
					"has_ca.key", hasCAKey,
					"total_keys", len(secret.Data))
			}
		}
	}
}
