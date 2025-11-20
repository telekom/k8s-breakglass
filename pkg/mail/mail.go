package mail

import (
	"crypto/tls"
	"fmt"
	"log"
	"math"
	"time"

	"github.com/telekom/k8s-breakglass/pkg/config"
	"github.com/telekom/k8s-breakglass/pkg/metrics"
	"gopkg.in/gomail.v2"
)

type Sender interface {
	Send(receivers []string, subject, body string) error
	GetHost() string
	GetPort() int
}

type sender struct {
	dialer         *gomail.Dialer
	senderAddress  string
	senderName     string
	retryCount     int
	retryBackoffMs int
}

// NewSenderFromMailProvider creates a mail sender from MailProvider configuration
func NewSenderFromMailProvider(mpConfig *config.MailProviderConfig, brandingName string) Sender {
	log.Printf("[mail] Initializing mail sender from MailProvider: %s (host: %s, port: %d)",
		mpConfig.Name, mpConfig.Host, mpConfig.Port)

	d := gomail.NewDialer(mpConfig.Host, mpConfig.Port, mpConfig.Username, mpConfig.Password)

	if mpConfig.InsecureSkipVerify {
		log.Printf("[mail] InsecureSkipVerify is enabled for mail TLS connection")
		d.TLSConfig = &tls.Config{InsecureSkipVerify: true}
	}

	// Use provider's sender configuration
	senderAddr := mpConfig.SenderAddress
	if senderAddr == "" {
		senderAddr = "noreply@breakglass.local"
	}

	senderName := mpConfig.SenderName
	if senderName == "" && brandingName != "" {
		senderName = brandingName
	}
	if senderName == "" {
		senderName = "Breakglass"
	}

	retryCount := mpConfig.RetryCount
	if retryCount <= 0 {
		retryCount = 3
	}

	retryBackoffMs := mpConfig.RetryBackoffMs
	if retryBackoffMs <= 0 {
		retryBackoffMs = 100
	}

	log.Printf("[mail] Retry configuration: count=%d, initialBackoffMs=%d", retryCount, retryBackoffMs)

	return &sender{
		dialer:         d,
		senderAddress:  senderAddr,
		senderName:     senderName,
		retryCount:     retryCount,
		retryBackoffMs: retryBackoffMs,
	}
}

func (s *sender) Send(receivers []string, subject, body string) error {
	// Validate receivers
	if len(receivers) == 0 {
		log.Printf("[mail] ERROR: Send called with no receivers. Subject: %s", subject)
		return fmt.Errorf("cannot send email with no receivers")
	}

	log.Printf("[mail] Preparing to send mail to %d receivers. Subject: %s", len(receivers), subject)
	msg := gomail.NewMessage()
	msg.SetAddressHeader("From", s.senderAddress, s.senderName)
	msg.SetHeader("Bcc", receivers...)
	msg.SetHeader("Subject", subject)
	msg.SetBody("text/html", body)

	var lastErr error
	backoffMs := s.retryBackoffMs

	for attempt := 0; attempt <= s.retryCount; attempt++ {
		err := s.dialer.DialAndSend(msg)
		if err == nil {
			log.Printf("[mail] Mail sent successfully to %d receivers on attempt %d", len(receivers), attempt+1)
			metrics.MailSendSuccess.WithLabelValues(s.GetHost()).Inc()
			return nil
		}

		lastErr = err
		if attempt < s.retryCount {
			log.Printf("[mail] Send attempt %d failed: %v. Retrying in %dms...", attempt+1, err, backoffMs)
			time.Sleep(time.Duration(backoffMs) * time.Millisecond)
			// Exponential backoff: backoff = backoff * 2^attempt (capped at reasonable values)
			backoffMs = int(math.Min(float64(backoffMs)*2, 32000)) // Cap at ~32 seconds
		} else {
			log.Printf("[mail] Failed to send mail after %d attempts: %v", s.retryCount+1, err)
		}
	}

	metrics.MailSendFailure.WithLabelValues(s.GetHost()).Inc()
	return lastErr
}

func (s *sender) GetHost() string {
	return s.dialer.Host
}

func (s *sender) GetPort() int {
	return s.dialer.Port
}
