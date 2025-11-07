package mail

import (
	"crypto/tls"
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

func NewSender(cfg config.Config) Sender {
	log.Printf("[mail] Initializing new mail sender for host: %s, port: %d, user: %s", cfg.Mail.Host, cfg.Mail.Port, cfg.Mail.User)
	d := gomail.NewDialer(cfg.Mail.Host, cfg.Mail.Port, cfg.Mail.User, cfg.Mail.Password)
	if cfg.Mail.InsecureSkipVerify {
		log.Printf("[mail] InsecureSkipVerify is enabled for mail TLS connection")
		d.TLSConfig = &tls.Config{InsecureSkipVerify: true}
	}
	// Determine sender address and name, use sensible defaults when missing
	senderAddr := cfg.Mail.SenderAddress
	if senderAddr == "" {
		senderAddr = "noreply@schiff.telekom.de"
	}
	senderName := cfg.Mail.SenderName
	if senderName == "" && cfg.Frontend.BrandingName != "" {
		senderName = cfg.Frontend.BrandingName
	}
	if senderName == "" {
		senderName = "Breakglass"
	}

	// Set retry defaults if not configured
	retryCount := cfg.Mail.RetryCount
	if retryCount <= 0 {
		retryCount = 3
	}
	retryBackoffMs := cfg.Mail.RetryBackoffMs
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
