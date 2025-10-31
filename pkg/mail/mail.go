package mail

import (
	"crypto/tls"
	"log"

	"gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/pkg/config"
	"gopkg.in/gomail.v2"
)

type Sender interface {
	Send(receivers []string, subject, body string) error
	GetHost() string
	GetPort() int
}

type sender struct {
	dialer        *gomail.Dialer
	senderAddress string
	senderName    string
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

	return &sender{
		dialer:        d,
		senderAddress: senderAddr,
		senderName:    senderName,
	}
}

func (s *sender) Send(receivers []string, subject, body string) error {
	log.Printf("[mail] Preparing to send mail to %d receivers. Subject: %s", len(receivers), subject)
	msg := gomail.NewMessage()
	msg.SetAddressHeader("From", s.senderAddress, s.senderName)
	msg.SetHeader("Bcc", receivers...)
	msg.SetHeader("Subject", subject)
	msg.SetBody("text/html", body)
	err := s.dialer.DialAndSend(msg)
	if err != nil {
		log.Printf("[mail] Failed to send mail: %v", err)
	} else {
		log.Printf("[mail] Mail sent successfully to %d receivers", len(receivers))
	}
	return err
}

func (s *sender) GetHost() string {
	return s.dialer.Host
}

func (s *sender) GetPort() int {
	return s.dialer.Port
}
