package mail

import (
	"context"
	"crypto/tls"
	"fmt"
	"math"
	"net"
	"net/smtp"
	"strings"
	"time"

	"github.com/telekom/k8s-breakglass/pkg/config"
	"github.com/telekom/k8s-breakglass/pkg/metrics"
	"go.uber.org/zap"
	"gopkg.in/gomail.v2"
	"sigs.k8s.io/controller-runtime/pkg/client"
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
	disableTLS     bool // when true, use plain SMTP without STARTTLS
	host           string
	port           int
	username       string
	password       string
	log            *zap.SugaredLogger
}

// sanitizeHeaderValue removes all ASCII control characters from header values
// to prevent email header injection attacks. This includes CR, LF, NUL, and
// other control characters (0x00-0x1F and 0x7F) that could be used to inject
// additional headers or break MIME structure.
func sanitizeHeaderValue(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		ch := s[i]
		// Skip ASCII control characters (0x00-0x1F) and DEL (0x7F)
		if ch < 0x20 || ch == 0x7F {
			continue
		}
		b.WriteByte(ch)
	}
	return b.String()
}

// sanitizeBodyValue normalizes the message body to avoid accidentally breaking the
// MIME structure when constructing raw messages. It preserves HTML content while
// removing bare CR characters that could interfere with SMTP parsing.
func sanitizeBodyValue(s string) string {
	// Remove carriage returns; SMTP line endings will be added by fmt.Sprintf template.
	s = strings.ReplaceAll(s, "\r", "")
	return s
}

// NewSenderFromMailProvider creates a mail sender from MailProvider configuration.
// The optional logger parameter allows structured logging; if nil, a default logger is used.
func NewSenderFromMailProvider(mpConfig *config.MailProviderConfig, brandingName string, logger ...*zap.SugaredLogger) Sender {
	var log *zap.SugaredLogger
	if len(logger) > 0 && logger[0] != nil {
		log = logger[0].Named("mail")
	} else {
		log = zap.S().Named("mail")
	}

	log.Infow("Initializing mail sender from MailProvider",
		"provider", mpConfig.Name,
		"host", mpConfig.Host,
		"port", mpConfig.Port,
		"disableTLS", mpConfig.DisableTLS)

	d := gomail.NewDialer(mpConfig.Host, mpConfig.Port, mpConfig.Username, mpConfig.Password)

	if mpConfig.InsecureSkipVerify {
		log.Warnw("InsecureSkipVerify is enabled for mail TLS connection - not recommended for production")
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

	log.Debugw("Retry configuration",
		"retryCount", retryCount,
		"initialBackoffMs", retryBackoffMs)

	return &sender{
		dialer:         d,
		senderAddress:  senderAddr,
		senderName:     senderName,
		retryCount:     retryCount,
		retryBackoffMs: retryBackoffMs,
		disableTLS:     mpConfig.DisableTLS,
		host:           mpConfig.Host,
		port:           mpConfig.Port,
		username:       mpConfig.Username,
		password:       mpConfig.Password,
		log:            log,
	}
}

func (s *sender) Send(receivers []string, subject, body string) error {
	// Validate receivers
	if len(receivers) == 0 {
		s.log.Errorw("Send called with no receivers",
			"subjectLength", len(subject)) // Don't log raw subject for privacy
		return fmt.Errorf("cannot send email with no receivers")
	}

	// Sanitize subject to prevent email header injection
	// Subject is a header value and must not contain CRLF characters
	safeSubject := sanitizeHeaderValue(subject)

	// Sanitize body to prevent MIME structure manipulation
	// This removes bare CR characters that could break email parsing
	safeBody := sanitizeBodyValue(body)

	s.log.Debugw("Preparing to send mail",
		"recipientCount", len(receivers),
		"subjectLength", len(safeSubject)) // Don't log raw subject/addresses for privacy

	var lastErr error
	backoffMs := s.retryBackoffMs

	for attempt := 0; attempt <= s.retryCount; attempt++ {
		var err error
		if s.disableTLS {
			// Use plain SMTP without STARTTLS (for MailHog and similar dev servers)
			err = s.sendPlainSMTP(receivers, safeSubject, safeBody)
		} else {
			// Use gomail with TLS/STARTTLS support
			msg := gomail.NewMessage()
			msg.SetAddressHeader("From", s.senderAddress, s.senderName)
			msg.SetHeader("Bcc", receivers...)
			msg.SetHeader("Subject", safeSubject)
			msg.SetBody("text/html", safeBody)
			err = s.dialer.DialAndSend(msg)
		}

		if err == nil {
			s.log.Infow("Mail sent successfully",
				"recipientCount", len(receivers),
				"attempt", attempt+1)
			metrics.MailSendSuccess.WithLabelValues(s.GetHost()).Inc()
			return nil
		}

		lastErr = err
		if attempt < s.retryCount {
			s.log.Warnw("Send attempt failed, retrying",
				"attempt", attempt+1,
				"error", err,
				"retryInMs", backoffMs)
			time.Sleep(time.Duration(backoffMs) * time.Millisecond)
			// Exponential backoff: backoff = backoff * 2^attempt (capped at reasonable values)
			backoffMs = int(math.Min(float64(backoffMs)*2, 32000)) // Cap at ~32 seconds
		} else {
			s.log.Errorw("Failed to send mail after all attempts",
				"attempts", s.retryCount+1,
				"error", err)
		}
	}

	metrics.MailSendFailure.WithLabelValues(s.GetHost()).Inc()
	return lastErr
}

// sendPlainSMTP sends email using plain SMTP without STARTTLS
// This is used for development SMTP servers like MailHog that don't support TLS
func (s *sender) sendPlainSMTP(receivers []string, subject, body string) error {
	addr := net.JoinHostPort(s.host, fmt.Sprintf("%d", s.port))

	// Connect to the server
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return fmt.Errorf("failed to connect to SMTP server: %w", err)
	}
	defer func() { _ = conn.Close() }()

	// Create SMTP client
	client, err := smtp.NewClient(conn, s.host)
	if err != nil {
		return fmt.Errorf("failed to create SMTP client: %w", err)
	}
	defer func() { _ = client.Close() }()

	// Authenticate if credentials are provided
	if s.username != "" && s.password != "" {
		auth := smtp.PlainAuth("", s.username, s.password, s.host)
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("SMTP authentication failed: %w", err)
		}
	}

	// Set sender
	fromAddr := s.senderAddress
	if err := client.Mail(fromAddr); err != nil {
		return fmt.Errorf("MAIL FROM failed: %w", err)
	}

	// Set recipients
	for _, rcpt := range receivers {
		if err := client.Rcpt(rcpt); err != nil {
			return fmt.Errorf("RCPT TO failed for %s: %w", rcpt, err)
		}
	}

	// Send the email body
	wc, err := client.Data()
	if err != nil {
		return fmt.Errorf("DATA command failed: %w", err)
	}

	// Build email headers and body
	// Sanitize header values to prevent email header injection attacks
	safeSenderName := sanitizeHeaderValue(s.senderName)
	safeSenderAddress := sanitizeHeaderValue(s.senderAddress)
	fromHeader := safeSenderAddress
	if safeSenderName != "" {
		fromHeader = fmt.Sprintf("%s <%s>", safeSenderName, safeSenderAddress)
	}

	// Sanitize receivers to prevent header injection through Bcc field
	safeReceivers := make([]string, len(receivers))
	for i, r := range receivers {
		safeReceivers[i] = sanitizeHeaderValue(r)
	}

	// Sanitize subject and body before constructing raw MIME message
	safeSubject := sanitizeHeaderValue(subject)
	safeBody := sanitizeBodyValue(body)

	msg := fmt.Sprintf("From: %s\r\n"+
		"Bcc: %s\r\n"+
		"Subject: %s\r\n"+
		"MIME-Version: 1.0\r\n"+
		"Content-Type: text/html; charset=UTF-8\r\n"+
		"\r\n"+
		"%s",
		fromHeader,
		joinReceivers(safeReceivers),
		safeSubject,
		safeBody)

	if _, err := wc.Write([]byte(msg)); err != nil {
		_ = wc.Close()
		return fmt.Errorf("failed to write message: %w", err)
	}

	if err := wc.Close(); err != nil {
		return fmt.Errorf("failed to close message writer: %w", err)
	}

	// Quit gracefully
	return client.Quit()
}

// joinReceivers joins email addresses for the Bcc header
func joinReceivers(receivers []string) string {
	result := ""
	for i, r := range receivers {
		if i > 0 {
			result += ", "
		}
		result += r
	}
	return result
}

func (s *sender) GetHost() string {
	return s.dialer.Host
}

func (s *sender) GetPort() int {
	return s.dialer.Port
}

func Setup(ctx context.Context, kubeClient client.Client, brandingName string, log *zap.SugaredLogger) (*Queue, error) {
	// Initialize MailProviderLoader and load default provider from cluster
	mailProviderLoader := config.NewMailProviderLoader(kubeClient).WithLogger(log)
	var mailQueue *Queue

	defaultProvider, err := mailProviderLoader.GetDefaultMailProvider(ctx)
	if err != nil {
		return nil, fmt.Errorf("no default mail provider found in cluster - mail notifications will be disabled: %w", err)
	} else {
		log.Infow("Using default mail provider from cluster",
			"provider", defaultProvider.Name,
			"host", defaultProvider.Host,
			"port", defaultProvider.Port)
		mailSender := NewSenderFromMailProvider(defaultProvider, brandingName, log)
		mailQueue = NewQueue(mailSender, log, defaultProvider.RetryCount, defaultProvider.RetryBackoffMs, defaultProvider.QueueSize)
		mailQueue.Start()
		log.Infow("Mail queue initialized and started",
			"provider", defaultProvider.Name,
			"retryCount", defaultProvider.RetryCount,
			"retryBackoffMs", defaultProvider.RetryBackoffMs,
			"queueSize", defaultProvider.QueueSize)
	}

	return mailQueue, nil
}
