package mail

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/telekom/k8s-breakglass/pkg/config"
)

func TestNewSenderFromMailProvider(t *testing.T) {
	tests := []struct {
		name         string
		mpConfig     *config.MailProviderConfig
		brandingName string
		description  string
	}{
		{
			name: "Basic mail configuration",
			mpConfig: &config.MailProviderConfig{
				Name:          "test-provider",
				Host:          "smtp.example.com",
				Port:          587,
				Username:      "test@example.com",
				Password:      "password123",
				SenderAddress: "noreply@example.com",
				SenderName:    "Test Sender",
			},
			brandingName: "My App",
			description:  "Should create sender with basic SMTP configuration",
		},
		{
			name: "Mail configuration with InsecureSkipVerify",
			mpConfig: &config.MailProviderConfig{
				Name:               "insecure-provider",
				Host:               "smtp.internal.com",
				Port:               25,
				Username:           "internal@company.com",
				Password:           "internal123",
				InsecureSkipVerify: true,
				SenderAddress:      "internal@company.com",
			},
			brandingName: "Internal App",
			description:  "Should create sender with TLS verification disabled",
		},
		{
			name: "Mail configuration with different port",
			mpConfig: &config.MailProviderConfig{
				Name:          "gmail-provider",
				Host:          "smtp.gmail.com",
				Port:          465,
				Username:      "user@gmail.com",
				Password:      "apppassword",
				SenderAddress: "user@gmail.com",
				SenderName:    "Gmail Sender",
			},
			brandingName: "",
			description:  "Should create sender with SSL port configuration",
		},
		{
			name: "Minimal configuration with defaults",
			mpConfig: &config.MailProviderConfig{
				Name: "minimal-provider",
				Host: "smtp.minimal.com",
				Port: 25,
			},
			brandingName: "Breakglass",
			description:  "Should handle minimal configuration with defaults",
		},
		{
			name: "Unauthenticated SMTP",
			mpConfig: &config.MailProviderConfig{
				Name:          "relay-provider",
				Host:          "smtp-relay.internal",
				Port:          25,
				SenderAddress: "noreply@internal.com",
			},
			brandingName: "",
			description:  "Should create sender for unauthenticated SMTP relay",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sender := NewSenderFromMailProvider(tt.mpConfig, tt.brandingName)

			assert.NotNil(t, sender, tt.description)
			assert.Implements(t, (*Sender)(nil), sender, "Should implement Sender interface")
		})
	}
}

func TestSender_Send(t *testing.T) {
	// Create a sender for testing
	mpConfig := &config.MailProviderConfig{
		Name:          "test-provider",
		Host:          "localhost",
		Port:          1025, // Use a non-standard port to avoid actual mail sending
		Username:      "test@example.com",
		Password:      "test123",
		SenderAddress: "sender@example.com",
	}
	sender := NewSenderFromMailProvider(mpConfig, "")

	tests := []struct {
		name        string
		receivers   []string
		subject     string
		body        string
		expectError bool
		description string
	}{
		{
			name:        "Single receiver",
			receivers:   []string{"recipient@example.com"},
			subject:     "Test Subject",
			body:        "<h1>Test Body</h1>",
			expectError: true, // Will fail due to no actual SMTP server
			description: "Should attempt to send to single receiver",
		},
		{
			name:        "Multiple receivers",
			receivers:   []string{"user1@example.com", "user2@example.com", "user3@example.com"},
			subject:     "Bulk Email Test",
			body:        "<p>This is a test email to multiple recipients.</p>",
			expectError: true, // Will fail due to no actual SMTP server
			description: "Should attempt to send to multiple receivers",
		},
		{
			name:        "Empty subject",
			receivers:   []string{"test@example.com"},
			subject:     "",
			body:        "<p>Email with empty subject</p>",
			expectError: true, // Will fail due to no actual SMTP server
			description: "Should handle empty subject",
		},
		{
			name:        "Empty body",
			receivers:   []string{"test@example.com"},
			subject:     "Empty Body Test",
			body:        "",
			expectError: true, // Will fail due to no actual SMTP server
			description: "Should handle empty body",
		},
		{
			name:        "No receivers",
			receivers:   []string{},
			subject:     "No Recipients",
			body:        "<p>This email has no recipients</p>",
			expectError: true, // Will fail due to no actual SMTP server
			description: "Should handle empty receivers list",
		},
		{
			name:        "Complex HTML body",
			receivers:   []string{"html@example.com"},
			subject:     "HTML Email Test",
			body:        `<html><body><h1>Welcome</h1><p>This is an <strong>HTML</strong> email with <a href="https://example.com">links</a>.</p></body></html>`,
			expectError: true, // Will fail due to no actual SMTP server
			description: "Should handle complex HTML content",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := sender.Send(tt.receivers, tt.subject, tt.body)

			if tt.expectError {
				assert.Error(t, err, tt.description+" - Should return error when no SMTP server")
			} else {
				assert.NoError(t, err, tt.description+" - Should send successfully")
			}
		})
	}
}

func TestSender_Interface(t *testing.T) {
	mpConfig := &config.MailProviderConfig{
		Name:          "test-provider",
		Host:          "test.example.com",
		Port:          587,
		Username:      "test@example.com",
		SenderAddress: "sender@example.com",
	}

	sender := NewSenderFromMailProvider(mpConfig, "")

	// Verify that the sender implements the Sender interface
	var _ = sender

	assert.NotNil(t, sender, "Sender should not be nil")
}

func TestSender_Configuration_Edge_Cases(t *testing.T) {
	tests := []struct {
		name     string
		mpConfig *config.MailProviderConfig
	}{
		{
			name: "Minimum port",
			mpConfig: &config.MailProviderConfig{
				Name:          "low-port",
				Host:          "smtp.example.com",
				Port:          1,
				Username:      "test@example.com",
				SenderAddress: "sender@example.com",
			},
		},
		{
			name: "High port number",
			mpConfig: &config.MailProviderConfig{
				Name:          "high-port",
				Host:          "smtp.example.com",
				Port:          65535,
				Username:      "test@example.com",
				SenderAddress: "sender@example.com",
			},
		},
		{
			name: "Special characters in credentials",
			mpConfig: &config.MailProviderConfig{
				Name:          "special-chars",
				Host:          "smtp.example.com",
				Port:          587,
				Username:      "test+tag@example.com",
				Password:      "p@ssw0rd!@#$%^&*()",
				SenderAddress: "sender@example.com",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sender := NewSenderFromMailProvider(tt.mpConfig, "")
			assert.NotNil(t, sender, "Should create sender even with edge case configuration")
		})
	}
}

func TestSender_Send_Edge_Cases(t *testing.T) {
	mpConfig := &config.MailProviderConfig{
		Name:          "edge-test",
		Host:          "localhost",
		Port:          1025,
		Username:      "test@example.com",
		SenderAddress: "sender@example.com",
	}
	sender := NewSenderFromMailProvider(mpConfig, "")

	t.Run("Very long subject", func(t *testing.T) {
		longSubject := "This is a very long subject line that exceeds typical email subject length limits and should still be handled properly by the mail sender implementation without causing any issues or truncation problems"
		err := sender.Send([]string{"test@example.com"}, longSubject, "Short body")
		assert.Error(t, err) // Will fail due to no SMTP server, but should not panic
	})

	t.Run("Very long body", func(t *testing.T) {
		longBody := "<html><body>"
		for i := 0; i < 1000; i++ {
			longBody += "<p>This is paragraph " + string(rune(i)) + " in a very long email body that tests the mail sender's ability to handle large content sizes.</p>"
		}
		longBody += "</body></html>"

		err := sender.Send([]string{"test@example.com"}, "Long Body Test", longBody)
		assert.Error(t, err) // Will fail due to no SMTP server, but should not panic
	})

	t.Run("Many receivers", func(t *testing.T) {
		manyReceivers := make([]string, 100)
		for i := 0; i < 100; i++ {
			manyReceivers[i] = "user" + string(rune(i)) + "@example.com"
		}

		err := sender.Send(manyReceivers, "Bulk Test", "Test body")
		assert.Error(t, err) // Will fail due to no SMTP server, but should not panic
	})
}

// startTestSMTPServer starts a minimal SMTP server on a random port that
// accepts one message and then returns. It is intentionally minimal and
// only implements the commands necessary for the mail sender tests.
func startTestSMTPServer(t *testing.T) (host string, port int, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer ln.Close()
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		r := bufio.NewReader(conn)
		// Welcome
		fmt.Fprintf(conn, "220 localhost Test SMTP Service Ready\r\n")
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				break
			}
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "EHLO") || strings.HasPrefix(line, "HELO") {
				fmt.Fprintf(conn, "250-localhost Hello\r\n250 OK\r\n")
				continue
			}
			if strings.HasPrefix(line, "MAIL FROM:") {
				fmt.Fprintf(conn, "250 OK\r\n")
				continue
			}
			if strings.HasPrefix(line, "RCPT TO:") {
				fmt.Fprintf(conn, "250 OK\r\n")
				continue
			}
			if strings.HasPrefix(line, "DATA") {
				fmt.Fprintf(conn, "354 End data with <CR><LF>.<CR><LF>\r\n")
				// read until dot line
				for {
					dline, derr := r.ReadString('\n')
					if derr != nil {
						break
					}
					if strings.TrimSpace(dline) == "." {
						break
					}
				}
				fmt.Fprintf(conn, "250 OK: queued as 12345\r\n")
				continue
			}
			if strings.HasPrefix(line, "QUIT") {
				fmt.Fprintf(conn, "221 Bye\r\n")
				break
			}
			// Unknown command – respond generically
			fmt.Fprintf(conn, "250 OK\r\n")
		}
		wg.Done()
	}()

	host = "127.0.0.1"
	addr := ln.Addr().String()
	var p int
	_, err = fmt.Sscanf(addr, "127.0.0.1:%d", &p)
	if err != nil {
		ln.Close()
		t.Fatalf("failed to parse listen addr: %v", err)
	}

	stop = func() {
		// ensure listener closed and goroutine finished
		ln.Close()
		wg.Wait()
	}
	return host, p, stop
}

func TestSender_Send_HappyPath(t *testing.T) {
	host, port, stop := startTestSMTPServer(t)
	defer stop()

	mpConfig := &config.MailProviderConfig{
		Name:          "happy-path",
		Host:          host,
		Port:          port,
		Username:      "", // no auth for our test server
		SenderAddress: "sender@example.com",
	}
	sender := NewSenderFromMailProvider(mpConfig, "")

	err := sender.Send([]string{"recipient@example.com"}, "Hello", "<p>body</p>")
	assert.NoError(t, err, "expected Send to succeed against test SMTP server")
}
