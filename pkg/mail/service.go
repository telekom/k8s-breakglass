// SPDX-FileCopyrightText: 2024 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package mail

import (
	"context"
	"sync"
	"time"

	"go.uber.org/zap"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/telekom/k8s-breakglass/pkg/config"
)

const (
	// queueStopTimeout is the maximum time to wait for the queue to stop during reload
	queueStopTimeout = 30 * time.Second
)

// Service manages the mail queue lifecycle and supports hot-reload
// when the MailProvider configuration changes.
type Service struct {
	client       client.Client
	loader       *config.MailProviderLoader
	brandingName string
	logger       *zap.SugaredLogger

	mu    sync.RWMutex
	queue *Queue
}

// NewService creates a new mail Service.
func NewService(kubeClient client.Client, brandingName string, logger *zap.SugaredLogger) *Service {
	loader := config.NewMailProviderLoader(kubeClient).WithLogger(logger)
	return &Service{
		client:       kubeClient,
		loader:       loader,
		brandingName: brandingName,
		logger:       logger.Named("mail-service"),
	}
}

// Start initializes the mail service by loading the default provider.
// Returns an error if no default provider is found, but the service
// can still be used (mail will be disabled until Reload is called).
func (s *Service) Start(ctx context.Context) error {
	return s.Reload(ctx)
}

// Reload reloads the mail configuration from the cluster.
// This is called when a MailProvider is created, updated, or deleted.
func (s *Service) Reload(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Stop existing queue
	if s.queue != nil {
		s.logger.Info("Stopping existing mail queue for reload")
		stopCtx, cancel := context.WithTimeout(ctx, queueStopTimeout)
		defer cancel()
		if err := s.queue.Stop(stopCtx); err != nil {
			s.logger.Warnw("Error stopping mail queue during reload", "error", err)
		}
		s.queue = nil
	}

	// Load new default provider
	defaultProvider, err := s.loader.GetDefaultMailProvider(ctx)
	if err != nil {
		s.logger.Warnw("No default mail provider found - mail notifications disabled", "error", err)
		return err
	}

	s.logger.Infow("Loading mail provider",
		"provider", defaultProvider.Name,
		"host", defaultProvider.Host,
		"port", defaultProvider.Port)

	// Create new sender and queue
	mailSender := NewSenderFromMailProvider(defaultProvider, s.brandingName, s.logger)
	s.queue = NewQueue(mailSender, s.logger, defaultProvider.RetryCount, defaultProvider.RetryBackoffMs, defaultProvider.QueueSize)
	s.queue.Start()

	s.logger.Infow("Mail queue initialized and started",
		"provider", defaultProvider.Name,
		"retryCount", defaultProvider.RetryCount,
		"retryBackoffMs", defaultProvider.RetryBackoffMs,
		"queueSize", defaultProvider.QueueSize)

	return nil
}

// Enqueue adds an email to the mail queue.
// If the queue is not initialized, the email is silently dropped.
func (s *Service) Enqueue(sessionID string, recipients []string, subject, body string) error {
	s.mu.RLock()
	queue := s.queue
	s.mu.RUnlock()

	if queue == nil {
		s.logger.Warnw("Mail queue not initialized, dropping email",
			"sessionID", sessionID,
			"recipients", len(recipients))
		return nil
	}

	return queue.Enqueue(sessionID, recipients, subject, body)
}

// IsEnabled returns whether the mail service has an active queue.
func (s *Service) IsEnabled() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.queue != nil
}

// Stop gracefully shuts down the mail service.
func (s *Service) Stop(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.queue != nil {
		s.logger.Info("Stopping mail service")
		err := s.queue.Stop(ctx)
		s.queue = nil
		return err
	}
	return nil
}

// GetQueue returns the underlying queue for direct access (if needed).
// This is primarily for backward compatibility.
// Deprecated: Use Enqueue directly.
func (s *Service) GetQueue() *Queue {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.queue
}
