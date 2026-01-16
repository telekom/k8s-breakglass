/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package mail

import (
	"context"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/telekom/k8s-breakglass/pkg/metrics"
	"go.uber.org/zap"
)

// QueueItem represents a single email to be sent with retry information
type QueueItem struct {
	ID        string
	Receivers []string
	Subject   string
	Body      string
	Attempt   int
	CreatedAt time.Time
	NextRetry time.Time
	Succeeded bool
}

// Queue manages asynchronous mail sending with retries
type Queue struct {
	sender           Sender
	queue            chan *QueueItem
	log              *zap.SugaredLogger
	maxRetries       int
	initialBackoffMs int
	wg               sync.WaitGroup
	ctx              context.Context
	cancel           context.CancelFunc
	maxQueueSize     int
}

// NewQueue creates a new mail queue for asynchronous sending
func NewQueue(sender Sender, log *zap.SugaredLogger, maxRetries, initialBackoffMs, maxQueueSize int) *Queue {
	if maxRetries <= 0 {
		maxRetries = 5 // Default: 10s, 60s, 3m, 10m, 30m
	}
	if initialBackoffMs <= 0 {
		initialBackoffMs = 10000 // Default: 10 seconds
	}
	if maxQueueSize <= 0 {
		maxQueueSize = 1000
	}

	log.Infow("Initializing mail queue",
		"maxRetries", maxRetries,
		"initialBackoffMs", initialBackoffMs,
		"maxQueueSize", maxQueueSize)

	ctx, cancel := context.WithCancel(context.Background())

	q := &Queue{
		sender:           sender,
		queue:            make(chan *QueueItem, maxQueueSize),
		log:              log,
		maxRetries:       maxRetries,
		initialBackoffMs: initialBackoffMs,
		maxQueueSize:     maxQueueSize,
		ctx:              ctx,
		cancel:           cancel,
	}

	return q
}

// Start begins the background worker for processing emails
func (q *Queue) Start() {
	q.wg.Add(1)
	go q.worker()
	q.log.Info("Mail queue worker started")
}

// Enqueue adds an email to the queue for sending
func (q *Queue) Enqueue(id string, receivers []string, subject, body string) error {
	if len(receivers) == 0 {
		q.log.Errorw("Cannot enqueue email: empty receivers list",
			"id", id,
			"subject", subject,
			"stackTrace", fmt.Sprintf("%+v", receivers))
		metrics.MailQueueDropped.WithLabelValues(q.sender.GetHost()).Inc()
		return fmt.Errorf("cannot enqueue email with no receivers")
	}

	// Check if context is already done first
	select {
	case <-q.ctx.Done():
		q.log.Errorw("Cannot enqueue, queue is shutting down", "id", id)
		metrics.MailQueueDropped.WithLabelValues(q.sender.GetHost()).Inc()
		return fmt.Errorf("queue is shutting down")
	default:
	}

	item := &QueueItem{
		ID:        id,
		Receivers: receivers,
		Subject:   subject,
		Body:      body,
		Attempt:   0,
		CreatedAt: time.Now(),
		NextRetry: time.Now(),
	}

	select {
	case q.queue <- item:
		metrics.MailQueued.WithLabelValues(q.sender.GetHost()).Inc()
		q.log.Debugw("Email queued for sending",
			"id", id,
			"receivers", len(receivers),
			"subject", subject)
		return nil
	case <-q.ctx.Done():
		q.log.Errorw("Cannot enqueue, queue is shutting down", "id", id)
		metrics.MailQueueDropped.WithLabelValues(q.sender.GetHost()).Inc()
		return fmt.Errorf("queue is shutting down")
	default:
		metrics.MailQueueDropped.WithLabelValues(q.sender.GetHost()).Inc()
		q.log.Errorw("Mail queue is full, dropping message",
			"id", id,
			"receivers", len(receivers),
			"queueSize", q.maxQueueSize)
		return fmt.Errorf("mail queue is full (capacity: %d)", q.maxQueueSize)
	}
}

// worker processes items from the queue
func (q *Queue) worker() {
	defer q.wg.Done()
	defer func() {
		if r := recover(); r != nil {
			q.log.Errorw("panic in mail queue worker recovered",
				"panic", r)
			metrics.MailFailed.WithLabelValues(q.sender.GetHost()).Inc()
			// Restart the worker to maintain processing capacity
			q.wg.Add(1)
			go q.worker()
		}
	}()

	pendingItems := make([]*QueueItem, 0)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-q.ctx.Done():
			q.log.Info("Mail queue worker shutting down")
			// Process remaining items in queue
			q.processPending(pendingItems)
			return

		case item := <-q.queue:
			if item != nil {
				q.processItem(item)
				// Track pending items only if not succeeded and we have retries left
				if !item.Succeeded && item.Attempt < q.maxRetries {
					pendingItems = append(pendingItems, item)
				}
			}

		case <-ticker.C:
			// Check for items ready for retry every 50ms
			now := time.Now()
			remainingPending := make([]*QueueItem, 0)

			for _, item := range pendingItems {
				if !item.Succeeded && now.After(item.NextRetry) {
					q.processItem(item)
				}
				// Keep in pending list if not succeeded and still has retries
				if !item.Succeeded && item.Attempt < q.maxRetries {
					remainingPending = append(remainingPending, item)
				}
			}
			pendingItems = remainingPending
		}
	}
}

// processItem attempts to send an email and schedules retry if needed
func (q *Queue) processItem(item *QueueItem) {
	item.Attempt++

	q.log.Infow("Processing queued email",
		"id", item.ID,
		"attempt", item.Attempt,
		"maxRetries", q.maxRetries+1,
		"receivers", len(item.Receivers))

	err := q.sender.Send(item.Receivers, item.Subject, item.Body)
	if err == nil {
		q.log.Infow("Queued email sent successfully",
			"id", item.ID,
			"attempt", item.Attempt,
			"receivers", len(item.Receivers),
			"subject", item.Subject)
		metrics.MailSent.WithLabelValues(q.sender.GetHost()).Inc()
		item.Succeeded = true
		return
	}

	// Send failed, schedule retry if we have attempts left
	if item.Attempt < q.maxRetries {
		backoffMs := q.calculateBackoff(item.Attempt)
		item.NextRetry = time.Now().Add(time.Duration(backoffMs) * time.Millisecond)

		q.log.Warnw("Email send failed, scheduling retry",
			"id", item.ID,
			"attempt", item.Attempt,
			"error", err,
			"retryIn", fmt.Sprintf("%dms", backoffMs),
			"nextRetry", item.NextRetry.Format(time.RFC3339))
		metrics.MailRetryScheduled.WithLabelValues(q.sender.GetHost()).Inc()
	} else {
		// All retries exhausted
		q.log.Errorw("Email send failed after all retries",
			"id", item.ID,
			"attempts", item.Attempt,
			"error", err,
			"receivers", item.Receivers,
			"subject", item.Subject)
		metrics.MailFailed.WithLabelValues(q.sender.GetHost()).Inc()
	}
}

// processPending processes any remaining pending items on shutdown
func (q *Queue) processPending(items []*QueueItem) {
	q.log.Infow("Processing pending items on shutdown", "count", len(items))
	for _, item := range items {
		if item.Attempt < q.maxRetries {
			q.log.Infow("Attempting final send for pending item before shutdown",
				"id", item.ID,
				"attempt", item.Attempt)
			q.processItem(item)
		}
	}
}

// calculateBackoff computes exponential backoff: 10s → 60s → 3m → 10m → 30m
func (q *Queue) calculateBackoff(attempt int) int {
	// Exponential backoff with base 2, starting from initialBackoffMs
	backoffMs := int(float64(q.initialBackoffMs) * math.Pow(2, float64(attempt-1)))
	// Cap at 30 minutes (1,800,000 ms) for conservative behavior
	if backoffMs > 1800000 {
		backoffMs = 1800000
	}
	return backoffMs
}

// Stop gracefully shuts down the queue and waits for all items to be processed
func (q *Queue) Stop(ctx context.Context) error {
	q.log.Info("Stopping mail queue")
	q.cancel()

	// Wait for worker to finish with timeout
	done := make(chan struct{})
	go func() {
		q.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		q.log.Info("Mail queue stopped gracefully")
		return nil
	case <-ctx.Done():
		q.log.Warnw("Mail queue shutdown timeout, some items may not have been processed")
		return ctx.Err()
	}
}

// Length returns the current number of items in the queue
func (q *Queue) Length() int {
	return len(q.queue)
}
