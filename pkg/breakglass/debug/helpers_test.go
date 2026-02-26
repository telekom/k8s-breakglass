package debug

import (
	"context"
	"sync"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/audit"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
)

// Scheme is the runtime scheme used for creating fake clients in debug tests.
var Scheme = testScheme()

func testScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(s))
	utilruntime.Must(breakglassv1alpha1.AddToScheme(s))
	utilruntime.Must(corev1.AddToScheme(s))
	return s
}

// ptrBool returns a pointer to a bool value.
func ptrBool(b bool) *bool { return &b }

// ptrInt32 returns a pointer to an int32 value.
func ptrInt32(i int32) *int32 { return &i }

// MockMailEnqueuer is a test double for MailEnqueuer
type MockMailEnqueuer struct {
	mu       sync.Mutex
	enabled  bool
	messages []EnqueuedEmail
	err      error
}

// EnqueuedEmail represents an email that was enqueued
type EnqueuedEmail struct {
	SessionID  string
	Recipients []string
	Subject    string
	Body       string
}

// NewMockMailEnqueuer creates a new mock mail enqueuer
func NewMockMailEnqueuer(enabled bool) *MockMailEnqueuer {
	return &MockMailEnqueuer{
		enabled:  enabled,
		messages: make([]EnqueuedEmail, 0),
	}
}

// Enqueue implements MailEnqueuer
func (m *MockMailEnqueuer) Enqueue(sessionID string, recipients []string, subject, body string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	m.messages = append(m.messages, EnqueuedEmail{
		SessionID:  sessionID,
		Recipients: recipients,
		Subject:    subject,
		Body:       body,
	})
	return nil
}

// IsEnabled implements MailEnqueuer
func (m *MockMailEnqueuer) IsEnabled() bool {
	return m.enabled
}

// GetMessages returns all enqueued messages
func (m *MockMailEnqueuer) GetMessages() []EnqueuedEmail {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]EnqueuedEmail{}, m.messages...)
}

// SetError sets an error to be returned on Enqueue
func (m *MockMailEnqueuer) SetError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.err = err
}

// Clear clears all messages on the mock
func (m *MockMailEnqueuer) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.messages = make([]EnqueuedEmail, 0)
}

// MockAuditEmitter is a test double for AuditEmitter
type MockAuditEmitter struct {
	mu      sync.Mutex
	enabled bool
	events  []*audit.Event
}

// NewMockAuditEmitter creates a new mock audit emitter
func NewMockAuditEmitter(enabled bool) *MockAuditEmitter {
	return &MockAuditEmitter{
		enabled: enabled,
		events:  make([]*audit.Event, 0),
	}
}

// Emit implements AuditEmitter
func (m *MockAuditEmitter) Emit(_ context.Context, event *audit.Event) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, event)
}

// IsEnabled implements AuditEmitter
func (m *MockAuditEmitter) IsEnabled() bool {
	return m.enabled
}

// GetEvents returns all emitted events
func (m *MockAuditEmitter) GetEvents() []*audit.Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]*audit.Event{}, m.events...)
}

// Clear clears all events on the mock
func (m *MockAuditEmitter) ClearEvents() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = make([]*audit.Event, 0)
}
