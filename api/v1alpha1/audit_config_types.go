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

package v1alpha1

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// AuditConfigSpec defines the audit trail configuration.
// The audit system is designed for EXTREMELY granular, non-blocking capture
// of all cluster actions with multiple sink options.
type AuditConfigSpec struct {
	// Enabled controls whether auditing is active.
	// +kubebuilder:default=true
	// +optional
	Enabled bool `json:"enabled,omitempty"`

	// Sinks defines where audit events are sent.
	// Multiple sinks can be configured for redundancy.
	// +kubebuilder:validation:MinItems=1
	Sinks []AuditSinkConfig `json:"sinks"`

	// Queue configures the async event queue.
	// +optional
	Queue *AuditQueueConfig `json:"queue,omitempty"`

	// Filtering controls which events are captured.
	// +optional
	Filtering *AuditFilterConfig `json:"filtering,omitempty"`

	// Sampling controls event sampling for high-volume scenarios.
	// +optional
	Sampling *AuditSamplingConfig `json:"sampling,omitempty"`
}

// AuditSinkConfig defines a single audit sink destination.
type AuditSinkConfig struct {
	// Name is a unique identifier for this sink.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	Name string `json:"name"`

	// Type is the sink type.
	// +kubebuilder:validation:Enum=log;webhook;kafka;kubernetes
	Type AuditSinkType `json:"type"`

	// Kafka configuration (required when type=kafka).
	// +optional
	Kafka *KafkaSinkSpec `json:"kafka,omitempty"`

	// Webhook configuration (required when type=webhook).
	// +optional
	Webhook *WebhookSinkSpec `json:"webhook,omitempty"`

	// Log configuration (optional when type=log).
	// +optional
	Log *LogSinkSpec `json:"log,omitempty"`

	// Kubernetes configuration (optional when type=kubernetes).
	// +optional
	Kubernetes *KubernetesSinkSpec `json:"kubernetes,omitempty"`

	// EventTypes limits this sink to specific event types.
	// Empty means all events.
	// +optional
	EventTypes []string `json:"eventTypes,omitempty"`

	// MinSeverity sets the minimum severity level for this sink.
	// Events below this severity are not sent to this sink.
	// +kubebuilder:validation:Enum=info;warning;critical
	// +optional
	MinSeverity string `json:"minSeverity,omitempty"`
}

// AuditSinkType defines the type of audit sink.
// +kubebuilder:validation:Enum=log;webhook;kafka;kubernetes
type AuditSinkType string

const (
	// AuditSinkTypeLog writes to structured logs.
	AuditSinkTypeLog AuditSinkType = "log"

	// AuditSinkTypeWebhook sends to an HTTP endpoint.
	AuditSinkTypeWebhook AuditSinkType = "webhook"

	// AuditSinkTypeKafka sends to a Kafka topic.
	AuditSinkTypeKafka AuditSinkType = "kafka"

	// AuditSinkTypeKubernetes creates Kubernetes Events.
	AuditSinkTypeKubernetes AuditSinkType = "kubernetes"
)

// KafkaSinkSpec configures a Kafka audit sink.
type KafkaSinkSpec struct {
	// Brokers is the list of Kafka broker addresses.
	// +kubebuilder:validation:MinItems=1
	Brokers []string `json:"brokers"`

	// Topic is the Kafka topic for audit events.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=249
	Topic string `json:"topic"`

	// TLS configuration for secure connections.
	// +optional
	TLS *KafkaTLSSpec `json:"tls,omitempty"`

	// SASL authentication configuration.
	// +optional
	SASL *KafkaSASLSpec `json:"sasl,omitempty"`

	// BatchSize is the number of events to batch before sending.
	// +kubebuilder:default=100
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=10000
	// +optional
	BatchSize int `json:"batchSize,omitempty"`

	// BatchTimeoutSeconds is the max time to wait before sending a partial batch.
	// +kubebuilder:default=1
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=60
	// +optional
	BatchTimeoutSeconds int `json:"batchTimeoutSeconds,omitempty"`

	// RequiredAcks determines acknowledgment level.
	// -1: all replicas, 0: none, 1: leader only
	// +kubebuilder:default=-1
	// +kubebuilder:validation:Minimum=-1
	// +kubebuilder:validation:Maximum=1
	// +optional
	RequiredAcks int `json:"requiredAcks,omitempty"`

	// Compression codec for messages.
	// +kubebuilder:validation:Enum=none;gzip;snappy;lz4;zstd
	// +kubebuilder:default=snappy
	// +optional
	Compression string `json:"compression,omitempty"`

	// Async enables fire-and-forget writes.
	// +kubebuilder:default=false
	// +optional
	Async bool `json:"async,omitempty"`
}

// KafkaTLSSpec configures TLS for Kafka connections.
type KafkaTLSSpec struct {
	// Enabled turns on TLS.
	// +kubebuilder:default=true
	Enabled bool `json:"enabled"`

	// CASecretRef references a Secret containing the CA certificate.
	// The Secret must have a key named "ca.crt".
	// +optional
	CASecretRef *SecretKeySelector `json:"caSecretRef,omitempty"`

	// ClientCertSecretRef references a Secret containing client cert and key for mTLS.
	// The Secret must have keys "tls.crt" and "tls.key".
	// +optional
	ClientCertSecretRef *SecretKeySelector `json:"clientCertSecretRef,omitempty"`

	// InsecureSkipVerify skips server certificate verification.
	// WARNING: Only for testing. Never use in production.
	// +kubebuilder:default=false
	// +optional
	InsecureSkipVerify bool `json:"insecureSkipVerify,omitempty"`
}

// KafkaSASLSpec configures SASL authentication for Kafka.
type KafkaSASLSpec struct {
	// Mechanism is the SASL mechanism.
	// +kubebuilder:validation:Enum=PLAIN;SCRAM-SHA-256;SCRAM-SHA-512
	Mechanism string `json:"mechanism"`

	// CredentialsSecretRef references a Secret containing SASL credentials.
	// The Secret must have keys "username" and "password".
	CredentialsSecretRef SecretKeySelector `json:"credentialsSecretRef"`
}

// WebhookSinkSpec configures an HTTP webhook audit sink.
type WebhookSinkSpec struct {
	// URL is the webhook endpoint.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:Pattern=`^https?://.+`
	URL string `json:"url"`

	// Headers to include in requests.
	// +optional
	Headers map[string]string `json:"headers,omitempty"`

	// AuthSecretRef references a Secret for authentication.
	// The Secret can have keys "token" (Bearer) or "username"/"password" (Basic).
	// +optional
	AuthSecretRef *SecretKeySelector `json:"authSecretRef,omitempty"`

	// TimeoutSeconds for HTTP requests.
	// +kubebuilder:default=5
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=30
	// +optional
	TimeoutSeconds int `json:"timeoutSeconds,omitempty"`

	// TLS configuration.
	// +optional
	TLS *WebhookTLSSpec `json:"tls,omitempty"`

	// BatchSize for batched webhook calls.
	// If > 1, events are sent as JSON arrays.
	// +kubebuilder:default=1
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=1000
	// +optional
	BatchSize int `json:"batchSize,omitempty"`

	// BatchURL is an optional separate endpoint for batch requests.
	// If not specified, the main URL is used for both single and batch writes.
	// This allows using different endpoints for single vs batch operations.
	// +optional
	// +kubebuilder:validation:Pattern=`^https?://.+`
	BatchURL string `json:"batchUrl,omitempty"`
}

// WebhookTLSSpec configures TLS for webhook connections.
type WebhookTLSSpec struct {
	// CASecretRef references a Secret containing the CA certificate.
	// +optional
	CASecretRef *SecretKeySelector `json:"caSecretRef,omitempty"`

	// InsecureSkipVerify skips server certificate verification.
	// +kubebuilder:default=false
	// +optional
	InsecureSkipVerify bool `json:"insecureSkipVerify,omitempty"`
}

// LogSinkSpec configures the log audit sink.
type LogSinkSpec struct {
	// Level sets the log level for audit events.
	// +kubebuilder:validation:Enum=debug;info;warn;error
	// +kubebuilder:default=info
	// +optional
	Level string `json:"level,omitempty"`

	// Format sets the log format.
	// +kubebuilder:validation:Enum=json;console
	// +kubebuilder:default=json
	// +optional
	Format string `json:"format,omitempty"`
}

// KubernetesSinkSpec configures the Kubernetes Event audit sink.
type KubernetesSinkSpec struct {
	// EventTypes limits which audit events create K8s Events.
	// Empty means use sensible defaults (session/escalation events only).
	// +optional
	EventTypes []string `json:"eventTypes,omitempty"`
}

// SecretKeySelector references a Secret.
// Secrets MUST be in the controller namespace (breakglass-system by default).
type SecretKeySelector struct {
	// Name of the Secret.
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// Namespace of the Secret.
	// MUST be in the same namespace as the breakglass controller (typically breakglass-system).
	// This is enforced by the controller for security - secrets cannot be read from arbitrary namespaces.
	// +kubebuilder:validation:MinLength=1
	Namespace string `json:"namespace"`
}

// AuditQueueConfig configures the async event queue.
type AuditQueueConfig struct {
	// Size is the queue capacity.
	// Larger queues handle traffic spikes better but use more memory.
	// +kubebuilder:default=100000
	// +kubebuilder:validation:Minimum=1000
	// +kubebuilder:validation:Maximum=10000000
	// +optional
	Size int `json:"size,omitempty"`

	// Workers is the number of concurrent sink writers.
	// +kubebuilder:default=5
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=100
	// +optional
	Workers int `json:"workers,omitempty"`

	// DropOnFull silently drops events when queue is full.
	// If false, a warning is logged for each dropped event.
	// +kubebuilder:default=true
	// +optional
	DropOnFull bool `json:"dropOnFull,omitempty"`
}

// AuditFilterConfig controls which events are captured.
type AuditFilterConfig struct {
	// IncludeEventTypes explicitly includes these event types.
	// Empty means include all.
	// +optional
	IncludeEventTypes []string `json:"includeEventTypes,omitempty"`

	// ExcludeEventTypes excludes these event types.
	// Takes precedence over IncludeEventTypes.
	// +optional
	ExcludeEventTypes []string `json:"excludeEventTypes,omitempty"`

	// IncludeUsers only captures events from these users.
	// Supports glob patterns (e.g., "system:*").
	// +optional
	IncludeUsers []string `json:"includeUsers,omitempty"`

	// ExcludeUsers excludes events from these users.
	// Useful for filtering out service accounts.
	// +optional
	ExcludeUsers []string `json:"excludeUsers,omitempty"`

	// IncludeNamespaces only captures events in these namespaces.
	// Supports pattern matching (glob-style) and label-based namespace selection.
	// +optional
	IncludeNamespaces *NamespaceFilter `json:"includeNamespaces,omitempty"`

	// ExcludeNamespaces excludes events from these namespaces.
	// Useful for filtering out kube-system.
	// Supports pattern matching (glob-style) and label-based namespace selection.
	// +optional
	ExcludeNamespaces *NamespaceFilter `json:"excludeNamespaces,omitempty"`

	// IncludeResources only captures events for these resource kinds.
	// +optional
	IncludeResources []string `json:"includeResources,omitempty"`

	// ExcludeResources excludes events for these resource kinds.
	// +optional
	ExcludeResources []string `json:"excludeResources,omitempty"`
}

// AuditSamplingConfig controls event sampling for high-volume scenarios.
type AuditSamplingConfig struct {
	// Rate is the sampling rate (0.0 to 1.0).
	// 1.0 = capture all, 0.1 = capture 10%.
	// +kubebuilder:default="1.0"
	// +optional
	Rate string `json:"rate,omitempty"`

	// HighVolumeEventTypes are sampled at the configured rate.
	// Other events are always captured at 100%.
	// +optional
	HighVolumeEventTypes []string `json:"highVolumeEventTypes,omitempty"`

	// AlwaysCaptureEventTypes are never sampled (always 100%).
	// +optional
	AlwaysCaptureEventTypes []string `json:"alwaysCaptureEventTypes,omitempty"`
}

// AuditConfigStatus defines the observed state of AuditConfig.
type AuditConfigStatus struct {
	// Conditions represent the current state of the AuditConfig.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// ActiveSinks lists currently active sink names.
	// +optional
	ActiveSinks []string `json:"activeSinks,omitempty"`

	// EventsProcessed is the total number of events processed.
	// +optional
	EventsProcessed int64 `json:"eventsProcessed,omitempty"`

	// EventsDropped is the total number of events dropped.
	// +optional
	EventsDropped int64 `json:"eventsDropped,omitempty"`

	// LastEventTime is when the last event was processed.
	// +optional
	LastEventTime *metav1.Time `json:"lastEventTime,omitempty"`

	// SinkStatuses contains per-sink status information.
	// +optional
	SinkStatuses []AuditSinkStatus `json:"sinkStatuses,omitempty"`
}

// AuditSinkStatus contains status for a single sink.
type AuditSinkStatus struct {
	// Name of the sink.
	Name string `json:"name"`

	// Ready indicates if the sink is operational.
	Ready bool `json:"ready"`

	// LastError is the most recent error, if any.
	// +optional
	LastError string `json:"lastError,omitempty"`

	// LastSuccessTime is when the sink last successfully processed an event.
	// +optional
	LastSuccessTime *metav1.Time `json:"lastSuccessTime,omitempty"`

	// EventsWritten is the number of events written to this sink.
	// +optional
	EventsWritten int64 `json:"eventsWritten,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName=ac
// +kubebuilder:printcolumn:name="Enabled",type=boolean,JSONPath=`.spec.enabled`
// +kubebuilder:printcolumn:name="Sinks",type=string,JSONPath=`.status.activeSinks`
// +kubebuilder:printcolumn:name="Processed",type=integer,JSONPath=`.status.eventsProcessed`
// +kubebuilder:printcolumn:name="Dropped",type=integer,JSONPath=`.status.eventsDropped`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// AuditConfig is the Schema for the auditconfigs API.
// It defines how audit events are captured, filtered, and delivered to sinks.
// AuditConfig is cluster-scoped and applies globally to all audit events.
type AuditConfig struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AuditConfigSpec   `json:"spec,omitempty"`
	Status AuditConfigStatus `json:"status,omitempty"`
}

//+kubebuilder:webhook:path=/validate-breakglass-t-caas-telekom-com-v1alpha1-auditconfig,mutating=false,failurePolicy=fail,sideEffects=None,groups=breakglass.t-caas.telekom.com,resources=auditconfigs,verbs=create;update,versions=v1alpha1,name=auditconfig.validation.breakglass.t-caas.telekom.com,admissionReviewVersions={v1,v1beta1}

// SetupWebhookWithManager registers webhooks for AuditConfig
func (ac *AuditConfig) SetupWebhookWithManager(mgr ctrl.Manager) error {
	InitWebhookClient(mgr.GetClient(), mgr.GetCache())
	return ctrl.NewWebhookManagedBy(mgr).
		For(ac).
		WithValidator(ac).
		Complete()
}

// ValidateCreate implements webhook.CustomValidator so a webhook will be registered for the type
func (ac *AuditConfig) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	auditConfig, ok := obj.(*AuditConfig)
	if !ok {
		return nil, fmt.Errorf("expected an AuditConfig object but got %T", obj)
	}

	// Use shared validation function for consistent validation between webhooks and reconcilers
	result := ValidateAuditConfig(auditConfig)
	if len(result.Errors) == 0 {
		return result.Warnings, nil
	}
	return result.Warnings, apierrors.NewInvalid(
		schema.GroupKind{Group: "breakglass.t-caas.telekom.com", Kind: "AuditConfig"},
		auditConfig.Name,
		result.Errors,
	)
}

// ValidateUpdate implements webhook.CustomValidator so a webhook will be registered for the type
func (ac *AuditConfig) ValidateUpdate(ctx context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	auditConfig, ok := newObj.(*AuditConfig)
	if !ok {
		return nil, fmt.Errorf("expected an AuditConfig object but got %T", newObj)
	}

	// Use shared validation function for consistent validation between webhooks and reconcilers
	result := ValidateAuditConfig(auditConfig)
	if len(result.Errors) == 0 {
		return result.Warnings, nil
	}
	return result.Warnings, apierrors.NewInvalid(
		schema.GroupKind{Group: "breakglass.t-caas.telekom.com", Kind: "AuditConfig"},
		auditConfig.Name,
		result.Errors,
	)
}

// ValidateDelete implements webhook.CustomValidator so a webhook will be registered for the type
func (ac *AuditConfig) ValidateDelete(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	// No validation needed for delete
	return nil, nil
}

// Ensure AuditConfig implements the CustomValidator interface
var _ admission.CustomValidator = &AuditConfig{}

// +kubebuilder:object:root=true

// AuditConfigList contains a list of AuditConfig.
type AuditConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AuditConfig `json:"items"`
}

func init() {
	SchemeBuilder.Register(&AuditConfig{}, &AuditConfigList{})
}
