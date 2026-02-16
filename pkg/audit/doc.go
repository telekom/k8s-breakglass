// Package audit provides the audit trail system for the breakglass controller,
// capturing and forwarding audit events to configurable sinks (Kafka, webhook,
// log, Kubernetes) with circuit breaker protection and queued delivery.
package audit
