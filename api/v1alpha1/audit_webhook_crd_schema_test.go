// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"context"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

// TestCRDSchema_AuditConfigWebhookPayloadFormat checks webhook.payloadFormat
// against a real API server: existing sinks default to json and keep batching,
// slack sinks reject batching, unknown formats are rejected.
func TestCRDSchema_AuditConfigWebhookPayloadFormat(t *testing.T) {
	c := impersonationEnvtestClient(t)
	ctx := context.Background()

	auditConfig := func(name string, webhook WebhookSinkSpec) *AuditConfig {
		webhook.URL = "https://hooks.example.com/x"
		return &AuditConfig{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec: AuditConfigSpec{Sinks: []AuditSinkConfig{{
				Name: "chat", Type: AuditSinkTypeWebhook, Webhook: &webhook,
			}}},
		}
	}

	legacy := auditConfig("legacy-webhook", WebhookSinkSpec{BatchSize: 10, BatchURL: "https://hooks.example.com/batch"})
	if err := c.Create(ctx, legacy); err != nil {
		t.Fatalf("existing webhook sink was rejected: %v", err)
	}
	got := &AuditConfig{}
	if err := c.Get(ctx, ctrlclient.ObjectKeyFromObject(legacy), got); err != nil {
		t.Fatalf("get: %v", err)
	}
	if format := got.Spec.Sinks[0].Webhook.PayloadFormat; format != WebhookPayloadFormatJSON {
		t.Fatalf("payloadFormat defaulted to %q, want json", format)
	}

	if err := c.Create(ctx, auditConfig("slack", WebhookSinkSpec{PayloadFormat: WebhookPayloadFormatSlack})); err != nil {
		t.Fatalf("slack webhook sink was rejected: %v", err)
	}

	for name, tc := range map[string]struct {
		webhook WebhookSinkSpec
		message string
	}{
		"slack-batch-url":  {WebhookSinkSpec{PayloadFormat: WebhookPayloadFormatSlack, BatchURL: "https://hooks.example.com/batch"}, "one message per event"},
		"slack-batch-size": {WebhookSinkSpec{PayloadFormat: WebhookPayloadFormatSlack, BatchSize: 10}, "one message per event"},
		"teams":            {WebhookSinkSpec{PayloadFormat: "teams"}, "Unsupported value"},
	} {
		err := c.Create(ctx, auditConfig(name, tc.webhook))
		if err == nil || !strings.Contains(err.Error(), tc.message) {
			t.Errorf("%s: want rejection containing %q, got %v", name, tc.message, err)
		}
	}
}
