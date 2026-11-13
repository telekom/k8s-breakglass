// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"context"
	"fmt"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// TestCRDSchema_RuntimeIdentityFields checks the real API server schema of
// DebugSession spec.ticketSystemID (same limit as BreakglassSession) and of
// DebugSessionTemplate spec.audit.runtimeIdentityMetadata.
func TestCRDSchema_RuntimeIdentityFields(t *testing.T) {
	c := impersonationEnvtestClient(t)
	ctx := context.Background()

	for i, tt := range []struct {
		name    string
		ticket  string
		wantErr bool
	}{
		{name: "empty", ticket: ""},
		{name: "max length multibyte", ticket: strings.Repeat("ü", MaxTicketSystemIDLength)},
		{name: "too long", ticket: strings.Repeat("a", MaxTicketSystemIDLength+1), wantErr: true},
	} {
		t.Run("ticketSystemID "+tt.name, func(t *testing.T) {
			session := &DebugSession{
				ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("runtime-identity-%d", i), Namespace: "default"},
				Spec:       DebugSessionSpec{Cluster: "c", TemplateRef: "t", RequestedBy: "u", TicketSystemID: tt.ticket},
			}
			err := c.Create(ctx, session)
			if tt.wantErr {
				if err == nil || !strings.Contains(err.Error(), "spec.ticketSystemID") {
					t.Fatalf("want spec.ticketSystemID error, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("create: %v", err)
			}
			stored := &DebugSession{}
			if err := c.Get(ctx, client.ObjectKeyFromObject(session), stored); err != nil || stored.Spec.TicketSystemID != tt.ticket {
				t.Fatalf("ticketSystemID not persisted: %q, %v", stored.Spec.TicketSystemID, err)
			}
		})
	}

	for i, value := range []*bool{nil, ptr(false)} {
		template := &DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("runtime-identity-template-%d", i)},
			Spec: DebugSessionTemplateSpec{
				Mode:         DebugSessionModeKubectlDebug,
				KubectlDebug: &KubectlDebugConfig{NodeDebug: &NodeDebugConfig{Enabled: true}},
				Audit:        &DebugSessionAuditConfig{RuntimeIdentityMetadata: value},
			},
		}
		if err := c.Create(ctx, template); err != nil {
			t.Fatalf("create template: %v", err)
		}
		stored := &DebugSessionTemplate{}
		if err := c.Get(ctx, client.ObjectKeyFromObject(template), stored); err != nil {
			t.Fatal(err)
		}
		if (value == nil) != (stored.Spec.Audit.RuntimeIdentityMetadata == nil) || value != nil && *stored.Spec.Audit.RuntimeIdentityMetadata != *value {
			t.Fatalf("runtimeIdentityMetadata = %v, want %v", stored.Spec.Audit.RuntimeIdentityMetadata, value)
		}
	}
}
