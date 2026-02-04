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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

// ==================== ValidationResult Tests ====================

func TestValidationResult_IsValid(t *testing.T) {
	t.Run("empty result is valid", func(t *testing.T) {
		result := &ValidationResult{}
		assert.True(t, result.IsValid())
	})

	t.Run("result with errors is not valid", func(t *testing.T) {
		result := &ValidationResult{}
		result.Errors = append(result.Errors, field.Required(field.NewPath("spec").Child("field1"), "must be set"))
		assert.False(t, result.IsValid())
	})

	t.Run("result with warnings but no errors is valid", func(t *testing.T) {
		result := &ValidationResult{
			Warnings: []string{"warning1"},
		}
		assert.True(t, result.IsValid())
	})
}

func TestValidationResult_ErrorMessage(t *testing.T) {
	t.Run("empty result returns empty string", func(t *testing.T) {
		result := &ValidationResult{}
		assert.Empty(t, result.ErrorMessage())
	})

	t.Run("single error returns that error", func(t *testing.T) {
		result := &ValidationResult{}
		result.Errors = append(result.Errors, field.Required(field.NewPath("spec").Child("field1"), "must be non-empty"))
		msg := result.ErrorMessage()
		assert.Contains(t, msg, "field1")
	})

	t.Run("multiple errors are joined", func(t *testing.T) {
		result := &ValidationResult{}
		result.Errors = append(result.Errors, field.Required(field.NewPath("spec").Child("field1"), "error1"))
		result.Errors = append(result.Errors, field.Required(field.NewPath("spec").Child("field2"), "error2"))
		msg := result.ErrorMessage()
		assert.Contains(t, msg, "field1")
		assert.Contains(t, msg, "field2")
	})
}

func TestValidationResult_AsError(t *testing.T) {
	t.Run("valid result returns nil error", func(t *testing.T) {
		result := &ValidationResult{}
		assert.NoError(t, result.AsError())
	})

	t.Run("invalid result returns non-nil error", func(t *testing.T) {
		result := &ValidationResult{}
		result.Errors = append(result.Errors, field.Required(field.NewPath("spec").Child("field1"), "error"))
		err := result.AsError()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "validation failed")
	})
}

// ==================== BreakglassEscalation Validation Tests ====================

func TestValidateBreakglassEscalation(t *testing.T) {
	validEscalation := func() *BreakglassEscalation {
		return &BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-escalation",
				Namespace: "test-ns",
			},
			Spec: BreakglassEscalationSpec{
				EscalatedGroup: "admin-group",
				Allowed: BreakglassEscalationAllowed{
					Groups:   []string{"dev-group"},
					Clusters: []string{"cluster-a"},
				},
				Approvers: BreakglassEscalationApprovers{
					Groups: []string{"approvers-group"},
				},
			},
		}
	}

	t.Run("nil escalation", func(t *testing.T) {
		result := ValidateBreakglassEscalation(nil)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "cannot be nil")
	})

	t.Run("valid escalation", func(t *testing.T) {
		result := ValidateBreakglassEscalation(validEscalation())
		assert.True(t, result.IsValid(), "expected valid, got errors: %s", result.ErrorMessage())
	})

	t.Run("missing escalatedGroup", func(t *testing.T) {
		e := validEscalation()
		e.Spec.EscalatedGroup = ""
		result := ValidateBreakglassEscalation(e)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "escalatedGroup")
	})

	t.Run("missing allowed groups and clusters", func(t *testing.T) {
		e := validEscalation()
		e.Spec.Allowed.Groups = nil
		e.Spec.Allowed.Clusters = nil
		e.Spec.ClusterConfigRefs = nil
		result := ValidateBreakglassEscalation(e)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "allowed")
	})

	t.Run("missing approvers", func(t *testing.T) {
		e := validEscalation()
		e.Spec.Approvers.Groups = nil
		e.Spec.Approvers.Users = nil
		result := ValidateBreakglassEscalation(e)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "approvers")
	})

	t.Run("empty string in allowed groups", func(t *testing.T) {
		e := validEscalation()
		e.Spec.Allowed.Groups = []string{"dev-group", ""}
		result := ValidateBreakglassEscalation(e)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "empty")
	})

	t.Run("duplicate allowed groups", func(t *testing.T) {
		e := validEscalation()
		e.Spec.Allowed.Groups = []string{"dev-group", "dev-group"}
		result := ValidateBreakglassEscalation(e)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "Duplicate")
	})

	t.Run("duplicate allowed clusters", func(t *testing.T) {
		e := validEscalation()
		e.Spec.Allowed.Clusters = []string{"cluster-a", "cluster-a"}
		result := ValidateBreakglassEscalation(e)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "Duplicate")
	})

	t.Run("valid with users instead of groups as approvers", func(t *testing.T) {
		e := validEscalation()
		e.Spec.Approvers.Groups = nil
		e.Spec.Approvers.Users = []string{"approver@example.com"}
		result := ValidateBreakglassEscalation(e)
		assert.True(t, result.IsValid())
	})

	t.Run("valid with clusterConfigRefs instead of allowed.clusters", func(t *testing.T) {
		e := validEscalation()
		e.Spec.Allowed.Clusters = nil
		e.Spec.ClusterConfigRefs = []string{"cluster-config-1"}
		result := ValidateBreakglassEscalation(e)
		assert.True(t, result.IsValid())
	})

	t.Run("invalid email domain format", func(t *testing.T) {
		e := validEscalation()
		e.Spec.AllowedApproverDomains = []string{"invalid-domain"}
		result := ValidateBreakglassEscalation(e)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "allowedApproverDomains")
	})

	t.Run("valid email domains", func(t *testing.T) {
		e := validEscalation()
		e.Spec.AllowedApproverDomains = []string{"example.com", "corp.example.org"}
		result := ValidateBreakglassEscalation(e)
		assert.True(t, result.IsValid())
	})
}

// ==================== BreakglassSession Validation Tests ====================

func TestValidateBreakglassSession(t *testing.T) {
	validSession := func() *BreakglassSession {
		return &BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-session",
				Namespace: "test-ns",
			},
			Spec: BreakglassSessionSpec{
				Cluster:      "cluster-a",
				User:         "user@example.com",
				GrantedGroup: "admin-group",
			},
		}
	}

	t.Run("nil session", func(t *testing.T) {
		result := ValidateBreakglassSession(nil)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "cannot be nil")
	})

	t.Run("valid session", func(t *testing.T) {
		result := ValidateBreakglassSession(validSession())
		assert.True(t, result.IsValid())
	})

	t.Run("missing cluster", func(t *testing.T) {
		s := validSession()
		s.Spec.Cluster = ""
		result := ValidateBreakglassSession(s)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "cluster")
	})

	t.Run("missing user", func(t *testing.T) {
		s := validSession()
		s.Spec.User = ""
		result := ValidateBreakglassSession(s)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "user")
	})

	t.Run("missing grantedGroup", func(t *testing.T) {
		s := validSession()
		s.Spec.GrantedGroup = ""
		result := ValidateBreakglassSession(s)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "grantedGroup")
	})

	t.Run("all required fields missing", func(t *testing.T) {
		s := &BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-session",
				Namespace: "test-ns",
			},
			Spec: BreakglassSessionSpec{},
		}
		result := ValidateBreakglassSession(s)
		assert.False(t, result.IsValid())
		// Should have errors for all three fields
		msg := result.ErrorMessage()
		assert.Contains(t, msg, "cluster")
		assert.Contains(t, msg, "user")
		assert.Contains(t, msg, "grantedGroup")
	})
}

// ==================== IdentityProvider Validation Tests ====================

func TestValidateIdentityProvider(t *testing.T) {
	validIDP := func() *IdentityProvider {
		return &IdentityProvider{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-idp",
				Namespace: "test-ns",
			},
			Spec: IdentityProviderSpec{
				OIDC: OIDCConfig{
					Authority: "https://auth.example.com",
					ClientID:  "breakglass-client",
				},
			},
		}
	}

	t.Run("nil identityProvider", func(t *testing.T) {
		result := ValidateIdentityProvider(nil)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "cannot be nil")
	})

	t.Run("valid identityProvider", func(t *testing.T) {
		result := ValidateIdentityProvider(validIDP())
		assert.True(t, result.IsValid())
	})

	t.Run("missing OIDC authority", func(t *testing.T) {
		idp := validIDP()
		idp.Spec.OIDC.Authority = ""
		result := ValidateIdentityProvider(idp)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "authority")
	})

	t.Run("missing OIDC clientID", func(t *testing.T) {
		idp := validIDP()
		idp.Spec.OIDC.ClientID = ""
		result := ValidateIdentityProvider(idp)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "clientID")
	})

	t.Run("invalid OIDC authority URL", func(t *testing.T) {
		idp := validIDP()
		idp.Spec.OIDC.Authority = "not-a-url"
		result := ValidateIdentityProvider(idp)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "authority")
	})

	t.Run("HTTP OIDC authority", func(t *testing.T) {
		idp := validIDP()
		idp.Spec.OIDC.Authority = "http://auth.example.com"
		result := ValidateIdentityProvider(idp)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "https")
	})

	t.Run("valid with optional issuer", func(t *testing.T) {
		idp := validIDP()
		idp.Spec.Issuer = "https://issuer.example.com"
		result := ValidateIdentityProvider(idp)
		assert.True(t, result.IsValid())
	})

	t.Run("invalid issuer URL", func(t *testing.T) {
		idp := validIDP()
		idp.Spec.Issuer = "not-a-url"
		result := ValidateIdentityProvider(idp)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "issuer")
	})

	t.Run("keycloak provider missing config", func(t *testing.T) {
		idp := validIDP()
		idp.Spec.GroupSyncProvider = GroupSyncProviderKeycloak
		idp.Spec.Keycloak = nil
		result := ValidateIdentityProvider(idp)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "keycloak")
	})

	t.Run("keycloak provider missing baseURL", func(t *testing.T) {
		idp := validIDP()
		idp.Spec.GroupSyncProvider = GroupSyncProviderKeycloak
		idp.Spec.Keycloak = &KeycloakGroupSync{
			Realm:    "test-realm",
			ClientID: "test-client",
		}
		result := ValidateIdentityProvider(idp)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "baseURL")
	})

	t.Run("keycloak provider missing realm", func(t *testing.T) {
		idp := validIDP()
		idp.Spec.GroupSyncProvider = GroupSyncProviderKeycloak
		idp.Spec.Keycloak = &KeycloakGroupSync{
			BaseURL:  "https://keycloak.example.com",
			ClientID: "test-client",
		}
		result := ValidateIdentityProvider(idp)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "realm")
	})

	t.Run("keycloak provider missing clientID", func(t *testing.T) {
		idp := validIDP()
		idp.Spec.GroupSyncProvider = GroupSyncProviderKeycloak
		idp.Spec.Keycloak = &KeycloakGroupSync{
			BaseURL: "https://keycloak.example.com",
			Realm:   "test-realm",
		}
		result := ValidateIdentityProvider(idp)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "clientID")
	})

	t.Run("valid keycloak provider", func(t *testing.T) {
		idp := validIDP()
		idp.Spec.GroupSyncProvider = GroupSyncProviderKeycloak
		idp.Spec.Keycloak = &KeycloakGroupSync{
			BaseURL:  "https://keycloak.example.com",
			Realm:    "test-realm",
			ClientID: "test-client",
			ClientSecretRef: SecretKeyReference{
				Name:      "keycloak-secret",
				Namespace: "test-ns",
			},
		}
		result := ValidateIdentityProvider(idp)
		assert.True(t, result.IsValid())
	})
}

// ==================== ClusterConfig Validation Tests ====================

func TestValidateClusterConfig(t *testing.T) {
	validCC := func() *ClusterConfig {
		return &ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-cluster",
				Namespace: "test-ns",
			},
			Spec: ClusterConfigSpec{
				KubeconfigSecretRef: &SecretKeyReference{
					Name:      "test-secret",
					Namespace: "test-ns",
				},
			},
		}
	}

	t.Run("nil clusterConfig", func(t *testing.T) {
		result := ValidateClusterConfig(nil)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "cannot be nil")
	})

	t.Run("valid clusterConfig", func(t *testing.T) {
		result := ValidateClusterConfig(validCC())
		assert.True(t, result.IsValid())
	})

	t.Run("kubeconfigSecretRef without name", func(t *testing.T) {
		cc := validCC()
		cc.Spec.KubeconfigSecretRef = &SecretKeyReference{
			Namespace: "default",
		}
		result := ValidateClusterConfig(cc)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "name")
	})

	t.Run("kubeconfigSecretRef without namespace", func(t *testing.T) {
		cc := validCC()
		cc.Spec.KubeconfigSecretRef = &SecretKeyReference{
			Name: "my-secret",
		}
		result := ValidateClusterConfig(cc)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "namespace")
	})

	t.Run("invalid qps", func(t *testing.T) {
		cc := validCC()
		qps := int32(0)
		cc.Spec.QPS = &qps
		result := ValidateClusterConfig(cc)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "qps")
	})

	t.Run("invalid burst", func(t *testing.T) {
		cc := validCC()
		burst := int32(0)
		cc.Spec.Burst = &burst
		result := ValidateClusterConfig(cc)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "burst")
	})

	t.Run("valid with identityProviderRefs", func(t *testing.T) {
		cc := validCC()
		cc.Spec.IdentityProviderRefs = []string{"idp-1", "idp-2"}
		result := ValidateClusterConfig(cc)
		assert.True(t, result.IsValid())
	})
}

// ==================== DenyPolicy Validation Tests ====================

func TestValidateDenyPolicy(t *testing.T) {
	validDP := func() *DenyPolicy {
		return &DenyPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-deny-policy",
				Namespace: "test-ns",
			},
			Spec: DenyPolicySpec{
				Rules: []DenyRule{
					{
						Verbs:     []string{"delete"},
						APIGroups: []string{""},
						Resources: []string{"pods"},
					},
				},
			},
		}
	}

	t.Run("nil denyPolicy", func(t *testing.T) {
		result := ValidateDenyPolicy(nil)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "cannot be nil")
	})

	t.Run("valid denyPolicy", func(t *testing.T) {
		result := ValidateDenyPolicy(validDP())
		assert.True(t, result.IsValid())
	})

	t.Run("rule without verbs", func(t *testing.T) {
		dp := validDP()
		dp.Spec.Rules[0].Verbs = nil
		result := ValidateDenyPolicy(dp)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "verbs")
	})

	t.Run("rule without resources", func(t *testing.T) {
		dp := validDP()
		dp.Spec.Rules[0].Resources = nil
		result := ValidateDenyPolicy(dp)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "resources")
	})

	t.Run("negative precedence", func(t *testing.T) {
		dp := validDP()
		precedence := int32(-1)
		dp.Spec.Precedence = &precedence
		result := ValidateDenyPolicy(dp)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "precedence")
	})

	t.Run("empty denyPolicy is valid", func(t *testing.T) {
		dp := &DenyPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-deny-policy",
				Namespace: "test-ns",
			},
			Spec: DenyPolicySpec{},
		}
		result := ValidateDenyPolicy(dp)
		// Empty rules list is valid - just doesn't deny anything
		assert.True(t, result.IsValid())
	})
}

// ==================== MailProvider Validation Tests ====================

func TestValidateMailProvider(t *testing.T) {
	validMP := func() *MailProvider {
		return &MailProvider{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-mail-provider",
				Namespace: "test-ns",
			},
			Spec: MailProviderSpec{
				SMTP: SMTPConfig{
					Host: "smtp.example.com",
					Port: 587,
				},
				Sender: SenderConfig{
					Address: "noreply@example.com",
				},
			},
		}
	}

	t.Run("nil mailProvider", func(t *testing.T) {
		result := ValidateMailProvider(nil)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "cannot be nil")
	})

	t.Run("valid mailProvider", func(t *testing.T) {
		result := ValidateMailProvider(validMP())
		assert.True(t, result.IsValid())
	})

	t.Run("missing SMTP host", func(t *testing.T) {
		mp := validMP()
		mp.Spec.SMTP.Host = ""
		result := ValidateMailProvider(mp)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "host")
	})

	t.Run("invalid SMTP port too low", func(t *testing.T) {
		mp := validMP()
		mp.Spec.SMTP.Port = 0
		result := ValidateMailProvider(mp)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "port")
	})

	t.Run("invalid SMTP port too high", func(t *testing.T) {
		mp := validMP()
		mp.Spec.SMTP.Port = 70000
		result := ValidateMailProvider(mp)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "port")
	})

	t.Run("missing sender address", func(t *testing.T) {
		mp := validMP()
		mp.Spec.Sender.Address = ""
		result := ValidateMailProvider(mp)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "address")
	})
}

// ==================== AuditConfig Validation Tests ====================

func TestValidateAuditConfig(t *testing.T) {
	validAC := func() *AuditConfig {
		return &AuditConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-audit-config",
				Namespace: "test-ns",
			},
			Spec: AuditConfigSpec{
				Sinks: []AuditSinkConfig{
					{
						Name: "default-sink",
						Type: AuditSinkTypeLog,
					},
				},
			},
		}
	}

	t.Run("nil auditConfig", func(t *testing.T) {
		result := ValidateAuditConfig(nil)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "cannot be nil")
	})

	t.Run("valid auditConfig", func(t *testing.T) {
		result := ValidateAuditConfig(validAC())
		assert.True(t, result.IsValid())
	})

	t.Run("missing sinks", func(t *testing.T) {
		ac := validAC()
		ac.Spec.Sinks = nil
		result := ValidateAuditConfig(ac)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "sinks")
	})

	t.Run("empty sinks", func(t *testing.T) {
		ac := validAC()
		ac.Spec.Sinks = []AuditSinkConfig{}
		result := ValidateAuditConfig(ac)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "sinks")
	})

	t.Run("sink without type", func(t *testing.T) {
		ac := validAC()
		ac.Spec.Sinks[0].Type = ""
		result := ValidateAuditConfig(ac)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "type")
	})

	t.Run("sink without name", func(t *testing.T) {
		ac := validAC()
		ac.Spec.Sinks[0].Name = ""
		result := ValidateAuditConfig(ac)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "name")
	})

	t.Run("duplicate sink names", func(t *testing.T) {
		ac := validAC()
		ac.Spec.Sinks = []AuditSinkConfig{
			{Name: "same-name", Type: AuditSinkTypeLog},
			{Name: "same-name", Type: AuditSinkTypeLog},
		}
		result := ValidateAuditConfig(ac)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "Duplicate")
	})
}

func TestValidateAuditConfig_KafkaSink(t *testing.T) {
	t.Run("valid kafka sink", func(t *testing.T) {
		ac := &AuditConfig{
			ObjectMeta: metav1.ObjectMeta{Name: "test"},
			Spec: AuditConfigSpec{
				Sinks: []AuditSinkConfig{
					{
						Name: "kafka-sink",
						Type: AuditSinkTypeKafka,
						Kafka: &KafkaSinkSpec{
							Brokers: []string{"kafka:9092"},
							Topic:   "audit-events",
						},
					},
				},
			},
		}
		result := ValidateAuditConfig(ac)
		assert.True(t, result.IsValid())
	})

	t.Run("kafka sink without kafka config", func(t *testing.T) {
		ac := &AuditConfig{
			ObjectMeta: metav1.ObjectMeta{Name: "test"},
			Spec: AuditConfigSpec{
				Sinks: []AuditSinkConfig{
					{
						Name:  "kafka-sink",
						Type:  AuditSinkTypeKafka,
						Kafka: nil,
					},
				},
			},
		}
		result := ValidateAuditConfig(ac)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "kafka configuration is required")
	})

	t.Run("kafka sink without brokers", func(t *testing.T) {
		ac := &AuditConfig{
			ObjectMeta: metav1.ObjectMeta{Name: "test"},
			Spec: AuditConfigSpec{
				Sinks: []AuditSinkConfig{
					{
						Name: "kafka-sink",
						Type: AuditSinkTypeKafka,
						Kafka: &KafkaSinkSpec{
							Brokers: []string{},
							Topic:   "audit-events",
						},
					},
				},
			},
		}
		result := ValidateAuditConfig(ac)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "broker")
	})

	t.Run("kafka sink without topic", func(t *testing.T) {
		ac := &AuditConfig{
			ObjectMeta: metav1.ObjectMeta{Name: "test"},
			Spec: AuditConfigSpec{
				Sinks: []AuditSinkConfig{
					{
						Name: "kafka-sink",
						Type: AuditSinkTypeKafka,
						Kafka: &KafkaSinkSpec{
							Brokers: []string{"kafka:9092"},
							Topic:   "",
						},
					},
				},
			},
		}
		result := ValidateAuditConfig(ac)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "topic")
	})

	t.Run("kafka sink with SASL missing credentials", func(t *testing.T) {
		ac := &AuditConfig{
			ObjectMeta: metav1.ObjectMeta{Name: "test"},
			Spec: AuditConfigSpec{
				Sinks: []AuditSinkConfig{
					{
						Name: "kafka-sink",
						Type: AuditSinkTypeKafka,
						Kafka: &KafkaSinkSpec{
							Brokers: []string{"kafka:9092"},
							Topic:   "audit-events",
							SASL: &KafkaSASLSpec{
								Mechanism: "SCRAM-SHA-512",
								CredentialsSecretRef: SecretKeySelector{
									Name:      "",
									Namespace: "",
								},
							},
						},
					},
				},
			},
		}
		result := ValidateAuditConfig(ac)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "credentials")
	})
}

func TestValidateAuditConfig_WebhookSink(t *testing.T) {
	t.Run("valid webhook sink", func(t *testing.T) {
		ac := &AuditConfig{
			ObjectMeta: metav1.ObjectMeta{Name: "test"},
			Spec: AuditConfigSpec{
				Sinks: []AuditSinkConfig{
					{
						Name: "webhook-sink",
						Type: AuditSinkTypeWebhook,
						Webhook: &WebhookSinkSpec{
							URL: "https://example.com/audit",
						},
					},
				},
			},
		}
		result := ValidateAuditConfig(ac)
		assert.True(t, result.IsValid())
	})

	t.Run("webhook sink without webhook config", func(t *testing.T) {
		ac := &AuditConfig{
			ObjectMeta: metav1.ObjectMeta{Name: "test"},
			Spec: AuditConfigSpec{
				Sinks: []AuditSinkConfig{
					{
						Name:    "webhook-sink",
						Type:    AuditSinkTypeWebhook,
						Webhook: nil,
					},
				},
			},
		}
		result := ValidateAuditConfig(ac)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "webhook configuration is required")
	})

	t.Run("webhook sink without URL", func(t *testing.T) {
		ac := &AuditConfig{
			ObjectMeta: metav1.ObjectMeta{Name: "test"},
			Spec: AuditConfigSpec{
				Sinks: []AuditSinkConfig{
					{
						Name: "webhook-sink",
						Type: AuditSinkTypeWebhook,
						Webhook: &WebhookSinkSpec{
							URL: "",
						},
					},
				},
			},
		}
		result := ValidateAuditConfig(ac)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "URL is required")
	})

	t.Run("webhook sink with authSecretRef missing name", func(t *testing.T) {
		ac := &AuditConfig{
			ObjectMeta: metav1.ObjectMeta{Name: "test"},
			Spec: AuditConfigSpec{
				Sinks: []AuditSinkConfig{
					{
						Name: "webhook-sink",
						Type: AuditSinkTypeWebhook,
						Webhook: &WebhookSinkSpec{
							URL: "https://example.com/audit",
							AuthSecretRef: &SecretKeySelector{
								Name:      "",
								Namespace: "test-ns",
							},
						},
					},
				},
			},
		}
		result := ValidateAuditConfig(ac)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "secret name is required")
	})

	t.Run("webhook sink with TLS caSecretRef missing namespace", func(t *testing.T) {
		ac := &AuditConfig{
			ObjectMeta: metav1.ObjectMeta{Name: "test"},
			Spec: AuditConfigSpec{
				Sinks: []AuditSinkConfig{
					{
						Name: "webhook-sink",
						Type: AuditSinkTypeWebhook,
						Webhook: &WebhookSinkSpec{
							URL: "https://example.com/audit",
							TLS: &WebhookTLSSpec{
								CASecretRef: &SecretKeySelector{
									Name:      "ca-cert",
									Namespace: "",
								},
							},
						},
					},
				},
			},
		}
		result := ValidateAuditConfig(ac)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "CA secret namespace is required")
	})

	t.Run("webhook sink with authSecretRef missing namespace", func(t *testing.T) {
		ac := &AuditConfig{
			ObjectMeta: metav1.ObjectMeta{Name: "test"},
			Spec: AuditConfigSpec{
				Sinks: []AuditSinkConfig{
					{
						Name: "webhook-sink",
						Type: AuditSinkTypeWebhook,
						Webhook: &WebhookSinkSpec{
							URL: "https://example.com/audit",
							AuthSecretRef: &SecretKeySelector{
								Name:      "auth-secret",
								Namespace: "",
							},
						},
					},
				},
			},
		}
		result := ValidateAuditConfig(ac)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "secret namespace is required")
	})

	t.Run("webhook sink with TLS caSecretRef missing name", func(t *testing.T) {
		ac := &AuditConfig{
			ObjectMeta: metav1.ObjectMeta{Name: "test"},
			Spec: AuditConfigSpec{
				Sinks: []AuditSinkConfig{
					{
						Name: "webhook-sink",
						Type: AuditSinkTypeWebhook,
						Webhook: &WebhookSinkSpec{
							URL: "https://example.com/audit",
							TLS: &WebhookTLSSpec{
								CASecretRef: &SecretKeySelector{
									Name:      "",
									Namespace: "test-ns",
								},
							},
						},
					},
				},
			},
		}
		result := ValidateAuditConfig(ac)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "CA secret name is required")
	})
}

func TestValidateAuditConfig_KafkaSASL(t *testing.T) {
	t.Run("kafka sink with SASL missing mechanism", func(t *testing.T) {
		ac := &AuditConfig{
			ObjectMeta: metav1.ObjectMeta{Name: "test"},
			Spec: AuditConfigSpec{
				Sinks: []AuditSinkConfig{
					{
						Name: "kafka-sink",
						Type: AuditSinkTypeKafka,
						Kafka: &KafkaSinkSpec{
							Brokers: []string{"kafka:9092"},
							Topic:   "audit-events",
							SASL: &KafkaSASLSpec{
								Mechanism: "",
								CredentialsSecretRef: SecretKeySelector{
									Name:      "creds",
									Namespace: "test-ns",
								},
							},
						},
					},
				},
			},
		}
		result := ValidateAuditConfig(ac)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "SASL mechanism is required")
	})

	t.Run("kafka sink with SASL missing credentials name only", func(t *testing.T) {
		ac := &AuditConfig{
			ObjectMeta: metav1.ObjectMeta{Name: "test"},
			Spec: AuditConfigSpec{
				Sinks: []AuditSinkConfig{
					{
						Name: "kafka-sink",
						Type: AuditSinkTypeKafka,
						Kafka: &KafkaSinkSpec{
							Brokers: []string{"kafka:9092"},
							Topic:   "audit-events",
							SASL: &KafkaSASLSpec{
								Mechanism: "SCRAM-SHA-512",
								CredentialsSecretRef: SecretKeySelector{
									Name:      "",
									Namespace: "test-ns",
								},
							},
						},
					},
				},
			},
		}
		result := ValidateAuditConfig(ac)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "credentials secret name is required")
	})

	t.Run("kafka sink with SASL missing credentials namespace only", func(t *testing.T) {
		ac := &AuditConfig{
			ObjectMeta: metav1.ObjectMeta{Name: "test"},
			Spec: AuditConfigSpec{
				Sinks: []AuditSinkConfig{
					{
						Name: "kafka-sink",
						Type: AuditSinkTypeKafka,
						Kafka: &KafkaSinkSpec{
							Brokers: []string{"kafka:9092"},
							Topic:   "audit-events",
							SASL: &KafkaSASLSpec{
								Mechanism: "SCRAM-SHA-512",
								CredentialsSecretRef: SecretKeySelector{
									Name:      "creds",
									Namespace: "",
								},
							},
						},
					},
				},
			},
		}
		result := ValidateAuditConfig(ac)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "credentials secret namespace is required")
	})

	t.Run("kafka sink with valid SASL config", func(t *testing.T) {
		ac := &AuditConfig{
			ObjectMeta: metav1.ObjectMeta{Name: "test"},
			Spec: AuditConfigSpec{
				Sinks: []AuditSinkConfig{
					{
						Name: "kafka-sink",
						Type: AuditSinkTypeKafka,
						Kafka: &KafkaSinkSpec{
							Brokers: []string{"kafka:9092"},
							Topic:   "audit-events",
							SASL: &KafkaSASLSpec{
								Mechanism: "SCRAM-SHA-512",
								CredentialsSecretRef: SecretKeySelector{
									Name:      "creds",
									Namespace: "test-ns",
								},
							},
						},
					},
				},
			},
		}
		result := ValidateAuditConfig(ac)
		assert.True(t, result.IsValid())
	})
}

func TestValidateAuditConfig_LogSink(t *testing.T) {
	t.Run("log sink with nil config", func(t *testing.T) {
		ac := &AuditConfig{
			ObjectMeta: metav1.ObjectMeta{Name: "test"},
			Spec: AuditConfigSpec{
				Sinks: []AuditSinkConfig{
					{
						Name: "log-sink",
						Type: AuditSinkTypeLog,
						Log:  nil,
					},
				},
			},
		}
		result := ValidateAuditConfig(ac)
		assert.True(t, result.IsValid())
	})

	t.Run("log sink with config", func(t *testing.T) {
		ac := &AuditConfig{
			ObjectMeta: metav1.ObjectMeta{Name: "test"},
			Spec: AuditConfigSpec{
				Sinks: []AuditSinkConfig{
					{
						Name: "log-sink",
						Type: AuditSinkTypeLog,
						Log: &LogSinkSpec{
							Level:  "info",
							Format: "json",
						},
					},
				},
			},
		}
		result := ValidateAuditConfig(ac)
		assert.True(t, result.IsValid())
	})
}

// ==================== Malformed Resource Tests ====================

// These tests verify that validation handles malformed resources gracefully
// even if they somehow bypassed webhook validation (e.g., direct etcd manipulation,
// CRD version migration, or disabled webhooks)

func TestValidateBreakglassEscalation_MalformedResources(t *testing.T) {
	t.Run("escalation with zero-value spec", func(t *testing.T) {
		e := &BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "malformed",
				Namespace: "test",
			},
			Spec: BreakglassEscalationSpec{},
		}
		result := ValidateBreakglassEscalation(e)
		assert.False(t, result.IsValid())
		// Should have multiple errors but not panic
		assert.Greater(t, len(result.Errors), 0)
	})

	t.Run("escalation with nil pointer fields", func(t *testing.T) {
		e := &BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "malformed",
				Namespace: "test",
			},
			Spec: BreakglassEscalationSpec{
				EscalatedGroup: "group",
				Allowed: BreakglassEscalationAllowed{
					Groups: nil, // nil slice
				},
				Approvers: BreakglassEscalationApprovers{
					Groups: nil,
					Users:  nil,
				},
			},
		}
		result := ValidateBreakglassEscalation(e)
		// Should handle nil slices gracefully
		assert.False(t, result.IsValid())
		assert.NotNil(t, result)
	})

	t.Run("escalation with whitespace-only values", func(t *testing.T) {
		e := &BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "malformed",
				Namespace: "test",
			},
			Spec: BreakglassEscalationSpec{
				EscalatedGroup: "   ", // whitespace only
				Allowed: BreakglassEscalationAllowed{
					Groups: []string{"valid-group"},
				},
				Approvers: BreakglassEscalationApprovers{
					Groups: []string{"approver-group"},
				},
			},
		}
		result := ValidateBreakglassEscalation(e)
		assert.False(t, result.IsValid())
	})
}

func TestValidateBreakglassSession_MalformedResources(t *testing.T) {
	t.Run("session with zero-value spec", func(t *testing.T) {
		s := &BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "malformed",
				Namespace: "test",
			},
			Spec: BreakglassSessionSpec{},
		}
		result := ValidateBreakglassSession(s)
		assert.False(t, result.IsValid())
		// Should report errors for all required fields
		assert.GreaterOrEqual(t, len(result.Errors), 3)
	})

	t.Run("session with whitespace-only values", func(t *testing.T) {
		s := &BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "malformed",
				Namespace: "test",
			},
			Spec: BreakglassSessionSpec{
				Cluster:      "   ",
				User:         "   ",
				GrantedGroup: "   ",
			},
		}
		// Note: Basic validation doesn't check for whitespace-only values
		// This would need to be added if required
		result := ValidateBreakglassSession(s)
		// Current implementation considers non-empty strings as valid
		assert.True(t, result.IsValid())
	})
}

func TestValidateIdentityProvider_MalformedResources(t *testing.T) {
	t.Run("IDP with zero-value spec", func(t *testing.T) {
		idp := &IdentityProvider{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "malformed",
				Namespace: "test",
			},
			Spec: IdentityProviderSpec{},
		}
		result := ValidateIdentityProvider(idp)
		assert.False(t, result.IsValid())
		// Should report errors for authority and clientID
		assert.GreaterOrEqual(t, len(result.Errors), 2)
	})

	t.Run("IDP with malformed URL", func(t *testing.T) {
		idp := &IdentityProvider{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "malformed",
				Namespace: "test",
			},
			Spec: IdentityProviderSpec{
				OIDC: OIDCConfig{
					Authority: "://not-a-valid-url",
					ClientID:  "client",
				},
			},
		}
		result := ValidateIdentityProvider(idp)
		assert.False(t, result.IsValid())
	})

	t.Run("IDP with empty keycloak config when keycloak provider", func(t *testing.T) {
		idp := &IdentityProvider{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "malformed",
				Namespace: "test",
			},
			Spec: IdentityProviderSpec{
				OIDC: OIDCConfig{
					Authority: "https://auth.example.com",
					ClientID:  "client",
				},
				GroupSyncProvider: GroupSyncProviderKeycloak,
				Keycloak:          &KeycloakGroupSync{}, // Empty config
			},
		}
		result := ValidateIdentityProvider(idp)
		assert.False(t, result.IsValid())
		// Should have errors for all keycloak fields
		assert.GreaterOrEqual(t, len(result.Errors), 3)
	})
}

func TestValidateClusterConfig_MalformedResources(t *testing.T) {
	t.Run("ClusterConfig with zero-value spec", func(t *testing.T) {
		cc := &ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "malformed",
				Namespace: "test",
			},
			Spec: ClusterConfigSpec{},
		}
		result := ValidateClusterConfig(cc)
		assert.False(t, result.IsValid())
	})

	t.Run("ClusterConfig with empty kubeconfigSecretRef", func(t *testing.T) {
		cc := &ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "malformed",
				Namespace: "test",
			},
			Spec: ClusterConfigSpec{
				KubeconfigSecretRef: &SecretKeyReference{}, // Empty - missing Name and Namespace
			},
		}
		result := ValidateClusterConfig(cc)
		assert.False(t, result.IsValid())
	})
}

func TestValidateMailProvider_MalformedResources(t *testing.T) {
	t.Run("MailProvider with zero-value spec", func(t *testing.T) {
		mp := &MailProvider{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "malformed",
				Namespace: "test",
			},
			Spec: MailProviderSpec{},
		}
		result := ValidateMailProvider(mp)
		assert.False(t, result.IsValid())
		// Should have errors for host, port, and sender address
		assert.GreaterOrEqual(t, len(result.Errors), 2)
	})
}

// ==================== Condition Constants Tests ====================

func TestValidationConditionConstants(t *testing.T) {
	t.Run("condition type is defined", func(t *testing.T) {
		assert.NotEmpty(t, ValidationConditionType)
	})

	t.Run("condition reasons are defined", func(t *testing.T) {
		assert.NotEmpty(t, ValidationConditionReasons.Valid)
		assert.NotEmpty(t, ValidationConditionReasons.Invalid)
		assert.NotEmpty(t, ValidationConditionReasons.MissingFields)
		assert.NotEmpty(t, ValidationConditionReasons.MalformedResource)
	})
}

// ==================== DebugSession Validation Tests ====================

func TestValidateDebugSession(t *testing.T) {
	t.Run("nil debug session", func(t *testing.T) {
		result := ValidateDebugSession(nil)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "cannot be nil")
	})

	t.Run("valid debug session", func(t *testing.T) {
		ds := &DebugSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-debug-session",
				Namespace: "default",
			},
			Spec: DebugSessionSpec{
				Cluster:     "test-cluster",
				TemplateRef: "debug-template-1",
				RequestedBy: "user@example.com",
			},
		}
		result := ValidateDebugSession(ds)
		assert.True(t, result.IsValid(), "expected valid, got errors: %s", result.ErrorMessage())
	})

	t.Run("missing cluster", func(t *testing.T) {
		ds := &DebugSession{
			Spec: DebugSessionSpec{
				TemplateRef: "debug-template-1",
				RequestedBy: "user@example.com",
			},
		}
		result := ValidateDebugSession(ds)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "cluster")
	})

	t.Run("missing templateRef", func(t *testing.T) {
		ds := &DebugSession{
			Spec: DebugSessionSpec{
				Cluster:     "test-cluster",
				RequestedBy: "user@example.com",
			},
		}
		result := ValidateDebugSession(ds)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "templateRef")
	})

	t.Run("missing requestedBy", func(t *testing.T) {
		ds := &DebugSession{
			Spec: DebugSessionSpec{
				Cluster:     "test-cluster",
				TemplateRef: "debug-template-1",
			},
		}
		result := ValidateDebugSession(ds)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "requestedBy")
	})

	t.Run("valid with requestedDuration", func(t *testing.T) {
		ds := &DebugSession{
			Spec: DebugSessionSpec{
				Cluster:           "test-cluster",
				TemplateRef:       "debug-template-1",
				RequestedBy:       "user@example.com",
				RequestedDuration: "2h",
			},
		}
		result := ValidateDebugSession(ds)
		assert.True(t, result.IsValid())
	})

	t.Run("invalid requestedDuration format", func(t *testing.T) {
		ds := &DebugSession{
			Spec: DebugSessionSpec{
				Cluster:           "test-cluster",
				TemplateRef:       "debug-template-1",
				RequestedBy:       "user@example.com",
				RequestedDuration: "invalid",
			},
		}
		result := ValidateDebugSession(ds)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "requestedDuration")
	})
}

// ==================== DebugPodTemplate Validation Tests ====================

func TestValidateDebugPodTemplate(t *testing.T) {
	t.Run("nil template", func(t *testing.T) {
		result := ValidateDebugPodTemplate(nil)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "cannot be nil")
	})

	t.Run("valid template with container", func(t *testing.T) {
		template := &DebugPodTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-template",
			},
			Spec: DebugPodTemplateSpec{
				Template: &DebugPodSpec{
					Spec: DebugPodSpecInner{
						Containers: []corev1.Container{
							{Name: "debug-container", Image: "busybox"},
						},
					},
				},
			},
		}
		result := ValidateDebugPodTemplate(template)
		assert.True(t, result.IsValid(), "expected valid, got errors: %s", result.ErrorMessage())
	})

	t.Run("template without containers", func(t *testing.T) {
		template := &DebugPodTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-template",
			},
			Spec: DebugPodTemplateSpec{
				Template: &DebugPodSpec{
					Spec: DebugPodSpecInner{
						Containers: []corev1.Container{},
					},
				},
			},
		}
		result := ValidateDebugPodTemplate(template)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "containers")
	})

	t.Run("container without name", func(t *testing.T) {
		template := &DebugPodTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-template",
			},
			Spec: DebugPodTemplateSpec{
				Template: &DebugPodSpec{
					Spec: DebugPodSpecInner{
						Containers: []corev1.Container{
							{Name: "", Image: "busybox"},
						},
					},
				},
			},
		}
		result := ValidateDebugPodTemplate(template)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "name")
	})

	t.Run("duplicate container names", func(t *testing.T) {
		template := &DebugPodTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-template",
			},
			Spec: DebugPodTemplateSpec{
				Template: &DebugPodSpec{
					Spec: DebugPodSpecInner{
						Containers: []corev1.Container{
							{Name: "debug", Image: "busybox"},
							{Name: "debug", Image: "alpine"},
						},
					},
				},
			},
		}
		result := ValidateDebugPodTemplate(template)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "debug")
	})
}

// ==================== DebugSessionTemplate Validation Tests ====================

func TestValidateDebugSessionTemplate(t *testing.T) {
	t.Run("nil template", func(t *testing.T) {
		result := ValidateDebugSessionTemplate(nil)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "cannot be nil")
	})

	t.Run("valid workload mode template", func(t *testing.T) {
		template := &DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-template",
			},
			Spec: DebugSessionTemplateSpec{
				Mode: DebugSessionModeWorkload,
				PodTemplateRef: &DebugPodTemplateReference{
					Name: "pod-template",
				},
			},
		}
		result := ValidateDebugSessionTemplate(template)
		assert.True(t, result.IsValid(), "expected valid, got errors: %s", result.ErrorMessage())
	})

	t.Run("workload mode without podTemplateRef", func(t *testing.T) {
		template := &DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-template",
			},
			Spec: DebugSessionTemplateSpec{
				Mode: DebugSessionModeWorkload,
			},
		}
		result := ValidateDebugSessionTemplate(template)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "podTemplateRef")
	})

	t.Run("kubectl-debug mode without kubectlDebug", func(t *testing.T) {
		template := &DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-template",
			},
			Spec: DebugSessionTemplateSpec{
				Mode: DebugSessionModeKubectlDebug,
			},
		}
		result := ValidateDebugSessionTemplate(template)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "kubectlDebug")
	})

	t.Run("hybrid mode requires both", func(t *testing.T) {
		template := &DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-template",
			},
			Spec: DebugSessionTemplateSpec{
				Mode: DebugSessionModeHybrid,
				PodTemplateRef: &DebugPodTemplateReference{
					Name: "pod-template",
				},
				// Missing KubectlDebug
			},
		}
		result := ValidateDebugSessionTemplate(template)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "kubectlDebug")
	})

	t.Run("valid constraints", func(t *testing.T) {
		template := &DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-template",
			},
			Spec: DebugSessionTemplateSpec{
				Mode: DebugSessionModeWorkload,
				PodTemplateRef: &DebugPodTemplateReference{
					Name: "pod-template",
				},
				Constraints: &DebugSessionConstraints{
					MaxDuration:     "4h",
					DefaultDuration: "1h",
				},
			},
		}
		result := ValidateDebugSessionTemplate(template)
		assert.True(t, result.IsValid(), "expected valid, got errors: %s", result.ErrorMessage())
	})

	t.Run("invalid maxDuration format", func(t *testing.T) {
		template := &DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-template",
			},
			Spec: DebugSessionTemplateSpec{
				Mode: DebugSessionModeWorkload,
				PodTemplateRef: &DebugPodTemplateReference{
					Name: "pod-template",
				},
				Constraints: &DebugSessionConstraints{
					MaxDuration: "invalid",
				},
			},
		}
		result := ValidateDebugSessionTemplate(template)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "maxDuration")
	})

	t.Run("invalid defaultDuration format", func(t *testing.T) {
		template := &DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-template",
			},
			Spec: DebugSessionTemplateSpec{
				Mode: DebugSessionModeWorkload,
				PodTemplateRef: &DebugPodTemplateReference{
					Name: "pod-template",
				},
				Constraints: &DebugSessionConstraints{
					DefaultDuration: "invalid",
				},
			},
		}
		result := ValidateDebugSessionTemplate(template)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "defaultDuration")
	})

	t.Run("default mode (empty) uses workload", func(t *testing.T) {
		template := &DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-template",
			},
			Spec: DebugSessionTemplateSpec{
				Mode: "", // Empty defaults to workload
				PodTemplateRef: &DebugPodTemplateReference{
					Name: "pod-template",
				},
			},
		}
		result := ValidateDebugSessionTemplate(template)
		assert.True(t, result.IsValid(), "expected valid, got errors: %s", result.ErrorMessage())
	})
}

// ==================== BreakglassSessionForReconciler Tests ====================

func TestValidateBreakglassSessionForReconciler(t *testing.T) {
	t.Run("nil session", func(t *testing.T) {
		result := ValidateBreakglassSessionForReconciler(nil)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "cannot be nil")
	})

	t.Run("valid session", func(t *testing.T) {
		session := &BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-session",
				Namespace: "default",
			},
			Spec: BreakglassSessionSpec{
				Cluster:      "prod-cluster",
				User:         "user@example.com",
				GrantedGroup: "cluster-admin",
			},
		}
		result := ValidateBreakglassSessionForReconciler(session)
		assert.True(t, result.IsValid(), "expected valid, got errors: %s", result.ErrorMessage())
	})

	t.Run("missing cluster", func(t *testing.T) {
		session := &BreakglassSession{
			Spec: BreakglassSessionSpec{
				User:         "user@example.com",
				GrantedGroup: "cluster-admin",
			},
		}
		result := ValidateBreakglassSessionForReconciler(session)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "cluster")
	})

	t.Run("missing user", func(t *testing.T) {
		session := &BreakglassSession{
			Spec: BreakglassSessionSpec{
				Cluster:      "prod-cluster",
				GrantedGroup: "cluster-admin",
			},
		}
		result := ValidateBreakglassSessionForReconciler(session)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "user")
	})

	t.Run("missing grantedGroup", func(t *testing.T) {
		session := &BreakglassSession{
			Spec: BreakglassSessionSpec{
				Cluster: "prod-cluster",
				User:    "user@example.com",
			},
		}
		result := ValidateBreakglassSessionForReconciler(session)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "grantedGroup")
	})

	t.Run("all required fields missing", func(t *testing.T) {
		session := &BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "malformed-session",
				Namespace: "default",
			},
			Spec: BreakglassSessionSpec{},
		}
		result := ValidateBreakglassSessionForReconciler(session)
		assert.False(t, result.IsValid())
		// Should have 3 errors: cluster, user, grantedGroup
		assert.Len(t, result.Errors, 3)
	})
}

// ==================== SchedulingOptions Validation Tests ====================

func TestValidateSchedulingOptions(t *testing.T) {
	t.Run("nil scheduling options", func(t *testing.T) {
		errs := validateSchedulingOptions(nil, field.NewPath("spec", "schedulingOptions"))
		assert.Empty(t, errs)
	})

	t.Run("valid scheduling options", func(t *testing.T) {
		opts := &SchedulingOptions{
			Required: true,
			Options: []SchedulingOption{
				{
					Name:        "sriov",
					DisplayName: "SRIOV Nodes",
					Description: "Deploy on nodes with SR-IOV network interfaces",
					Default:     true,
				},
				{
					Name:        "standard",
					DisplayName: "Standard Nodes",
					Description: "Deploy on regular worker nodes",
				},
			},
		}
		errs := validateSchedulingOptions(opts, field.NewPath("spec", "schedulingOptions"))
		assert.Empty(t, errs)
	})

	t.Run("empty options list", func(t *testing.T) {
		opts := &SchedulingOptions{
			Required: false,
			Options:  []SchedulingOption{},
		}
		errs := validateSchedulingOptions(opts, field.NewPath("spec", "schedulingOptions"))
		assert.Len(t, errs, 1)
		assert.Contains(t, errs[0].Error(), "at least one scheduling option is required")
	})

	t.Run("missing option name", func(t *testing.T) {
		opts := &SchedulingOptions{
			Options: []SchedulingOption{
				{
					DisplayName: "Test Option",
				},
			},
		}
		errs := validateSchedulingOptions(opts, field.NewPath("spec", "schedulingOptions"))
		assert.Len(t, errs, 1)
		assert.Contains(t, errs[0].Error(), "name")
	})

	t.Run("missing option displayName", func(t *testing.T) {
		opts := &SchedulingOptions{
			Options: []SchedulingOption{
				{
					Name: "test",
				},
			},
		}
		errs := validateSchedulingOptions(opts, field.NewPath("spec", "schedulingOptions"))
		assert.Len(t, errs, 1)
		assert.Contains(t, errs[0].Error(), "displayName")
	})

	t.Run("duplicate option names", func(t *testing.T) {
		opts := &SchedulingOptions{
			Options: []SchedulingOption{
				{
					Name:        "sriov",
					DisplayName: "SRIOV Option 1",
				},
				{
					Name:        "sriov",
					DisplayName: "SRIOV Option 2",
				},
			},
		}
		errs := validateSchedulingOptions(opts, field.NewPath("spec", "schedulingOptions"))
		assert.Len(t, errs, 1)
		assert.Contains(t, errs[0].Error(), "Duplicate")
	})

	t.Run("multiple defaults not allowed", func(t *testing.T) {
		opts := &SchedulingOptions{
			Options: []SchedulingOption{
				{
					Name:        "option1",
					DisplayName: "Option 1",
					Default:     true,
				},
				{
					Name:        "option2",
					DisplayName: "Option 2",
					Default:     true,
				},
			},
		}
		errs := validateSchedulingOptions(opts, field.NewPath("spec", "schedulingOptions"))
		assert.Len(t, errs, 1)
		assert.Contains(t, errs[0].Error(), "only one option can be marked as default")
	})

	t.Run("option with scheduling constraints", func(t *testing.T) {
		opts := &SchedulingOptions{
			Required: true,
			Options: []SchedulingOption{
				{
					Name:        "sriov",
					DisplayName: "SRIOV Nodes",
					SchedulingConstraints: &SchedulingConstraints{
						NodeSelector: map[string]string{
							"network.kubernetes.io/sriov": "true",
						},
					},
				},
			},
		}
		errs := validateSchedulingOptions(opts, field.NewPath("spec", "schedulingOptions"))
		assert.Empty(t, errs)
	})

	t.Run("option with allowed groups", func(t *testing.T) {
		opts := &SchedulingOptions{
			Options: []SchedulingOption{
				{
					Name:          "privileged",
					DisplayName:   "Privileged Nodes",
					AllowedGroups: []string{"admin-group"},
					AllowedUsers:  []string{"admin@example.com"},
				},
			},
		}
		errs := validateSchedulingOptions(opts, field.NewPath("spec", "schedulingOptions"))
		assert.Empty(t, errs)
	})
}

func TestDebugSessionTemplate_WithSchedulingOptions(t *testing.T) {
	t.Run("valid template with scheduling options", func(t *testing.T) {
		template := &DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-template",
			},
			Spec: DebugSessionTemplateSpec{
				Mode: DebugSessionModeWorkload,
				PodTemplateRef: &DebugPodTemplateReference{
					Name: "pod-template",
				},
				SchedulingOptions: &SchedulingOptions{
					Required: true,
					Options: []SchedulingOption{
						{
							Name:        "sriov",
							DisplayName: "SRIOV Nodes",
							Default:     true,
						},
						{
							Name:        "standard",
							DisplayName: "Standard Nodes",
						},
					},
				},
			},
		}
		result := ValidateDebugSessionTemplate(template)
		assert.True(t, result.IsValid(), "expected valid, got errors: %s", result.ErrorMessage())
	})

	t.Run("template with scheduling constraints", func(t *testing.T) {
		template := &DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-template",
			},
			Spec: DebugSessionTemplateSpec{
				Mode: DebugSessionModeWorkload,
				PodTemplateRef: &DebugPodTemplateReference{
					Name: "pod-template",
				},
				SchedulingConstraints: &SchedulingConstraints{
					NodeSelector: map[string]string{
						"node-pool": "general",
					},
					DeniedNodes: []string{"control-plane-*"},
					DeniedNodeLabels: map[string]string{
						"node-role.kubernetes.io/control-plane": "*",
					},
				},
			},
		}
		result := ValidateDebugSessionTemplate(template)
		assert.True(t, result.IsValid(), "expected valid, got errors: %s", result.ErrorMessage())
	})

	t.Run("template with both constraints and options", func(t *testing.T) {
		template := &DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-template",
			},
			Spec: DebugSessionTemplateSpec{
				Mode: DebugSessionModeWorkload,
				PodTemplateRef: &DebugPodTemplateReference{
					Name: "pod-template",
				},
				// Base constraints that apply to all options
				SchedulingConstraints: &SchedulingConstraints{
					DeniedNodeLabels: map[string]string{
						"node-role.kubernetes.io/control-plane": "*",
					},
				},
				// Options that add additional constraints
				SchedulingOptions: &SchedulingOptions{
					Options: []SchedulingOption{
						{
							Name:        "sriov",
							DisplayName: "SRIOV Nodes",
							SchedulingConstraints: &SchedulingConstraints{
								NodeSelector: map[string]string{
									"network.kubernetes.io/sriov": "true",
								},
							},
						},
					},
				},
			},
		}
		result := ValidateDebugSessionTemplate(template)
		assert.True(t, result.IsValid(), "expected valid, got errors: %s", result.ErrorMessage())
	})

	t.Run("template with invalid scheduling options", func(t *testing.T) {
		template := &DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-template",
			},
			Spec: DebugSessionTemplateSpec{
				Mode: DebugSessionModeWorkload,
				PodTemplateRef: &DebugPodTemplateReference{
					Name: "pod-template",
				},
				SchedulingOptions: &SchedulingOptions{
					Options: []SchedulingOption{}, // Empty - should fail
				},
			},
		}
		result := ValidateDebugSessionTemplate(template)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "at least one scheduling option is required")
	})
}

// TestValidateNamespaceConstraints tests the NamespaceConstraints validation.
func TestValidateNamespaceConstraints(t *testing.T) {
	t.Run("nil namespace constraints", func(t *testing.T) {
		errs := validateNamespaceConstraints(nil, field.NewPath("spec", "namespaceConstraints"))
		assert.Empty(t, errs)
	})

	t.Run("valid namespace constraints with allowed patterns", func(t *testing.T) {
		nc := &NamespaceConstraints{
			AllowedNamespaces: &NamespaceFilter{
				Patterns: []string{"debug-*", "test-*"},
			},
			DefaultNamespace: "debug-default",
		}
		errs := validateNamespaceConstraints(nc, field.NewPath("spec", "namespaceConstraints"))
		// Should be valid because default matches wildcard pattern
		assert.Empty(t, errs)
	})

	t.Run("valid namespace constraints with selector terms", func(t *testing.T) {
		nc := &NamespaceConstraints{
			AllowedNamespaces: &NamespaceFilter{
				SelectorTerms: []NamespaceSelectorTerm{
					{
						MatchLabels: map[string]string{
							"debug-enabled": "true",
						},
					},
				},
			},
			DefaultNamespace: "my-namespace",
		}
		errs := validateNamespaceConstraints(nc, field.NewPath("spec", "namespaceConstraints"))
		// Should be valid because selector terms take precedence
		assert.Empty(t, errs)
	})

	t.Run("empty allowed namespaces filter", func(t *testing.T) {
		nc := &NamespaceConstraints{
			AllowedNamespaces: &NamespaceFilter{
				// Empty - should fail
			},
		}
		errs := validateNamespaceConstraints(nc, field.NewPath("spec", "namespaceConstraints"))
		assert.Len(t, errs, 1)
		assert.Contains(t, errs[0].Error(), "patterns or selectorTerms must be specified")
	})

	t.Run("empty denied namespaces filter", func(t *testing.T) {
		nc := &NamespaceConstraints{
			DeniedNamespaces: &NamespaceFilter{
				// Empty - should fail
			},
		}
		errs := validateNamespaceConstraints(nc, field.NewPath("spec", "namespaceConstraints"))
		assert.Len(t, errs, 1)
		assert.Contains(t, errs[0].Error(), "patterns or selectorTerms must be specified")
	})

	t.Run("default namespace in denied patterns", func(t *testing.T) {
		nc := &NamespaceConstraints{
			DeniedNamespaces: &NamespaceFilter{
				Patterns: []string{"kube-system", "debug-prod"},
			},
			DefaultNamespace: "debug-prod",
		}
		errs := validateNamespaceConstraints(nc, field.NewPath("spec", "namespaceConstraints"))
		assert.Len(t, errs, 1)
		assert.Contains(t, errs[0].Error(), "default namespace cannot be in the denied namespaces")
	})

	t.Run("default namespace not in allowed patterns without wildcards", func(t *testing.T) {
		nc := &NamespaceConstraints{
			AllowedNamespaces: &NamespaceFilter{
				Patterns: []string{"debug-ns-1", "debug-ns-2"},
			},
			DefaultNamespace: "debug-ns-3",
		}
		errs := validateNamespaceConstraints(nc, field.NewPath("spec", "namespaceConstraints"))
		assert.Len(t, errs, 1)
		assert.Contains(t, errs[0].Error(), "default namespace must be in the allowed namespaces")
	})

	t.Run("valid with denied and allowed namespaces", func(t *testing.T) {
		nc := &NamespaceConstraints{
			AllowedNamespaces: &NamespaceFilter{
				Patterns: []string{"debug-*"},
			},
			DeniedNamespaces: &NamespaceFilter{
				Patterns: []string{"kube-*", "default"},
			},
			DefaultNamespace:   "debug-main",
			AllowUserNamespace: true,
		}
		errs := validateNamespaceConstraints(nc, field.NewPath("spec", "namespaceConstraints"))
		assert.Empty(t, errs)
	})
}

// TestValidateImpersonationConfig tests the ImpersonationConfig validation.
func TestValidateImpersonationConfig(t *testing.T) {
	t.Run("nil impersonation config", func(t *testing.T) {
		errs := validateImpersonationConfig(nil, field.NewPath("spec", "impersonation"))
		assert.Empty(t, errs)
	})

	t.Run("valid with serviceAccountRef", func(t *testing.T) {
		ic := &ImpersonationConfig{
			ServiceAccountRef: &ServiceAccountReference{
				Name:      "debug-deployer",
				Namespace: "breakglass-system",
			},
		}
		errs := validateImpersonationConfig(ic, field.NewPath("spec", "impersonation"))
		assert.Empty(t, errs)
	})

	t.Run("serviceAccountRef missing name", func(t *testing.T) {
		ic := &ImpersonationConfig{
			ServiceAccountRef: &ServiceAccountReference{
				Namespace: "default",
			},
		}
		errs := validateImpersonationConfig(ic, field.NewPath("spec", "impersonation"))
		assert.Len(t, errs, 1)
		assert.Contains(t, errs[0].Error(), "name is required")
	})

	t.Run("serviceAccountRef missing namespace", func(t *testing.T) {
		ic := &ImpersonationConfig{
			ServiceAccountRef: &ServiceAccountReference{
				Name: "my-sa",
			},
		}
		errs := validateImpersonationConfig(ic, field.NewPath("spec", "impersonation"))
		assert.Len(t, errs, 1)
		assert.Contains(t, errs[0].Error(), "namespace is required")
	})
}

// TestDebugSessionTemplate_WithNamespaceConstraints tests template validation with namespace constraints.
func TestDebugSessionTemplate_WithNamespaceConstraints(t *testing.T) {
	t.Run("valid template with namespace constraints", func(t *testing.T) {
		template := &DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-template",
			},
			Spec: DebugSessionTemplateSpec{
				Mode: DebugSessionModeWorkload,
				PodTemplateRef: &DebugPodTemplateReference{
					Name: "pod-template",
				},
				NamespaceConstraints: &NamespaceConstraints{
					AllowedNamespaces: &NamespaceFilter{
						Patterns: []string{"debug-*"},
					},
					DefaultNamespace:   "debug-main",
					AllowUserNamespace: true,
				},
			},
		}
		result := ValidateDebugSessionTemplate(template)
		assert.True(t, result.IsValid(), "expected valid, got errors: %s", result.ErrorMessage())
	})

	t.Run("template with invalid namespace constraints", func(t *testing.T) {
		template := &DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-template",
			},
			Spec: DebugSessionTemplateSpec{
				Mode: DebugSessionModeWorkload,
				PodTemplateRef: &DebugPodTemplateReference{
					Name: "pod-template",
				},
				NamespaceConstraints: &NamespaceConstraints{
					AllowedNamespaces: &NamespaceFilter{
						// Empty - invalid
					},
				},
			},
		}
		result := ValidateDebugSessionTemplate(template)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "patterns or selectorTerms must be specified")
	})
}

// TestDebugSessionTemplate_WithImpersonation tests template validation with impersonation config.
func TestDebugSessionTemplate_WithImpersonation(t *testing.T) {
	t.Run("valid template with serviceAccountRef impersonation", func(t *testing.T) {
		template := &DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-template",
			},
			Spec: DebugSessionTemplateSpec{
				Mode: DebugSessionModeWorkload,
				PodTemplateRef: &DebugPodTemplateReference{
					Name: "pod-template",
				},
				Impersonation: &ImpersonationConfig{
					ServiceAccountRef: &ServiceAccountReference{
						Name:      "debug-deployer",
						Namespace: "breakglass-system",
					},
				},
			},
		}
		result := ValidateDebugSessionTemplate(template)
		assert.True(t, result.IsValid(), "expected valid, got errors: %s", result.ErrorMessage())
	})

	t.Run("valid template with existing SA impersonation", func(t *testing.T) {
		template := &DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-template",
			},
			Spec: DebugSessionTemplateSpec{
				Mode: DebugSessionModeWorkload,
				PodTemplateRef: &DebugPodTemplateReference{
					Name: "pod-template",
				},
				Impersonation: &ImpersonationConfig{
					ServiceAccountRef: &ServiceAccountReference{
						Name:      "debug-sa",
						Namespace: "breakglass-system",
					},
				},
			},
		}
		result := ValidateDebugSessionTemplate(template)
		assert.True(t, result.IsValid(), "expected valid, got errors: %s", result.ErrorMessage())
	})

	t.Run("template with incomplete impersonation SA ref", func(t *testing.T) {
		template := &DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-template",
			},
			Spec: DebugSessionTemplateSpec{
				Mode: DebugSessionModeWorkload,
				PodTemplateRef: &DebugPodTemplateReference{
					Name: "pod-template",
				},
				Impersonation: &ImpersonationConfig{
					ServiceAccountRef: &ServiceAccountReference{
						Name: "existing-sa",
						// Missing namespace
					},
				},
			},
		}
		result := ValidateDebugSessionTemplate(template)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "namespace is required")
	})
}

// ==================== Debug Session Template New Features Tests ====================

func TestValidateDebugSessionNotificationConfig(t *testing.T) {
	fldPath := field.NewPath("spec", "notification")

	t.Run("nil config is valid", func(t *testing.T) {
		errs := validateDebugSessionNotificationConfig(nil, fldPath)
		assert.Empty(t, errs)
	})

	t.Run("valid enabled config", func(t *testing.T) {
		config := &DebugSessionNotificationConfig{
			Enabled: true,
		}
		errs := validateDebugSessionNotificationConfig(config, fldPath)
		assert.Empty(t, errs)
	})

	t.Run("valid config with excluded recipients", func(t *testing.T) {
		config := &DebugSessionNotificationConfig{
			ExcludedRecipients: &NotificationExclusions{
				Users:  []string{"bot@example.com"},
				Groups: []string{"bots"},
			},
		}
		errs := validateDebugSessionNotificationConfig(config, fldPath)
		assert.Empty(t, errs)
	})

	t.Run("empty user in excluded recipients", func(t *testing.T) {
		config := &DebugSessionNotificationConfig{
			ExcludedRecipients: &NotificationExclusions{
				Users: []string{""},
			},
		}
		errs := validateDebugSessionNotificationConfig(config, fldPath)
		assert.NotEmpty(t, errs)
	})

	t.Run("empty group in excluded recipients", func(t *testing.T) {
		config := &DebugSessionNotificationConfig{
			ExcludedRecipients: &NotificationExclusions{
				Groups: []string{""},
			},
		}
		errs := validateDebugSessionNotificationConfig(config, fldPath)
		assert.NotEmpty(t, errs)
	})

	t.Run("valid additional recipients", func(t *testing.T) {
		config := &DebugSessionNotificationConfig{
			AdditionalRecipients: []string{"admin@example.com", "ops@example.com"},
		}
		errs := validateDebugSessionNotificationConfig(config, fldPath)
		assert.Empty(t, errs)
	})

	t.Run("invalid email in additional recipients", func(t *testing.T) {
		config := &DebugSessionNotificationConfig{
			AdditionalRecipients: []string{"not-an-email"},
		}
		errs := validateDebugSessionNotificationConfig(config, fldPath)
		assert.NotEmpty(t, errs)
		assert.Contains(t, errs[0].Error(), "email")
	})

	t.Run("empty email in additional recipients", func(t *testing.T) {
		config := &DebugSessionNotificationConfig{
			AdditionalRecipients: []string{""},
		}
		errs := validateDebugSessionNotificationConfig(config, fldPath)
		assert.NotEmpty(t, errs)
	})
}

func TestValidateDebugRequestReasonConfig(t *testing.T) {
	fldPath := field.NewPath("spec", "requestReason")

	t.Run("nil config is valid", func(t *testing.T) {
		errs := validateDebugRequestReasonConfig(nil, fldPath)
		assert.Empty(t, errs)
	})

	t.Run("valid mandatory config", func(t *testing.T) {
		config := &DebugRequestReasonConfig{
			Mandatory: true,
			MinLength: 10,
			MaxLength: 500,
		}
		errs := validateDebugRequestReasonConfig(config, fldPath)
		assert.Empty(t, errs)
	})

	t.Run("valid optional config with description", func(t *testing.T) {
		config := &DebugRequestReasonConfig{
			Mandatory:   false,
			Description: "Please describe the issue:",
		}
		errs := validateDebugRequestReasonConfig(config, fldPath)
		assert.Empty(t, errs)
	})

	t.Run("minLength greater than maxLength", func(t *testing.T) {
		config := &DebugRequestReasonConfig{
			Mandatory: true,
			MinLength: 100,
			MaxLength: 50,
		}
		errs := validateDebugRequestReasonConfig(config, fldPath)
		assert.NotEmpty(t, errs)
		assert.Contains(t, errs[0].Error(), "minLength")
	})

	t.Run("valid suggested reasons", func(t *testing.T) {
		config := &DebugRequestReasonConfig{
			SuggestedReasons: []string{"Bug investigation", "Performance tuning"},
		}
		errs := validateDebugRequestReasonConfig(config, fldPath)
		assert.Empty(t, errs)
	})

	t.Run("empty suggested reason", func(t *testing.T) {
		config := &DebugRequestReasonConfig{
			SuggestedReasons: []string{"Valid reason", ""},
		}
		errs := validateDebugRequestReasonConfig(config, fldPath)
		assert.NotEmpty(t, errs)
	})

	t.Run("duplicate suggested reasons", func(t *testing.T) {
		config := &DebugRequestReasonConfig{
			SuggestedReasons: []string{"Bug investigation", "Bug investigation"},
		}
		errs := validateDebugRequestReasonConfig(config, fldPath)
		assert.NotEmpty(t, errs)
		assert.Contains(t, errs[0].Error(), "Duplicate")
	})
}

func TestValidateDebugApprovalReasonConfig(t *testing.T) {
	fldPath := field.NewPath("spec", "approvalReason")

	t.Run("nil config is valid", func(t *testing.T) {
		errs := validateDebugApprovalReasonConfig(nil, fldPath)
		assert.Empty(t, errs)
	})

	t.Run("valid mandatory config", func(t *testing.T) {
		config := &DebugApprovalReasonConfig{
			Mandatory: true,
			MinLength: 5,
		}
		errs := validateDebugApprovalReasonConfig(config, fldPath)
		assert.Empty(t, errs)
	})

	t.Run("negative minLength", func(t *testing.T) {
		config := &DebugApprovalReasonConfig{
			Mandatory: true,
			MinLength: -1,
		}
		errs := validateDebugApprovalReasonConfig(config, fldPath)
		assert.NotEmpty(t, errs)
		assert.Contains(t, errs[0].Error(), "minLength")
	})
}

func TestValidateDebugResourceQuotaConfig(t *testing.T) {
	fldPath := field.NewPath("spec", "resourceQuota")

	t.Run("nil config is valid", func(t *testing.T) {
		errs := validateDebugResourceQuotaConfig(nil, fldPath)
		assert.Empty(t, errs)
	})

	t.Run("valid limits config", func(t *testing.T) {
		config := &DebugResourceQuotaConfig{
			MaxCPU:    "2",
			MaxMemory: "4Gi",
		}
		errs := validateDebugResourceQuotaConfig(config, fldPath)
		assert.Empty(t, errs)
	})

	t.Run("valid limits with storage", func(t *testing.T) {
		config := &DebugResourceQuotaConfig{
			MaxCPU:     "4",
			MaxMemory:  "8Gi",
			MaxStorage: "10Gi",
		}
		errs := validateDebugResourceQuotaConfig(config, fldPath)
		assert.Empty(t, errs)
	})

	t.Run("invalid CPU format", func(t *testing.T) {
		config := &DebugResourceQuotaConfig{
			MaxCPU: "invalid",
		}
		errs := validateDebugResourceQuotaConfig(config, fldPath)
		assert.NotEmpty(t, errs)
		assert.Contains(t, errs[0].Error(), "maxCPU")
	})

	t.Run("invalid memory format", func(t *testing.T) {
		config := &DebugResourceQuotaConfig{
			MaxMemory: "not-a-quantity",
		}
		errs := validateDebugResourceQuotaConfig(config, fldPath)
		assert.NotEmpty(t, errs)
		assert.Contains(t, errs[0].Error(), "maxMemory")
	})

	t.Run("invalid storage format", func(t *testing.T) {
		config := &DebugResourceQuotaConfig{
			MaxStorage: "bad",
		}
		errs := validateDebugResourceQuotaConfig(config, fldPath)
		assert.NotEmpty(t, errs)
		assert.Contains(t, errs[0].Error(), "maxStorage")
	})
}

func TestValidateDebugPDBConfig(t *testing.T) {
	fldPath := field.NewPath("spec", "podDisruptionBudget")

	t.Run("nil config is valid", func(t *testing.T) {
		errs := validateDebugPDBConfig(nil, fldPath)
		assert.Empty(t, errs)
	})

	t.Run("valid minAvailable", func(t *testing.T) {
		minAvailable := int32(1)
		config := &DebugPDBConfig{
			MinAvailable: &minAvailable,
		}
		errs := validateDebugPDBConfig(config, fldPath)
		assert.Empty(t, errs)
	})

	t.Run("valid maxUnavailable", func(t *testing.T) {
		maxUnavailable := int32(2)
		config := &DebugPDBConfig{
			MaxUnavailable: &maxUnavailable,
		}
		errs := validateDebugPDBConfig(config, fldPath)
		assert.Empty(t, errs)
	})

	t.Run("both minAvailable and maxUnavailable specified", func(t *testing.T) {
		minAvailable := int32(1)
		maxUnavailable := int32(1)
		config := &DebugPDBConfig{
			MinAvailable:   &minAvailable,
			MaxUnavailable: &maxUnavailable,
		}
		errs := validateDebugPDBConfig(config, fldPath)
		assert.NotEmpty(t, errs)
		assert.Contains(t, errs[0].Error(), "only one of")
	})

	t.Run("negative minAvailable", func(t *testing.T) {
		minAvailable := int32(-1)
		config := &DebugPDBConfig{
			MinAvailable: &minAvailable,
		}
		errs := validateDebugPDBConfig(config, fldPath)
		assert.NotEmpty(t, errs)
		assert.Contains(t, errs[0].Error(), "minAvailable")
	})

	t.Run("negative maxUnavailable", func(t *testing.T) {
		maxUnavailable := int32(-1)
		config := &DebugPDBConfig{
			MaxUnavailable: &maxUnavailable,
		}
		errs := validateDebugPDBConfig(config, fldPath)
		assert.NotEmpty(t, errs)
		assert.Contains(t, errs[0].Error(), "maxUnavailable")
	})
}

func TestValidateBindingTimeWindow(t *testing.T) {
	fldPath := field.NewPath("spec")

	t.Run("both nil is valid", func(t *testing.T) {
		errs := validateBindingTimeWindow(nil, nil, fldPath)
		assert.Empty(t, errs)
	})

	t.Run("only effectiveFrom is valid", func(t *testing.T) {
		now := metav1.Now()
		errs := validateBindingTimeWindow(&now, nil, fldPath)
		assert.Empty(t, errs)
	})

	t.Run("only expiresAt is valid", func(t *testing.T) {
		now := metav1.Now()
		errs := validateBindingTimeWindow(nil, &now, fldPath)
		assert.Empty(t, errs)
	})

	t.Run("valid time window", func(t *testing.T) {
		now := metav1.Now()
		later := metav1.NewTime(now.Add(24 * 60 * 60 * 1_000_000_000)) // 24 hours later
		errs := validateBindingTimeWindow(&now, &later, fldPath)
		assert.Empty(t, errs)
	})

	t.Run("expiresAt before effectiveFrom is invalid", func(t *testing.T) {
		now := metav1.Now()
		earlier := metav1.NewTime(now.Add(-24 * 60 * 60 * 1_000_000_000)) // 24 hours earlier
		errs := validateBindingTimeWindow(&now, &earlier, fldPath)
		assert.NotEmpty(t, errs)
		assert.Contains(t, errs[0].Error(), "expiresAt must be after effectiveFrom")
	})
}

func TestDebugSessionTemplate_WithNewFeatures(t *testing.T) {
	t.Run("valid template with notification config", func(t *testing.T) {
		template := &DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-template",
			},
			Spec: DebugSessionTemplateSpec{
				Mode: DebugSessionModeWorkload,
				PodTemplateRef: &DebugPodTemplateReference{
					Name: "pod-template",
				},
				Notification: &DebugSessionNotificationConfig{
					Enabled: true,
				},
			},
		}
		result := ValidateDebugSessionTemplate(template)
		assert.True(t, result.IsValid(), "expected valid, got errors: %s", result.ErrorMessage())
	})

	t.Run("valid template with request reason config", func(t *testing.T) {
		template := &DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-template",
			},
			Spec: DebugSessionTemplateSpec{
				Mode: DebugSessionModeWorkload,
				PodTemplateRef: &DebugPodTemplateReference{
					Name: "pod-template",
				},
				RequestReason: &DebugRequestReasonConfig{
					Mandatory: true,
					MinLength: 10,
					MaxLength: 500,
				},
			},
		}
		result := ValidateDebugSessionTemplate(template)
		assert.True(t, result.IsValid(), "expected valid, got errors: %s", result.ErrorMessage())
	})

	t.Run("valid template with resource quota", func(t *testing.T) {
		template := &DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-template",
			},
			Spec: DebugSessionTemplateSpec{
				Mode: DebugSessionModeWorkload,
				PodTemplateRef: &DebugPodTemplateReference{
					Name: "pod-template",
				},
				ResourceQuota: &DebugResourceQuotaConfig{
					MaxCPU:    "2",
					MaxMemory: "4Gi",
				},
			},
		}
		result := ValidateDebugSessionTemplate(template)
		assert.True(t, result.IsValid(), "expected valid, got errors: %s", result.ErrorMessage())
	})

	t.Run("valid template with grace period", func(t *testing.T) {
		template := &DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-template",
			},
			Spec: DebugSessionTemplateSpec{
				Mode: DebugSessionModeWorkload,
				PodTemplateRef: &DebugPodTemplateReference{
					Name: "pod-template",
				},
				GracePeriodBeforeExpiry: "10m",
			},
		}
		result := ValidateDebugSessionTemplate(template)
		assert.True(t, result.IsValid(), "expected valid, got errors: %s", result.ErrorMessage())
	})

	t.Run("invalid grace period format", func(t *testing.T) {
		template := &DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-template",
			},
			Spec: DebugSessionTemplateSpec{
				Mode: DebugSessionModeWorkload,
				PodTemplateRef: &DebugPodTemplateReference{
					Name: "pod-template",
				},
				GracePeriodBeforeExpiry: "invalid",
			},
		}
		result := ValidateDebugSessionTemplate(template)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "gracePeriodBeforeExpiry")
	})

	t.Run("deprecated template generates warning", func(t *testing.T) {
		template := &DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-template",
			},
			Spec: DebugSessionTemplateSpec{
				Mode: DebugSessionModeWorkload,
				PodTemplateRef: &DebugPodTemplateReference{
					Name: "pod-template",
				},
				Deprecated:         true,
				DeprecationMessage: "Use new-template instead",
			},
		}
		result := ValidateDebugSessionTemplate(template)
		assert.True(t, result.IsValid(), "deprecated template should still be valid, got errors: %s", result.ErrorMessage())
		assert.NotEmpty(t, result.Warnings, "expected deprecation warning")
	})

	t.Run("valid template with labels and annotations", func(t *testing.T) {
		template := &DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-template",
			},
			Spec: DebugSessionTemplateSpec{
				Mode: DebugSessionModeWorkload,
				PodTemplateRef: &DebugPodTemplateReference{
					Name: "pod-template",
				},
				Labels: map[string]string{
					"env":  "production",
					"team": "platform",
				},
				Annotations: map[string]string{
					"description": "Production debug template",
				},
			},
		}
		result := ValidateDebugSessionTemplate(template)
		assert.True(t, result.IsValid(), "expected valid, got errors: %s", result.ErrorMessage())
	})
}
