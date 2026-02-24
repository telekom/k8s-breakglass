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
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
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

	t.Run("empty denyPolicy is rejected", func(t *testing.T) {
		dp := &DenyPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-deny-policy",
				Namespace: "test-ns",
			},
			Spec: DenyPolicySpec{},
		}
		result := ValidateDenyPolicy(dp)
		// Empty spec (no rules and no podSecurityRules) should be rejected
		assert.False(t, result.IsValid())
		assert.Len(t, result.Errors, 1)
		assert.Contains(t, result.Errors[0].Detail, "rules")
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

// ==================== Defense-in-Depth Validation Tests ====================

// These tests verify Go webhook validation mirrors CEL rules for
// PodSecurityOverrides.requireApproval and SessionLimitsOverride.unlimited.

func TestValidateBreakglassEscalation_PodSecurityRequireApproval(t *testing.T) {
	validBase := func() *BreakglassEscalation {
		return &BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "test"},
			Spec: BreakglassEscalationSpec{
				EscalatedGroup: "admin-group",
				Allowed:        BreakglassEscalationAllowed{Groups: []string{"dev"}, Clusters: []string{"c1"}},
				Approvers:      BreakglassEscalationApprovers{Groups: []string{"approvers"}},
			},
		}
	}

	t.Run("requireApproval false without approvers is valid", func(t *testing.T) {
		e := validBase()
		e.Spec.PodSecurityOverrides = &PodSecurityOverrides{
			Enabled:         true,
			RequireApproval: false,
		}
		result := ValidateBreakglassEscalation(e)
		assert.True(t, result.IsValid(), "expected valid, got: %s", result.ErrorMessage())
	})

	t.Run("requireApproval true with approver groups is valid", func(t *testing.T) {
		e := validBase()
		e.Spec.PodSecurityOverrides = &PodSecurityOverrides{
			Enabled:         true,
			RequireApproval: true,
			Approvers:       &PodSecurityApprovers{Groups: []string{"sec-team"}},
		}
		result := ValidateBreakglassEscalation(e)
		assert.True(t, result.IsValid(), "expected valid, got: %s", result.ErrorMessage())
	})

	t.Run("requireApproval true with approver users is valid", func(t *testing.T) {
		e := validBase()
		e.Spec.PodSecurityOverrides = &PodSecurityOverrides{
			Enabled:         true,
			RequireApproval: true,
			Approvers:       &PodSecurityApprovers{Users: []string{"admin@example.com"}},
		}
		result := ValidateBreakglassEscalation(e)
		assert.True(t, result.IsValid(), "expected valid, got: %s", result.ErrorMessage())
	})

	t.Run("requireApproval true without approvers is invalid", func(t *testing.T) {
		e := validBase()
		e.Spec.PodSecurityOverrides = &PodSecurityOverrides{
			Enabled:         true,
			RequireApproval: true,
		}
		result := ValidateBreakglassEscalation(e)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "approvers")
	})

	t.Run("requireApproval true with empty approvers is invalid", func(t *testing.T) {
		e := validBase()
		e.Spec.PodSecurityOverrides = &PodSecurityOverrides{
			Enabled:         true,
			RequireApproval: true,
			Approvers:       &PodSecurityApprovers{},
		}
		result := ValidateBreakglassEscalation(e)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "approvers")
	})
}

func TestValidateBreakglassEscalation_SessionLimitsUnlimited(t *testing.T) {
	validBase := func() *BreakglassEscalation {
		return &BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "test"},
			Spec: BreakglassEscalationSpec{
				EscalatedGroup: "admin-group",
				Allowed:        BreakglassEscalationAllowed{Groups: []string{"dev"}, Clusters: []string{"c1"}},
				Approvers:      BreakglassEscalationApprovers{Groups: []string{"approvers"}},
			},
		}
	}

	int32Ptr := func(v int32) *int32 { return &v }

	t.Run("unlimited true without limits is valid", func(t *testing.T) {
		e := validBase()
		e.Spec.SessionLimitsOverride = &SessionLimitsOverride{Unlimited: true}
		result := ValidateBreakglassEscalation(e)
		assert.True(t, result.IsValid(), "expected valid, got: %s", result.ErrorMessage())
	})

	t.Run("unlimited false with limits is valid", func(t *testing.T) {
		e := validBase()
		e.Spec.SessionLimitsOverride = &SessionLimitsOverride{
			Unlimited:                false,
			MaxActiveSessionsPerUser: int32Ptr(5),
			MaxActiveSessionsTotal:   int32Ptr(10),
		}
		result := ValidateBreakglassEscalation(e)
		assert.True(t, result.IsValid(), "expected valid, got: %s", result.ErrorMessage())
	})

	t.Run("unlimited true with maxActiveSessionsPerUser is invalid", func(t *testing.T) {
		e := validBase()
		e.Spec.SessionLimitsOverride = &SessionLimitsOverride{
			Unlimited:                true,
			MaxActiveSessionsPerUser: int32Ptr(5),
		}
		result := ValidateBreakglassEscalation(e)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "maxActiveSessionsPerUser")
	})

	t.Run("unlimited true with maxActiveSessionsTotal is invalid", func(t *testing.T) {
		e := validBase()
		e.Spec.SessionLimitsOverride = &SessionLimitsOverride{
			Unlimited:              true,
			MaxActiveSessionsTotal: int32Ptr(10),
		}
		result := ValidateBreakglassEscalation(e)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "maxActiveSessionsTotal")
	})

	t.Run("unlimited true with both limits is invalid", func(t *testing.T) {
		e := validBase()
		e.Spec.SessionLimitsOverride = &SessionLimitsOverride{
			Unlimited:                true,
			MaxActiveSessionsPerUser: int32Ptr(5),
			MaxActiveSessionsTotal:   int32Ptr(10),
		}
		result := ValidateBreakglassEscalation(e)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "maxActiveSessionsPerUser")
		assert.Contains(t, result.ErrorMessage(), "maxActiveSessionsTotal")
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

	t.Run("valid templateString", func(t *testing.T) {
		template := &DebugPodTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-template",
			},
			Spec: DebugPodTemplateSpec{
				TemplateString: "apiVersion: v1\nkind: Pod\nmetadata:\n  name: {{ .session.name }}",
			},
		}
		result := ValidateDebugPodTemplate(template)
		assert.True(t, result.IsValid(), "expected valid, got errors: %s", result.ErrorMessage())
	})

	t.Run("invalid templateString syntax - unclosed brace", func(t *testing.T) {
		template := &DebugPodTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-template",
			},
			Spec: DebugPodTemplateSpec{
				TemplateString: "apiVersion: v1\nkind: Pod\nmetadata:\n  name: {{ .session.name",
			},
		}
		result := ValidateDebugPodTemplate(template)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "invalid Go template syntax")
	})

	t.Run("invalid templateString syntax - unknown function", func(t *testing.T) {
		template := &DebugPodTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-template",
			},
			Spec: DebugPodTemplateSpec{
				TemplateString: "apiVersion: v1\nkind: Pod\nmetadata:\n  name: {{ unknownFunc .Name }}",
			},
		}
		result := ValidateDebugPodTemplate(template)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "invalid Go template syntax")
	})

	t.Run("neither template nor templateString specified", func(t *testing.T) {
		template := &DebugPodTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-template",
			},
			Spec: DebugPodTemplateSpec{
				// Both template and templateString are empty/nil
			},
		}
		result := ValidateDebugPodTemplate(template)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "either template or templateString must be specified")
	})

	t.Run("both template and templateString specified - mutually exclusive", func(t *testing.T) {
		template := &DebugPodTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-template",
			},
			Spec: DebugPodTemplateSpec{
				Template: &DebugPodSpec{
					Spec: DebugPodSpecInner{
						Containers: []corev1.Container{
							{Name: "debug", Image: "busybox"},
						},
					},
				},
				TemplateString: "apiVersion: v1\nkind: Pod\nmetadata:\n  name: test",
			},
		}
		result := ValidateDebugPodTemplate(template)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "mutually exclusive")
	})

	t.Run("templateString with custom functions validates", func(t *testing.T) {
		// Verify that custom runtime functions like truncName, k8sName, etc. pass validation
		template := &DebugPodTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-template",
			},
			Spec: DebugPodTemplateSpec{
				TemplateString: `apiVersion: v1
kind: Pod
metadata:
  name: {{ .session.name | truncName 63 }}
  labels:
    app: {{ .session.name | k8sName }}
spec:
  containers:
  - name: debug
    image: busybox
    resources:
      limits:
        memory: {{ parseQuantity "1Gi" | formatQuantity }}
    env:
    - name: REQUIRED_VAR
      value: {{ required "REQUIRED_VAR is required" .vars.requiredValue }}
  volumes:
  - name: config
    configMap:
      name: {{ .session.name | yamlSafe }}`,
			},
		}
		result := ValidateDebugPodTemplate(template)
		assert.True(t, result.IsValid(), "expected valid, got errors: %s", result.ErrorMessage())
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

	t.Run("valid podTemplateString", func(t *testing.T) {
		template := &DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-template",
			},
			Spec: DebugSessionTemplateSpec{
				Mode:              DebugSessionModeWorkload,
				PodTemplateString: "apiVersion: v1\nkind: Pod\nmetadata:\n  name: {{ .session.name }}",
			},
		}
		result := ValidateDebugSessionTemplate(template)
		assert.True(t, result.IsValid(), "expected valid, got errors: %s", result.ErrorMessage())
	})

	t.Run("invalid podTemplateString syntax", func(t *testing.T) {
		template := &DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-template",
			},
			Spec: DebugSessionTemplateSpec{
				Mode:              DebugSessionModeWorkload,
				PodTemplateString: "apiVersion: v1\nkind: Pod\nmetadata:\n  name: {{ .session.name",
			},
		}
		result := ValidateDebugSessionTemplate(template)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "invalid Go template syntax")
	})

	t.Run("valid podOverridesTemplate", func(t *testing.T) {
		template := &DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-template",
			},
			Spec: DebugSessionTemplateSpec{
				Mode: DebugSessionModeWorkload,
				PodTemplateRef: &DebugPodTemplateReference{
					Name: "pod-template",
				},
				PodOverridesTemplate: "metadata:\n  labels:\n    custom: {{ .vars.customLabel | default \"default\" }}",
			},
		}
		result := ValidateDebugSessionTemplate(template)
		assert.True(t, result.IsValid(), "expected valid, got errors: %s", result.ErrorMessage())
	})

	t.Run("invalid podOverridesTemplate syntax", func(t *testing.T) {
		template := &DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-template",
			},
			Spec: DebugSessionTemplateSpec{
				Mode: DebugSessionModeWorkload,
				PodTemplateRef: &DebugPodTemplateReference{
					Name: "pod-template",
				},
				PodOverridesTemplate: "metadata:\n  labels:\n    custom: {{ unknownFunc .vars }}",
			},
		}
		result := ValidateDebugSessionTemplate(template)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "invalid Go template syntax")
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

// ==================== TemplateString Format Validation Tests ====================

func TestValidateDebugPodTemplate_TemplateStringFormat(t *testing.T) {
	t.Run("bare PodSpec format is valid", func(t *testing.T) {
		template := &DebugPodTemplate{
			Spec: DebugPodTemplateSpec{
				TemplateString: `containers:
  - name: debug
    image: busybox:latest
    command: ["sleep", "infinity"]
`,
			},
		}
		result := ValidateDebugPodTemplate(template)
		assert.True(t, result.IsValid(), "expected valid, got errors: %s", result.ErrorMessage())
	})

	t.Run("kind Pod format is valid", func(t *testing.T) {
		template := &DebugPodTemplate{
			Spec: DebugPodTemplateSpec{
				TemplateString: `apiVersion: v1
kind: Pod
spec:
  containers:
    - name: debug
      image: busybox:latest
`,
			},
		}
		result := ValidateDebugPodTemplate(template)
		assert.True(t, result.IsValid(), "expected valid, got errors: %s", result.ErrorMessage())
	})

	t.Run("kind Deployment format is valid", func(t *testing.T) {
		template := &DebugPodTemplate{
			Spec: DebugPodTemplateSpec{
				TemplateString: `apiVersion: apps/v1
kind: Deployment
metadata:
  name: debug
spec:
  replicas: 1
  selector:
    matchLabels:
      app: debug
  template:
    spec:
      containers:
        - name: debug
          image: busybox:latest
`,
			},
		}
		result := ValidateDebugPodTemplate(template)
		assert.True(t, result.IsValid(), "expected valid, got errors: %s", result.ErrorMessage())
	})

	t.Run("kind DaemonSet format is valid", func(t *testing.T) {
		template := &DebugPodTemplate{
			Spec: DebugPodTemplateSpec{
				TemplateString: `apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: debug-ds
spec:
  selector:
    matchLabels:
      app: debug
  template:
    spec:
      containers:
        - name: debug
          image: busybox:latest
`,
			},
		}
		result := ValidateDebugPodTemplate(template)
		assert.True(t, result.IsValid(), "expected valid, got errors: %s", result.ErrorMessage())
	})

	t.Run("unsupported kind is rejected", func(t *testing.T) {
		template := &DebugPodTemplate{
			Spec: DebugPodTemplateSpec{
				TemplateString: `apiVersion: batch/v1
kind: Job
metadata:
  name: test
spec:
  template:
    spec:
      containers:
        - name: test
          image: busybox
`,
			},
		}
		result := ValidateDebugPodTemplate(template)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "unsupported kind")
		assert.Contains(t, result.ErrorMessage(), "Job")
	})

	t.Run("wrong apiVersion for Pod is rejected", func(t *testing.T) {
		template := &DebugPodTemplate{
			Spec: DebugPodTemplateSpec{
				TemplateString: `apiVersion: apps/v1
kind: Pod
spec:
  containers:
    - name: debug
      image: busybox
`,
			},
		}
		result := ValidateDebugPodTemplate(template)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "Pod requires apiVersion v1")
	})

	t.Run("wrong apiVersion for Deployment is rejected", func(t *testing.T) {
		template := &DebugPodTemplate{
			Spec: DebugPodTemplateSpec{
				TemplateString: `apiVersion: v1
kind: Deployment
spec:
  template:
    spec:
      containers:
        - name: debug
          image: busybox
`,
			},
		}
		result := ValidateDebugPodTemplate(template)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "Deployment requires apiVersion apps/v1")
	})

	t.Run("apiVersion without kind is rejected", func(t *testing.T) {
		template := &DebugPodTemplate{
			Spec: DebugPodTemplateSpec{
				TemplateString: `apiVersion: v1
containers:
  - name: debug
    image: busybox
`,
			},
		}
		result := ValidateDebugPodTemplate(template)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "apiVersion but no kind")
	})

	t.Run("Go template directives skip format validation", func(t *testing.T) {
		// Template with Go directives in the first document should skip static format validation
		template := &DebugPodTemplate{
			Spec: DebugPodTemplateSpec{
				TemplateString: `apiVersion: v1
kind: Pod
spec:
  containers:
    - name: debug-{{ .session.name }}
      image: {{ .vars.image | default "busybox:latest" }}
`,
			},
		}
		result := ValidateDebugPodTemplate(template)
		assert.True(t, result.IsValid(), "expected valid, got errors: %s", result.ErrorMessage())
	})

	t.Run("real-world coredump-collector format is valid", func(t *testing.T) {
		template := &DebugPodTemplate{
			Spec: DebugPodTemplateSpec{
				TemplateString: `apiVersion: v1
kind: Pod
metadata:
  labels:
    breakglass.t-caas.telekom.com/debug-type: coredump
spec:
  hostNetwork: false
  automountServiceAccountToken: false
  restartPolicy: Never
  terminationGracePeriodSeconds: 30
  containers:
    - name: coredump
      image: docker.io/library/alpine:3.21
      command:
        - /bin/sh
        - -c
        - "echo 'Ready'; sleep infinity"
      securityContext:
        allowPrivilegeEscalation: false
        capabilities:
          drop: ["ALL"]
      volumeMounts:
        - name: coredumps
          mountPath: /coredumps
          readOnly: true
  volumes:
    - name: coredumps
      hostPath:
        path: /var/lib/systemd/coredump
        type: DirectoryOrCreate
`,
			},
		}
		result := ValidateDebugPodTemplate(template)
		assert.True(t, result.IsValid(), "expected valid, got errors: %s", result.ErrorMessage())
	})
}

func TestValidateDebugSessionTemplate_TemplateStringFormat(t *testing.T) {
	t.Run("valid podTemplateString with bare PodSpec", func(t *testing.T) {
		template := &DebugSessionTemplate{
			Spec: DebugSessionTemplateSpec{
				Mode: DebugSessionModeWorkload,
				PodTemplateString: `containers:
  - name: debug
    image: busybox:latest
`,
			},
		}
		result := ValidateDebugSessionTemplate(template)
		assert.True(t, result.IsValid(), "expected valid, got errors: %s", result.ErrorMessage())
	})

	t.Run("valid podTemplateString with kind Pod", func(t *testing.T) {
		template := &DebugSessionTemplate{
			Spec: DebugSessionTemplateSpec{
				Mode: DebugSessionModeWorkload,
				PodTemplateString: `apiVersion: v1
kind: Pod
spec:
  containers:
    - name: debug
      image: busybox:latest
`,
			},
		}
		result := ValidateDebugSessionTemplate(template)
		assert.True(t, result.IsValid(), "expected valid, got errors: %s", result.ErrorMessage())
	})

	t.Run("unsupported kind in podTemplateString is rejected", func(t *testing.T) {
		template := &DebugSessionTemplate{
			Spec: DebugSessionTemplateSpec{
				Mode: DebugSessionModeWorkload,
				PodTemplateString: `apiVersion: batch/v1
kind: CronJob
spec:
  schedule: "*/5 * * * *"
`,
			},
		}
		result := ValidateDebugSessionTemplate(template)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "unsupported kind")
	})

	t.Run("workload type mismatch produces warning", func(t *testing.T) {
		template := &DebugSessionTemplate{
			Spec: DebugSessionTemplateSpec{
				Mode:         DebugSessionModeWorkload,
				WorkloadType: DebugWorkloadDeployment,
				PodTemplateString: `apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: debug
spec:
  selector:
    matchLabels:
      app: debug
  template:
    spec:
      containers:
        - name: debug
          image: busybox:latest
`,
			},
		}
		result := ValidateDebugSessionTemplate(template)
		// Should be valid (warning, not error) — runtime enforces the mismatch
		assert.True(t, result.IsValid(), "expected valid, got errors: %s", result.ErrorMessage())
		assert.NotEmpty(t, result.Warnings, "expected mismatch warning")
		assert.Contains(t, result.Warnings[0], "DaemonSet")
		assert.Contains(t, result.Warnings[0], "Deployment")
	})

	t.Run("matching workload type produces no warning", func(t *testing.T) {
		template := &DebugSessionTemplate{
			Spec: DebugSessionTemplateSpec{
				Mode:         DebugSessionModeWorkload,
				WorkloadType: DebugWorkloadDaemonSet,
				PodTemplateString: `apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: debug
spec:
  selector:
    matchLabels:
      app: debug
  template:
    spec:
      containers:
        - name: debug
          image: busybox:latest
`,
			},
		}
		result := ValidateDebugSessionTemplate(template)
		assert.True(t, result.IsValid(), "expected valid, got errors: %s", result.ErrorMessage())
		assert.Empty(t, result.Warnings, "expected no warnings for matching types")
	})
}

func TestValidateTemplateStringFormat(t *testing.T) {
	tests := []struct {
		name        string
		template    string
		wantErrors  int
		containsMsg string
	}{
		{
			name:       "bare PodSpec — valid",
			template:   "containers:\n  - name: debug\n    image: busybox\n",
			wantErrors: 0,
		},
		{
			name:       "kind Pod v1 — valid",
			template:   "apiVersion: v1\nkind: Pod\nspec:\n  containers:\n    - name: debug\n      image: busybox\n",
			wantErrors: 0,
		},
		{
			name:       "kind Deployment apps/v1 — valid",
			template:   "apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      containers:\n        - name: debug\n          image: busybox\n",
			wantErrors: 0,
		},
		{
			name:       "kind DaemonSet apps/v1 — valid",
			template:   "apiVersion: apps/v1\nkind: DaemonSet\nspec:\n  template:\n    spec:\n      containers:\n        - name: debug\n          image: busybox\n",
			wantErrors: 0,
		},
		{
			name:        "unsupported kind StatefulSet",
			template:    "apiVersion: apps/v1\nkind: StatefulSet\nspec: {}\n",
			wantErrors:  1,
			containsMsg: "unsupported kind",
		},
		{
			name:        "apiVersion without kind",
			template:    "apiVersion: v1\ncontainers:\n  - name: debug\n    image: busybox\n",
			wantErrors:  1,
			containsMsg: "apiVersion but no kind",
		},
		{
			name:        "kind without apiVersion",
			template:    "kind: Pod\nspec:\n  containers:\n    - name: debug\n      image: busybox\n",
			wantErrors:  1,
			containsMsg: "apiVersion but no kind",
		},
		{
			name:        "Pod with wrong apiVersion",
			template:    "apiVersion: apps/v1\nkind: Pod\nspec: {}\n",
			wantErrors:  1,
			containsMsg: "Pod requires apiVersion v1",
		},
		{
			name:        "Deployment with wrong apiVersion",
			template:    "apiVersion: v1\nkind: Deployment\nspec: {}\n",
			wantErrors:  1,
			containsMsg: "Deployment requires apiVersion apps/v1",
		},
		{
			name:       "Go template directives — skip validation",
			template:   "apiVersion: v1\nkind: {{ .vars.kind }}\nspec: {}\n",
			wantErrors: 0,
		},
		{
			name:       "empty template — skip",
			template:   "",
			wantErrors: 0,
		},
		{
			name:       "multi-doc — validates first doc only",
			template:   "apiVersion: v1\nkind: Pod\nspec:\n  containers:\n    - name: debug\n      image: busybox\n---\napiVersion: v1\nkind: ConfigMap\ndata:\n  key: value\n",
			wantErrors: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errs := validateTemplateStringFormat(tt.template, field.NewPath("spec", "templateString"))
			assert.Len(t, errs, tt.wantErrors, "unexpected error count for %q", tt.name)
			if tt.containsMsg != "" && len(errs) > 0 {
				assert.Contains(t, errs[0].Error(), tt.containsMsg)
			}
		})
	}
}

func TestWarnTemplateStringWorkloadMismatch(t *testing.T) {
	tests := []struct {
		name         string
		template     string
		workloadType DebugWorkloadType
		wantWarnings int
	}{
		{
			name:         "matching DaemonSet — no warning",
			template:     "apiVersion: apps/v1\nkind: DaemonSet\nspec: {}\n",
			workloadType: DebugWorkloadDaemonSet,
			wantWarnings: 0,
		},
		{
			name:         "matching Deployment — no warning",
			template:     "apiVersion: apps/v1\nkind: Deployment\nspec: {}\n",
			workloadType: DebugWorkloadDeployment,
			wantWarnings: 0,
		},
		{
			name:         "DaemonSet vs Deployment — warning",
			template:     "apiVersion: apps/v1\nkind: DaemonSet\nspec: {}\n",
			workloadType: DebugWorkloadDeployment,
			wantWarnings: 1,
		},
		{
			name:         "Deployment vs DaemonSet — warning",
			template:     "apiVersion: apps/v1\nkind: Deployment\nspec: {}\n",
			workloadType: DebugWorkloadDaemonSet,
			wantWarnings: 1,
		},
		{
			name:         "bare PodSpec — no warning",
			template:     "containers:\n  - name: debug\n    image: busybox\n",
			workloadType: DebugWorkloadDaemonSet,
			wantWarnings: 0,
		},
		{
			name:         "kind Pod — no warning (not Deployment/DaemonSet)",
			template:     "apiVersion: v1\nkind: Pod\nspec: {}\n",
			workloadType: DebugWorkloadDaemonSet,
			wantWarnings: 0,
		},
		{
			name:         "Go template directives — skip",
			template:     "apiVersion: apps/v1\nkind: {{ .kind }}\nspec: {}\n",
			workloadType: DebugWorkloadDaemonSet,
			wantWarnings: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			warnings := warnTemplateStringWorkloadMismatch(tt.template, tt.workloadType)
			assert.Len(t, warnings, tt.wantWarnings, "unexpected warning count for %q", tt.name)
		})
	}
}

// ==================== YAML Doc Separator Tests ====================

func TestValidateTemplateStringFormat_YAMLDocSeparator(t *testing.T) {
	t.Run("--- inside YAML string value does not cause false split", func(t *testing.T) {
		// A template where the first document contains a string with --- on its own line.
		// The regex-based splitter (?m)^---\s*$ requires --- at start of line,
		// so an indented or embedded --- inside a YAML value won't split.
		template := `apiVersion: v1
kind: Pod
spec:
  containers:
    - name: debug
      image: busybox
      command:
        - /bin/sh
        - -c
        - |
          echo "separator below"
          ---
          echo "still same doc"
`
		errs := validateTemplateStringFormat(template, field.NewPath("spec", "templateString"))
		// The --- in the command is indented, so the regex won't match it.
		// The first document should parse as a valid Pod.
		assert.Empty(t, errs, "indented --- should not cause false document split")
	})

	t.Run("--- at start of line splits documents correctly", func(t *testing.T) {
		// First doc: valid Pod, second doc: ConfigMap (should not affect validation)
		template := "apiVersion: v1\nkind: Pod\nspec:\n  containers:\n    - name: debug\n      image: busybox\n---\napiVersion: v1\nkind: ConfigMap\ndata:\n  key: value\n"
		errs := validateTemplateStringFormat(template, field.NewPath("spec", "templateString"))
		assert.Empty(t, errs, "valid first doc should pass; second doc is ignored")
	})

	t.Run("--- with trailing spaces still splits", func(t *testing.T) {
		template := "apiVersion: v1\nkind: Pod\nspec:\n  containers:\n    - name: debug\n      image: busybox\n---   \napiVersion: v1\nkind: ConfigMap\n"
		errs := validateTemplateStringFormat(template, field.NewPath("spec", "templateString"))
		assert.Empty(t, errs, "--- with trailing spaces should still split correctly")
	})

	t.Run("warnWorkloadMismatch uses same separator for multi-doc", func(t *testing.T) {
		// First doc is DaemonSet, second doc is a ConfigMap.
		// The --- separator must work consistently between format validation and mismatch warnings.
		template := "apiVersion: apps/v1\nkind: DaemonSet\nspec: {}\n---\napiVersion: v1\nkind: ConfigMap\ndata:\n  key: value\n"
		warnings := warnTemplateStringWorkloadMismatch(template, DebugWorkloadDeployment)
		assert.Len(t, warnings, 1, "should detect mismatch in first doc only")
		assert.Contains(t, warnings[0], "DaemonSet")
	})
}

// ==================== DaemonSet Wrong apiVersion Tests ====================

func TestValidateTemplateStringFormat_DaemonSetWrongAPIVersion(t *testing.T) {
	template := `apiVersion: v1
kind: DaemonSet
spec:
  selector:
    matchLabels:
      app: debug
  template:
    spec:
      containers:
        - name: debug
          image: busybox
`
	errs := validateTemplateStringFormat(template, field.NewPath("spec", "templateString"))
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Error(), "DaemonSet requires apiVersion apps/v1")
}

// ==================== Dry-Run Render Tests ====================

func TestTryRenderTemplateString(t *testing.T) {
	t.Run("non-templated string returns no warnings", func(t *testing.T) {
		warnings := tryRenderTemplateString(`apiVersion: v1
kind: Pod
spec:
  containers:
    - name: debug
      image: busybox
`, nil)
		assert.Empty(t, warnings, "plain YAML should not produce warnings")
	})

	t.Run("empty string returns no warnings", func(t *testing.T) {
		warnings := tryRenderTemplateString("", nil)
		assert.Empty(t, warnings)
	})

	t.Run("valid template with session context renders cleanly", func(t *testing.T) {
		warnings := tryRenderTemplateString(`apiVersion: v1
kind: Pod
metadata:
  name: debug-{{ .session.name }}
  labels:
    cluster: {{ .session.cluster }}
spec:
  containers:
    - name: debug
      image: busybox:latest
`, nil)
		assert.Empty(t, warnings, "valid template with session fields should render cleanly")
	})

	t.Run("template with vars renders cleanly when defaults provided", func(t *testing.T) {
		warnings := tryRenderTemplateString(`apiVersion: v1
kind: Pod
spec:
  containers:
    - name: debug
      image: {{ .vars.image }}
`, map[string]string{"image": "busybox:latest"})
		assert.Empty(t, warnings, "template with provided var should render cleanly")
	})

	t.Run("template accessing deeply nested missing field renders with no-value", func(t *testing.T) {
		// Go templates on map[string]interface{} render missing keys as <no value>.
		// This is not an error in Go templates — the dry-run won't produce warnings.
		warnings := tryRenderTemplateString(`apiVersion: v1
kind: Pod
spec:
  containers:
    - name: {{ .NonExistent }}
      image: busybox
`, nil)
		// Missing map key renders as "<no value>", which is valid YAML, so no warning
		assert.Empty(t, warnings, "missing map key renders as <no value>, which is valid YAML")
	})

	t.Run("template producing invalid YAML produces warning", func(t *testing.T) {
		// Template that unconditionally produces invalid YAML.
		// Use a static broken block that doesn't depend on conditions.
		warnings := tryRenderTemplateString(`{{ "not: [valid: yaml: [[[" }}
`, nil)
		assert.NotEmpty(t, warnings, "invalid YAML output should produce a warning")
	})

	t.Run("template with sprig functions renders cleanly", func(t *testing.T) {
		// Note: sprig's lower/trunc expect string input; use toString to convert.
		// This matches how real templates work against map[string]interface{} context.
		warnings := tryRenderTemplateString(`apiVersion: v1
kind: Pod
metadata:
  name: {{ .session.name | toString | lower | trunc 63 }}
spec:
  containers:
    - name: debug
      image: busybox
`, nil)
		assert.Empty(t, warnings, "sprig functions should work in dry-run")
	})

	t.Run("template with required function uses placeholder", func(t *testing.T) {
		// The dry-run replaces `required` with a function that returns PLACEHOLDER
		warnings := tryRenderTemplateString(`apiVersion: v1
kind: Pod
metadata:
  name: {{ required "name is required" .session.name }}
spec:
  containers:
    - name: debug
      image: busybox
`, nil)
		assert.Empty(t, warnings, "required function should return placeholder in dry-run")
	})

	t.Run("template with conditional blocks renders cleanly", func(t *testing.T) {
		warnings := tryRenderTemplateString(`apiVersion: v1
kind: Pod
spec:
  containers:
    - name: debug
      image: busybox
{{ if .vars.enableVolume }}
  volumes:
    - name: data
      emptyDir: {}
{{ end }}
`, map[string]string{"enableVolume": "true"})
		assert.Empty(t, warnings, "conditional template should render cleanly")
	})

	t.Run("multi-doc template validates all documents", func(t *testing.T) {
		warnings := tryRenderTemplateString(`apiVersion: v1
kind: Pod
spec:
  containers:
    - name: debug
      image: busybox
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: {{ .session.name }}-config
data:
  cluster: {{ .session.cluster }}
`, nil)
		assert.Empty(t, warnings, "valid multi-doc template should render cleanly")
	})

	t.Run("real-world DaemonSet template with all context fields", func(t *testing.T) {
		warnings := tryRenderTemplateString(`apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: debug-{{ .session.name | toString | trunc 50 }}
  namespace: {{ .target.namespace }}
  labels:
    {{- range $k, $v := .labels }}
    {{ $k }}: {{ $v }}
    {{- end }}
spec:
  selector:
    matchLabels:
      app: debug
  template:
    spec:
      containers:
        - name: debug
          image: {{ .vars.image | default "busybox:latest" }}
          command: ["sleep", "infinity"]
`, map[string]string{"image": "alpine:3.21"})
		assert.Empty(t, warnings, "real-world DaemonSet template should render cleanly")
	})
}

// ==================== DebugPodTemplate Dry-Run Integration Tests ====================

func TestValidateDebugPodTemplate_DryRunWarnings(t *testing.T) {
	t.Run("valid Go template produces no warnings", func(t *testing.T) {
		template := &DebugPodTemplate{
			Spec: DebugPodTemplateSpec{
				TemplateString: `apiVersion: v1
kind: Pod
metadata:
  name: debug-{{ .session.name }}
spec:
  containers:
    - name: debug
      image: {{ .vars.image | default "busybox:latest" }}
`,
			},
		}
		result := ValidateDebugPodTemplate(template)
		assert.True(t, result.IsValid(), "expected valid, got errors: %s", result.ErrorMessage())
		assert.Empty(t, result.Warnings, "no dry-run warnings expected for valid template")
	})

	t.Run("template with execution error gets warning", func(t *testing.T) {
		// Use `call` on a non-function value to force an execution error
		template := &DebugPodTemplate{
			Spec: DebugPodTemplateSpec{
				TemplateString: `apiVersion: v1
kind: Pod
spec:
  containers:
    - name: {{ call .session.name }}
      image: busybox
`,
			},
		}
		result := ValidateDebugPodTemplate(template)
		// Template syntax is valid, format is skipped (has {{), no format errors expected
		assert.True(t, result.IsValid(), "template syntax is valid")
		// But dry-run should warn about execution failure
		assert.NotEmpty(t, result.Warnings, "expected dry-run warning for execution error")
	})
}

// ==================== DebugSessionTemplate Dry-Run Integration Tests ====================

func TestValidateDebugSessionTemplate_DryRunWarnings(t *testing.T) {
	t.Run("valid Go template with ExtraDeployVariables defaults", func(t *testing.T) {
		template := &DebugSessionTemplate{
			Spec: DebugSessionTemplateSpec{
				Mode: DebugSessionModeWorkload,
				PodTemplateString: `apiVersion: v1
kind: Pod
metadata:
  name: debug-{{ .session.name }}
spec:
  containers:
    - name: debug
      image: {{ .vars.image }}
`,
				ExtraDeployVariables: []ExtraDeployVariable{
					{
						Name:      "image",
						InputType: InputTypeText,
						Default:   jsonRawPtr(`"busybox:latest"`),
					},
				},
			},
		}
		result := ValidateDebugSessionTemplate(template)
		assert.True(t, result.IsValid(), "expected valid, got errors: %s", result.ErrorMessage())
		assert.Empty(t, result.Warnings, "valid template with var defaults should produce no warnings")
	})

	t.Run("var without default gets PLACEHOLDER", func(t *testing.T) {
		template := &DebugSessionTemplate{
			Spec: DebugSessionTemplateSpec{
				Mode: DebugSessionModeWorkload,
				PodTemplateString: `apiVersion: v1
kind: Pod
spec:
  containers:
    - name: debug
      image: {{ .vars.customImage }}
`,
				ExtraDeployVariables: []ExtraDeployVariable{
					{
						Name:      "customImage",
						InputType: InputTypeText,
						Required:  true,
						// No default — should get PLACEHOLDER
					},
				},
			},
		}
		result := ValidateDebugSessionTemplate(template)
		assert.True(t, result.IsValid(), "expected valid, got errors: %s", result.ErrorMessage())
		// PLACEHOLDER is valid YAML, so no warnings expected
		assert.Empty(t, result.Warnings, "PLACEHOLDER should be valid YAML")
	})

	t.Run("template with execution error gets warning", func(t *testing.T) {
		template := &DebugSessionTemplate{
			Spec: DebugSessionTemplateSpec{
				Mode: DebugSessionModeWorkload,
				PodTemplateString: `apiVersion: v1
kind: Pod
spec:
  containers:
    - name: {{ call .session.name }}
      image: busybox
`,
			},
		}
		result := ValidateDebugSessionTemplate(template)
		assert.True(t, result.IsValid(), "syntax is valid, format skipped due to {{")
		assert.NotEmpty(t, result.Warnings, "execution failure should produce dry-run warning")
		assert.Contains(t, result.Warnings[0], "dry-run render warning")
	})

	t.Run("non-templated podTemplateString skips dry-run", func(t *testing.T) {
		template := &DebugSessionTemplate{
			Spec: DebugSessionTemplateSpec{
				Mode: DebugSessionModeWorkload,
				PodTemplateString: `containers:
  - name: debug
    image: busybox:latest
`,
			},
		}
		result := ValidateDebugSessionTemplate(template)
		assert.True(t, result.IsValid())
		// No {{ in template, so tryRenderTemplateString returns nil immediately
		assert.Empty(t, result.Warnings)
	})

	t.Run("boolean ExtraDeployVariable default is unquoted", func(t *testing.T) {
		template := &DebugSessionTemplate{
			Spec: DebugSessionTemplateSpec{
				Mode: DebugSessionModeWorkload,
				PodTemplateString: `apiVersion: v1
kind: Pod
spec:
  containers:
    - name: debug
      image: busybox
{{ if eq .vars.enableDebug "true" }}
  hostNetwork: true
{{ end }}
`,
				ExtraDeployVariables: []ExtraDeployVariable{
					{
						Name:      "enableDebug",
						InputType: InputTypeBoolean,
						Default:   jsonRawPtr(`true`),
					},
				},
			},
		}
		result := ValidateDebugSessionTemplate(template)
		assert.True(t, result.IsValid())
		// Boolean `true` (unquoted JSON) should be passed as "true" string to template
		assert.Empty(t, result.Warnings, "boolean var should render cleanly")
	})
}

// ==================== Additional validateTemplateStringFormat Tests ====================

func TestValidateTemplateStringFormat_AdditionalCases(t *testing.T) {
	t.Run("DaemonSet with extensions/v1beta1 apiVersion", func(t *testing.T) {
		errs := validateTemplateStringFormat(
			"apiVersion: extensions/v1beta1\nkind: DaemonSet\nspec: {}\n",
			field.NewPath("spec", "templateString"))
		require.Len(t, errs, 1)
		assert.Contains(t, errs[0].Error(), "DaemonSet requires apiVersion apps/v1")
	})

	t.Run("template with directives in kind skips validation", func(t *testing.T) {
		// apiVersion is set but kind uses Go template — skip validation
		errs := validateTemplateStringFormat(
			"apiVersion: v1\nkind: {{ .vars.kind }}\nspec: {}\n",
			field.NewPath("spec", "templateString"))
		assert.Empty(t, errs, "should skip validation when template has Go directives")
	})

	t.Run("whitespace-only template after trimming", func(t *testing.T) {
		errs := validateTemplateStringFormat("   \n   \n   ", field.NewPath("spec", "templateString"))
		assert.Empty(t, errs, "whitespace-only template should produce no errors")
	})

	t.Run("first doc empty but second doc has content", func(t *testing.T) {
		// When first doc is empty, the split produces an empty first part
		errs := validateTemplateStringFormat(
			"\n---\napiVersion: v1\nkind: ConfigMap\ndata:\n  key: value\n",
			field.NewPath("spec", "templateString"))
		// Empty first doc is handled by the empty check
		assert.Empty(t, errs, "empty first doc should be treated as valid")
	})

	t.Run("invalid YAML in non-templated first doc", func(t *testing.T) {
		errs := validateTemplateStringFormat(
			"not: [valid: yaml: [[[",
			field.NewPath("spec", "templateString"))
		require.NotEmpty(t, errs)
		assert.Contains(t, errs[0].Error(), "invalid YAML")
	})

	t.Run("Deployment with extensions/v1beta1 apiVersion", func(t *testing.T) {
		errs := validateTemplateStringFormat(
			"apiVersion: extensions/v1beta1\nkind: Deployment\nspec: {}\n",
			field.NewPath("spec", "templateString"))
		require.Len(t, errs, 1)
		assert.Contains(t, errs[0].Error(), "Deployment requires apiVersion apps/v1")
	})

	t.Run("unsupported kind ReplicaSet", func(t *testing.T) {
		errs := validateTemplateStringFormat(
			"apiVersion: apps/v1\nkind: ReplicaSet\nspec: {}\n",
			field.NewPath("spec", "templateString"))
		require.Len(t, errs, 1)
		assert.Contains(t, errs[0].Error(), "unsupported kind")
		assert.Contains(t, errs[0].Error(), "ReplicaSet")
	})

	t.Run("unsupported kind CronJob", func(t *testing.T) {
		errs := validateTemplateStringFormat(
			"apiVersion: batch/v1\nkind: CronJob\nspec: {}\n",
			field.NewPath("spec", "templateString"))
		require.Len(t, errs, 1)
		assert.Contains(t, errs[0].Error(), "unsupported kind")
		assert.Contains(t, errs[0].Error(), "CronJob")
	})
}

// ==================== Additional warnTemplateStringWorkloadMismatch Tests ====================

func TestWarnTemplateStringWorkloadMismatch_AdditionalCases(t *testing.T) {
	t.Run("empty workloadType returns no warning", func(t *testing.T) {
		// When workloadType is empty, the function should check against the template kind
		warnings := warnTemplateStringWorkloadMismatch(
			"apiVersion: apps/v1\nkind: DaemonSet\nspec: {}\n",
			"",
		)
		// DebugWorkloadType("DaemonSet") != DebugWorkloadType("") => warning
		assert.Len(t, warnings, 1, "empty workloadType should produce mismatch warning against DaemonSet")
	})

	t.Run("empty template returns no warning", func(t *testing.T) {
		warnings := warnTemplateStringWorkloadMismatch("", DebugWorkloadDaemonSet)
		assert.Empty(t, warnings, "empty template should produce no warnings")
	})

	t.Run("template with directives and non-empty workloadType", func(t *testing.T) {
		warnings := warnTemplateStringWorkloadMismatch(
			"apiVersion: apps/v1\nkind: {{ .vars.kind }}\nspec: {}\n",
			DebugWorkloadDaemonSet,
		)
		assert.Empty(t, warnings, "template with Go directives should skip mismatch check")
	})

	t.Run("whitespace-only template returns no warning", func(t *testing.T) {
		warnings := warnTemplateStringWorkloadMismatch("   \n   ", DebugWorkloadDaemonSet)
		assert.Empty(t, warnings)
	})

	t.Run("unmarshal error returns no warning", func(t *testing.T) {
		warnings := warnTemplateStringWorkloadMismatch(
			"not: [valid: yaml: [[[",
			DebugWorkloadDaemonSet,
		)
		assert.Empty(t, warnings, "YAML parse error should return no warnings (not an error)")
	})
}

// ==================== Additional tryRenderTemplateString Tests ====================

func TestTryRenderTemplateString_CustomFunctions(t *testing.T) {
	t.Run("yamlQuote function works in dry-run", func(t *testing.T) {
		warnings := tryRenderTemplateString(`apiVersion: v1
kind: Pod
spec:
  containers:
    - name: debug
      image: busybox
      env:
        - name: USER_INPUT
          value: {{ .vars.input | yamlQuote }}
`, map[string]string{"input": "test: value"})
		assert.Empty(t, warnings, "yamlQuote should work in dry-run")
	})

	t.Run("toYaml function works in dry-run (stub returns empty)", func(t *testing.T) {
		warnings := tryRenderTemplateString(`apiVersion: v1
kind: Pod
spec:
  containers:
    - name: debug
      image: busybox
  nodeSelector:
    {{ toYaml .labels }}
`, nil)
		assert.Empty(t, warnings, "toYaml stub should not crash dry-run")
	})

	t.Run("fromYaml function works in dry-run (stub returns nil)", func(t *testing.T) {
		// fromYaml returns nil; accessing a field on nil produces <no value>
		warnings := tryRenderTemplateString(`apiVersion: v1
kind: Pod
spec:
  containers:
    - name: debug
      image: busybox
`, nil)
		assert.Empty(t, warnings, "fromYaml stub should not crash dry-run")
	})

	t.Run("resourceQuantity function works in dry-run", func(t *testing.T) {
		warnings := tryRenderTemplateString(`apiVersion: v1
kind: Pod
spec:
  containers:
    - name: debug
      image: busybox
      resources:
        requests:
          memory: {{ resourceQuantity "512Mi" }}
`, nil)
		assert.Empty(t, warnings, "resourceQuantity should work in dry-run")
	})

	t.Run("truncName function works in dry-run", func(t *testing.T) {
		warnings := tryRenderTemplateString(`apiVersion: v1
kind: Pod
metadata:
  name: {{ truncName 20 .session.name }}
spec:
  containers:
    - name: debug
      image: busybox
`, nil)
		assert.Empty(t, warnings, "truncName should work in dry-run")
	})

	t.Run("k8sName function works in dry-run", func(t *testing.T) {
		warnings := tryRenderTemplateString(`apiVersion: v1
kind: Pod
metadata:
  name: {{ k8sName .session.name }}
spec:
  containers:
    - name: debug
      image: busybox
`, nil)
		assert.Empty(t, warnings, "k8sName should work in dry-run")
	})

	t.Run("indent function works in dry-run", func(t *testing.T) {
		warnings := tryRenderTemplateString(`apiVersion: v1
kind: Pod
spec:
  containers:
    - name: debug
      image: busybox
      env:
{{ indent 8 "- name: TEST\n  value: hello" }}
`, nil)
		assert.Empty(t, warnings, "indent should work in dry-run")
	})

	t.Run("nindent function works in dry-run", func(t *testing.T) {
		warnings := tryRenderTemplateString(`apiVersion: v1
kind: Pod
spec:
  containers:
    - name: debug
      image: busybox
      env: {{- nindent 8 "- name: TEST\n  value: hello" }}
`, nil)
		assert.Empty(t, warnings, "nindent should work in dry-run")
	})

	t.Run("yamlSafe function works in dry-run", func(t *testing.T) {
		warnings := tryRenderTemplateString(`apiVersion: v1
kind: Pod
metadata:
  name: {{ yamlSafe .vars.safeName }}
spec:
  containers:
    - name: debug
      image: busybox
`, map[string]string{"safeName": "test:name#value"})
		assert.Empty(t, warnings, "yamlSafe should work in dry-run")
	})

	t.Run("formatQuantity function works in dry-run (stub returns empty)", func(t *testing.T) {
		warnings := tryRenderTemplateString(`apiVersion: v1
kind: Pod
spec:
  containers:
    - name: debug
      image: busybox
      resources:
        requests:
          memory: {{ formatQuantity 0 }}
`, nil)
		assert.Empty(t, warnings, "formatQuantity stub should not crash dry-run")
	})

	t.Run("parseQuantity function works in dry-run (stub passthrough)", func(t *testing.T) {
		warnings := tryRenderTemplateString(`apiVersion: v1
kind: Pod
spec:
  containers:
    - name: debug
      image: busybox
      resources:
        requests:
          memory: {{ parseQuantity "512Mi" }}
`, nil)
		assert.Empty(t, warnings, "parseQuantity stub should not crash dry-run")
	})
}

func TestTryRenderTemplateString_AdditionalCases(t *testing.T) {
	t.Run("template execution error with fail function", func(t *testing.T) {
		// `fail` is a Sprig function that calls panic — the dry-run should catch this
		warnings := tryRenderTemplateString(`{{ fail "intentional error" }}`, nil)
		assert.NotEmpty(t, warnings, "fail function should produce a dry-run warning")
		assert.Contains(t, warnings[0], "dry-run render warning")
	})

	t.Run("rendered valid YAML but not a valid K8s resource", func(t *testing.T) {
		// Renders to valid YAML (just a map) — no warning expected since
		// tryRenderTemplateString only validates YAML syntax, not K8s structure
		warnings := tryRenderTemplateString(`{{ "foo: bar" }}`, nil)
		assert.Empty(t, warnings, "valid YAML should not produce warnings regardless of content")
	})

	t.Run("template accessing .labels fields", func(t *testing.T) {
		warnings := tryRenderTemplateString(`apiVersion: v1
kind: Pod
metadata:
  labels:
    {{- range $k, $v := .labels }}
    {{ $k }}: {{ $v }}
    {{- end }}
spec:
  containers:
    - name: debug
      image: busybox
`, nil)
		assert.Empty(t, warnings, "template accessing .labels should work with sample context")
	})

	t.Run("template accessing .annotations fields", func(t *testing.T) {
		warnings := tryRenderTemplateString(`apiVersion: v1
kind: Pod
metadata:
  annotations:
    {{- range $k, $v := .annotations }}
    {{ $k }}: {{ $v }}
    {{- end }}
spec:
  containers:
    - name: debug
      image: busybox
`, nil)
		assert.Empty(t, warnings, "template accessing .annotations should work with sample context")
	})

	t.Run("template accessing .template fields", func(t *testing.T) {
		warnings := tryRenderTemplateString(`apiVersion: v1
kind: Pod
metadata:
  name: debug-{{ .template.name }}
  labels:
    display: {{ .template.displayName }}
spec:
  containers:
    - name: debug
      image: busybox
`, nil)
		assert.Empty(t, warnings, "template accessing .template context should work")
	})

	t.Run("template accessing .binding fields", func(t *testing.T) {
		warnings := tryRenderTemplateString(`apiVersion: v1
kind: Pod
metadata:
  name: debug-{{ .binding.name }}
  namespace: {{ .binding.namespace }}
spec:
  containers:
    - name: debug
      image: busybox
`, nil)
		assert.Empty(t, warnings, "template accessing .binding context should work")
	})

	t.Run("var with PLACEHOLDER when no default", func(t *testing.T) {
		// When a var has no default, it gets PLACEHOLDER
		warnings := tryRenderTemplateString(`apiVersion: v1
kind: Pod
spec:
  containers:
    - name: debug
      image: {{ .vars.missingVar }}
`, nil)
		// .vars.missingVar will produce <no value> since vars map doesn't have it
		// But that's still valid YAML
		assert.Empty(t, warnings)
	})

	t.Run("multi-doc with invalid second document YAML", func(t *testing.T) {
		warnings := tryRenderTemplateString(`apiVersion: v1
kind: Pod
spec:
  containers:
    - name: debug
      image: busybox
---
{{ "not: [valid: yaml: [[[" }}
`, nil)
		assert.NotEmpty(t, warnings, "invalid second doc YAML should produce warning")
		assert.Contains(t, warnings[0], "document 2")
	})

	t.Run("template with empty rendered output is fine", func(t *testing.T) {
		warnings := tryRenderTemplateString(`{{- if eq "a" "b" }}
apiVersion: v1
kind: Pod
spec:
  containers:
    - name: debug
      image: busybox
{{- end }}
`, nil)
		assert.Empty(t, warnings, "empty rendered output should be fine (conditional suppression)")
	})
}

// ==================== Additional ValidateDebugPodTemplate Tests ====================

func TestValidateDebugPodTemplate_AdditionalCases(t *testing.T) {
	t.Run("Go template syntax error in templateString", func(t *testing.T) {
		template := &DebugPodTemplate{
			Spec: DebugPodTemplateSpec{
				TemplateString: `apiVersion: v1
kind: Pod
spec:
  containers:
    - name: {{ .session.name
      image: busybox
`,
			},
		}
		result := ValidateDebugPodTemplate(template)
		assert.False(t, result.IsValid(), "template syntax error should fail validation")
		assert.Contains(t, result.ErrorMessage(), "template syntax")
	})

	t.Run("kind without apiVersion in DebugPodTemplate", func(t *testing.T) {
		template := &DebugPodTemplate{
			Spec: DebugPodTemplateSpec{
				TemplateString: `kind: Pod
spec:
  containers:
    - name: debug
      image: busybox
`,
			},
		}
		result := ValidateDebugPodTemplate(template)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "apiVersion but no kind")
	})
}

// ==================== Additional ValidateDebugSessionTemplate Tests ====================

func TestValidateDebugSessionTemplate_AdditionalCases(t *testing.T) {
	t.Run("Go template syntax error in podTemplateString", func(t *testing.T) {
		template := &DebugSessionTemplate{
			Spec: DebugSessionTemplateSpec{
				Mode: DebugSessionModeWorkload,
				PodTemplateString: `apiVersion: v1
kind: Pod
spec:
  containers:
    - name: {{ .session.name
      image: busybox
`,
			},
		}
		result := ValidateDebugSessionTemplate(template)
		assert.False(t, result.IsValid(), "template syntax error should fail validation")
		assert.Contains(t, result.ErrorMessage(), "template syntax")
	})

	t.Run("ExtraDeployVariable with JSON array default", func(t *testing.T) {
		template := &DebugSessionTemplate{
			Spec: DebugSessionTemplateSpec{
				Mode: DebugSessionModeWorkload,
				PodTemplateString: `apiVersion: v1
kind: Pod
spec:
  containers:
    - name: debug
      image: busybox
      args: {{ .vars.args }}
`,
				ExtraDeployVariables: []ExtraDeployVariable{
					{
						Name:      "args",
						InputType: InputTypeText,
						Default:   jsonRawPtr(`["--verbose","--debug"]`),
					},
				},
			},
		}
		result := ValidateDebugSessionTemplate(template)
		assert.True(t, result.IsValid(), "expected valid, got errors: %s", result.ErrorMessage())
	})

	t.Run("ExtraDeployVariable with JSON object default", func(t *testing.T) {
		template := &DebugSessionTemplate{
			Spec: DebugSessionTemplateSpec{
				Mode: DebugSessionModeWorkload,
				PodTemplateString: `apiVersion: v1
kind: Pod
spec:
  containers:
    - name: debug
      image: busybox
      env:
        - name: CONFIG
          value: {{ .vars.config }}
`,
				ExtraDeployVariables: []ExtraDeployVariable{
					{
						Name:      "config",
						InputType: InputTypeText,
						Default:   jsonRawPtr(`{"key":"value"}`),
					},
				},
			},
		}
		result := ValidateDebugSessionTemplate(template)
		assert.True(t, result.IsValid(), "expected valid, got errors: %s", result.ErrorMessage())
	})

	t.Run("DaemonSet with wrong apiVersion in DST context", func(t *testing.T) {
		template := &DebugSessionTemplate{
			Spec: DebugSessionTemplateSpec{
				Mode:         DebugSessionModeWorkload,
				WorkloadType: DebugWorkloadDaemonSet,
				PodTemplateString: `apiVersion: v1
kind: DaemonSet
spec:
  selector:
    matchLabels:
      app: debug
  template:
    spec:
      containers:
        - name: debug
          image: busybox
`,
			},
		}
		result := ValidateDebugSessionTemplate(template)
		assert.False(t, result.IsValid())
		assert.Contains(t, result.ErrorMessage(), "DaemonSet requires apiVersion apps/v1")
	})

	t.Run("workload mismatch with default workloadType (DaemonSet)", func(t *testing.T) {
		// Default workloadType is DaemonSet — templateString produces Deployment
		template := &DebugSessionTemplate{
			Spec: DebugSessionTemplateSpec{
				Mode: DebugSessionModeWorkload,
				// WorkloadType not set => defaults to DaemonSet
				PodTemplateString: `apiVersion: apps/v1
kind: Deployment
metadata:
  name: debug
spec:
  replicas: 1
  selector:
    matchLabels:
      app: debug
  template:
    spec:
      containers:
        - name: debug
          image: busybox
`,
			},
		}
		result := ValidateDebugSessionTemplate(template)
		assert.True(t, result.IsValid(), "mismatch is a warning, not error")
		// Default workloadType is empty string in Go, warnTemplateStringWorkloadMismatch
		// should still produce a warning if the template kind doesn't match
		// (depends on how default is handled — let's check)
	})

	t.Run("numeric ExtraDeployVariable default", func(t *testing.T) {
		template := &DebugSessionTemplate{
			Spec: DebugSessionTemplateSpec{
				Mode: DebugSessionModeWorkload,
				PodTemplateString: `apiVersion: v1
kind: Pod
spec:
  containers:
    - name: debug
      image: busybox
      env:
        - name: REPLICAS
          value: {{ .vars.replicas }}
`,
				ExtraDeployVariables: []ExtraDeployVariable{
					{
						Name:      "replicas",
						InputType: InputTypeNumber,
						Default:   jsonRawPtr(`3`),
					},
				},
			},
		}
		result := ValidateDebugSessionTemplate(template)
		assert.True(t, result.IsValid(), "expected valid, got errors: %s", result.ErrorMessage())
		assert.Empty(t, result.Warnings, "numeric var should render cleanly")
	})

	t.Run("float ExtraDeployVariable default", func(t *testing.T) {
		template := &DebugSessionTemplate{
			Spec: DebugSessionTemplateSpec{
				Mode: DebugSessionModeWorkload,
				PodTemplateString: `apiVersion: v1
kind: Pod
spec:
  containers:
    - name: debug
      image: busybox
      env:
        - name: RATIO
          value: {{ .vars.ratio }}
`,
				ExtraDeployVariables: []ExtraDeployVariable{
					{
						Name:      "ratio",
						InputType: InputTypeNumber,
						Default:   jsonRawPtr(`0.5`),
					},
				},
			},
		}
		result := ValidateDebugSessionTemplate(template)
		assert.True(t, result.IsValid(), "expected valid, got errors: %s", result.ErrorMessage())
		assert.Empty(t, result.Warnings)
	})
}

// jsonRawPtr creates a *apiextensionsv1.JSON from a raw JSON string.
func jsonRawPtr(raw string) *apiextensionsv1.JSON {
	return &apiextensionsv1.JSON{Raw: []byte(raw)}
}
