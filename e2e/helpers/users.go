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

package helpers

// TestUser represents a test user configured in Keycloak
// These users are defined in config/dev/resources/breakglass-e2e-realm.json
type TestUser struct {
	Username string
	Password string
	Email    string
	Groups   []string
}

// TestUsers provides access to pre-configured test users in Keycloak.
// These users are seeded via the breakglass-e2e-realm.json configuration.
var TestUsers = struct {
	// Requester is a user that can request breakglass sessions
	// Groups: dev, ops, requester
	Requester TestUser

	// Approver is a user that can approve/reject breakglass sessions
	// Groups: approver, senior-ops, approval-notes
	Approver TestUser

	// ApproverInternal is another approver for internal escalations
	// Groups: approver, senior-ops, breakglass
	ApproverInternal TestUser

	// SeniorApprover is a senior approver for high-risk escalations
	// Groups: approver, senior-ops, emergency-response
	SeniorApprover TestUser

	// DevAlpha is a developer in the frontend team
	// Groups: dev, frontend-team, devs-a
	DevAlpha TestUser

	// DevBeta is a developer in the backend/database team
	// Groups: dev, backend-team, database-team, devs-b
	DevBeta TestUser

	// OpsGamma is an ops user in the monitoring team
	// Groups: ops, monitoring-team, ops-a
	OpsGamma TestUser

	// TenantB is a user in the tenant-b team
	// Groups: dev, tenant-b-team, devs-b
	TenantB TestUser

	// Limited is a read-only user with restricted access
	// Groups: read-only
	Limited TestUser

	// LeadDev is a lead developer
	// Groups: dev, tenant-b-team
	LeadDev TestUser

	// InfraLead is an infrastructure lead with senior ops access
	// Groups: ops, senior-ops, ops-b
	InfraLead TestUser

	// RequesterPodAdmin is a requester with pod admin privileges
	// Groups: dev, breakglass-pods-admin, state-transition-admins
	RequesterPodAdmin TestUser

	// RequesterEmergency is a requester with emergency admin access
	// Groups: ops, breakglass-emergency-admin, concurrent-admins
	RequesterEmergency TestUser

	// RequesterReadOnly is a requester with read-only access
	// Groups: dev, breakglass-read-only, ghost-cluster-admins
	RequesterReadOnly TestUser

	// ApproverOps is an approver from the ops team
	// Groups: approver, ops, monitoring-team
	ApproverOps TestUser

	// ApproverSecurity is an approver from the security team
	// Groups: approver, emergency-response, senior-ops
	ApproverSecurity TestUser

	// SecurityRequester is a user specifically for security tests with minimal permissions
	// Groups: security-test-requester
	SecurityRequester TestUser

	// SecurityApprover is an approver specifically for security tests
	// Groups: approver, security-test-approver
	SecurityApprover TestUser

	// UnauthorizedUser is a user with no special permissions for testing denial scenarios
	// Groups: (none - just read-only)
	UnauthorizedUser TestUser

	// =============================================================================
	// TEST CATEGORY PERSONAS
	// These personas are designed for specific test categories to ensure isolation
	// =============================================================================

	// AuditTestRequester is for audit/compliance testing with isolated audit events
	// Groups: audit-functional-test-group, dev
	AuditTestRequester TestUser

	// AuditTestApprover is an approver for audit tests
	// Groups: approver, audit-test-approver
	AuditTestApprover TestUser

	// NotificationTestRequester is for notification tests with predictable email routing
	// Groups: notification-test-group, notification-group-test, dev
	NotificationTestRequester TestUser

	// NotificationTestApprover is an approver for notification tests
	// Groups: approver, notification-test-approver
	NotificationTestApprover TestUser

	// PolicyTestRequester is for deny policy tests with minimal permissions
	// Groups: policy-test-group (minimal to properly test denials)
	PolicyTestRequester TestUser

	// PolicyTestApprover is an approver for policy tests
	// Groups: approver, policy-test-approver
	PolicyTestApprover TestUser

	// DebugSessionRequester is for debug session feature testing
	// Groups: debug-session-test-group, dev
	DebugSessionRequester TestUser

	// DebugSessionApprover is an approver for debug session tests
	// Groups: approver, debug-session-approver
	DebugSessionApprover TestUser

	// SchedulingTestRequester is for scheduled session and cleanup tests
	// Groups: scheduled-admins, dev
	SchedulingTestRequester TestUser

	// SchedulingTestApprover is an approver for scheduling tests
	// Groups: approver, scheduling-test-approver
	SchedulingTestApprover TestUser

	// WebhookTestRequester is for SAR webhook authorization boundary testing
	// Groups: webhook-test-group, dev
	WebhookTestRequester TestUser

	// WebhookTestApprover is an approver for webhook tests
	// Groups: approver, webhook-test-approver
	WebhookTestApprover TestUser

	// MultiClusterRequester is for multi-cluster operations testing
	// Groups: breakglass-multi-cluster-ops, ops
	MultiClusterRequester TestUser

	// MultiClusterApprover is an approver for multi-cluster tests
	// Groups: approver, multi-cluster-approver
	MultiClusterApprover TestUser

	// CompleteFlowRequester is specifically for TestCompleteBreakglassFlow
	// This user does NOT have complete-flow-test-admins group by default - they get it via session
	// Groups: complete-flow-requester-base (minimal group with no special permissions)
	CompleteFlowRequester TestUser

	// CompleteFlowApprover is an approver for complete flow tests
	// Groups: approver, complete-flow-approver
	CompleteFlowApprover TestUser
}{
	Requester: TestUser{
		Username: "test-user",
		Password: "test-password",
		Email:    "test-user@example.com",
		Groups: []string{
			"dev", "ops", "requester",
			// Multi-cluster E2E required group - escalations use this
			"breakglass-users",
			// E2E test groups with RBAC bindings
			"complete-flow-test-admins",
			"e2e-test-group",
			"test-group",
			"valid-group",
			"notification-test-group",
			"notification-group-test",
			"hidden-approvers-group",
			"approver-groups-test",
			"mandatory-reason-group",
			"cross-cluster-group",
			"clusterconfig-ref-group",
			"target-cluster-group",
			"audit-functional-test-group",
			"ghost-cluster-admins",
			"concurrent-admins",
			"state-transition-admins",
			"recreate-admins",
			"recreate-admins-v2",
			"update-test-admins",
			"breakglass-pods-admin",
			"breakglass-read-only",
			"breakglass-emergency-admin",
			"breakglass-create-all",
			"breakglass-multi-cluster-ops",
			"webhook-test-group",
			"domain-restricted-access",
			"validation-admins",
			// Additional groups for session state tests
			"transition-test-group",
			"auth-test-group",
			"expired-auth-test-group",
			"withdrawn-auth-test-group",
			"cleanup-test-admins",
			"state-test-admins",
			"scheduled-admins",
		},
	},
	Approver: TestUser{
		Username: "approver-user",
		Password: "approver-password",
		Email:    "approver@example.org", // Must match Keycloak realm config
		Groups:   []string{"approver", "senior-ops", "approval-notes", "breakglass-approvers"},
	},
	ApproverInternal: TestUser{
		Username: "approver-internal",
		Password: "approver-internal-password",
		Email:    "approver-internal@example.com", // Must match Keycloak realm config
		Groups:   []string{"approver", "senior-ops", "breakglass", "breakglass-approvers"},
	},
	SeniorApprover: TestUser{
		Username: "senior-approver",
		Password: "senior-approver-password",
		Email:    "senior-approver@example.com",
		Groups:   []string{"approver", "senior-ops", "emergency-response", "breakglass-approvers"},
	},
	DevAlpha: TestUser{
		Username: "dev-user-alpha",
		Password: "dev-alpha-password",
		Email:    "dev-alpha@example.com",
		Groups:   []string{"dev", "frontend-team", "devs-a", "breakglass-users"},
	},
	DevBeta: TestUser{
		Username: "dev-user-beta",
		Password: "dev-beta-password",
		Email:    "dev-beta@example.com",
		Groups:   []string{"dev", "backend-team", "database-team", "devs-b"},
	},
	OpsGamma: TestUser{
		Username: "ops-user-gamma",
		Password: "ops-gamma-password",
		Email:    "ops-gamma@example.com",
		Groups:   []string{"ops", "monitoring-team", "ops-a"},
	},
	TenantB: TestUser{
		Username: "tenant-b-user",
		Password: "tenant-b-password",
		Email:    "tenant-b-user@example.com", // Must match Keycloak realm config
		Groups:   []string{"dev", "tenant-b-team", "devs-b"},
	},
	Limited: TestUser{
		Username: "limited-user",
		Password: "limited-password",
		Email:    "limited-user@example.com", // Must match Keycloak realm config
		Groups:   []string{"read-only"},
	},
	LeadDev: TestUser{
		Username: "lead-dev",
		Password: "lead-dev-password",
		Email:    "lead-dev@example.com",
		Groups:   []string{"dev", "tenant-b-team"},
	},
	InfraLead: TestUser{
		Username: "infra-lead",
		Password: "infra-lead-password",
		Email:    "infra-lead@example.com",
		Groups:   []string{"ops", "senior-ops", "ops-b"},
	},
	RequesterPodAdmin: TestUser{
		Username: "requester-pod-admin",
		Password: "requester-pod-admin-password",
		Email:    "requester-pod-admin@example.com",
		Groups: []string{
			"dev",
			"breakglass-pods-admin",
			"state-transition-admins",
			"update-test-admins",
			"concurrent-admins",
		},
	},
	RequesterEmergency: TestUser{
		Username: "requester-emergency",
		Password: "requester-emergency-password",
		Email:    "requester-emergency@example.com",
		Groups: []string{
			"ops",
			"breakglass-emergency-admin",
			"concurrent-admins",
			"recreate-admins",
			"recreate-admins-v2",
		},
	},
	RequesterReadOnly: TestUser{
		Username: "requester-readonly",
		Password: "requester-readonly-password",
		Email:    "requester-readonly@example.com",
		Groups: []string{
			"dev",
			"breakglass-read-only",
			"ghost-cluster-admins",
			"validation-admins",
		},
	},
	ApproverOps: TestUser{
		Username: "approver-ops",
		Password: "approver-ops-password",
		Email:    "approver-ops@example.com",
		Groups:   []string{"approver", "ops", "monitoring-team"},
	},
	ApproverSecurity: TestUser{
		Username: "approver-security",
		Password: "approver-security-password",
		Email:    "approver-security@example.com",
		Groups:   []string{"approver", "emergency-response", "senior-ops"},
	},
	SecurityRequester: TestUser{
		Username: "security-requester",
		Password: "security-requester-password",
		Email:    "security-requester@example.com",
		Groups: []string{
			"security-test-requester",
			"pending-auth-test-group",
			"self-approve-test-group",
			"unreachable-test-group",
		},
	},
	SecurityApprover: TestUser{
		Username: "security-approver",
		Password: "security-approver-password",
		Email:    "security-approver@example.com",
		Groups:   []string{"approver", "security-test-approver"},
	},
	UnauthorizedUser: TestUser{
		Username: "unauthorized-user",
		Password: "unauthorized-password",
		Email:    "unauthorized@example.com",
		Groups:   []string{"read-only"}, // Minimal permissions
	},

	// =============================================================================
	// TEST CATEGORY PERSONAS - VALUES
	// =============================================================================

	AuditTestRequester: TestUser{
		Username: "audit-requester",
		Password: "audit-requester-password",
		Email:    "audit-requester@example.com",
		Groups:   []string{"audit-functional-test-group", "dev"},
	},
	AuditTestApprover: TestUser{
		Username: "audit-approver",
		Password: "audit-approver-password",
		Email:    "audit-approver@example.com",
		Groups:   []string{"approver", "audit-test-approver"},
	},
	NotificationTestRequester: TestUser{
		Username: "notification-requester",
		Password: "notification-requester-password",
		Email:    "notification-requester@example.com",
		Groups:   []string{"notification-test-group", "notification-group-test", "dev"},
	},
	NotificationTestApprover: TestUser{
		Username: "notification-approver",
		Password: "notification-approver-password",
		Email:    "notification-approver@example.com",
		Groups:   []string{"approver", "notification-test-approver"},
	},
	PolicyTestRequester: TestUser{
		Username: "policy-requester",
		Password: "policy-requester-password",
		Email:    "policy-requester@example.com",
		Groups:   []string{"policy-test-group", "breakglass-users"}, // Minimal for deny policy testing + multi-cluster access
	},
	PolicyTestApprover: TestUser{
		Username: "policy-approver",
		Password: "policy-approver-password",
		Email:    "policy-approver@example.com",
		Groups:   []string{"approver", "policy-test-approver"},
	},
	DebugSessionRequester: TestUser{
		Username: "debug-session-requester",
		Password: "debug-session-requester-password",
		Email:    "debug-session-requester@example.com",
		Groups:   []string{"debug-session-test-group", "dev"},
	},
	DebugSessionApprover: TestUser{
		Username: "debug-session-approver",
		Password: "debug-session-approver-password",
		Email:    "debug-session-approver@example.com",
		Groups:   []string{"approver", "debug-session-approver"},
	},
	SchedulingTestRequester: TestUser{
		Username: "scheduling-requester",
		Password: "scheduling-requester-password",
		Email:    "scheduling-requester@example.com",
		Groups:   []string{"scheduled-admins", "dev", "breakglass-users"},
	},
	SchedulingTestApprover: TestUser{
		Username: "scheduling-approver",
		Password: "scheduling-approver-password",
		Email:    "scheduling-approver@example.com",
		Groups:   []string{"approver", "scheduling-test-approver"},
	},
	WebhookTestRequester: TestUser{
		Username: "webhook-requester",
		Password: "webhook-requester-password",
		Email:    "webhook-requester@example.com",
		Groups:   []string{"webhook-test-group", "dev", "breakglass-users"},
	},
	WebhookTestApprover: TestUser{
		Username: "webhook-approver",
		Password: "webhook-approver-password",
		Email:    "webhook-approver@example.com",
		Groups:   []string{"approver", "webhook-test-approver"},
	},
	MultiClusterRequester: TestUser{
		Username: "multi-cluster-requester",
		Password: "multi-cluster-requester-password",
		Email:    "multi-cluster-requester@example.com",
		Groups:   []string{"breakglass-multi-cluster-ops", "ops"},
	},
	MultiClusterApprover: TestUser{
		Username: "multi-cluster-approver",
		Password: "multi-cluster-approver-password",
		Email:    "multi-cluster-approver@example.com",
		Groups:   []string{"approver", "multi-cluster-approver"},
	},
	CompleteFlowRequester: TestUser{
		Username: "complete-flow-requester",
		Password: "complete-flow-requester-password",
		Email:    "complete-flow-requester@example.com",
		Groups:   []string{"complete-flow-requester-base"}, // Minimal - NO complete-flow-test-admins!
	},
	CompleteFlowApprover: TestUser{
		Username: "complete-flow-approver",
		Password: "complete-flow-approver-password",
		Email:    "complete-flow-approver@example.com",
		Groups:   []string{"approver", "complete-flow-approver"},
	},
}

// GetApproverUsers returns all users with approver capabilities
func GetApproverUsers() []TestUser {
	return []TestUser{
		TestUsers.Approver,
		TestUsers.ApproverInternal,
		TestUsers.SeniorApprover,
		TestUsers.ApproverOps,
		TestUsers.ApproverSecurity,
	}
}

// GetRequesterUsers returns all users with requester capabilities
func GetRequesterUsers() []TestUser {
	return []TestUser{
		TestUsers.Requester,
		TestUsers.DevAlpha,
		TestUsers.DevBeta,
		TestUsers.OpsGamma,
		TestUsers.TenantB,
		TestUsers.LeadDev,
		TestUsers.InfraLead,
		TestUsers.RequesterPodAdmin,
		TestUsers.RequesterEmergency,
		TestUsers.RequesterReadOnly,
	}
}

// GetRequesterWithGroup returns the first requester user that has the specified group
func GetRequesterWithGroup(group string) *TestUser {
	for _, user := range GetRequesterUsers() {
		for _, g := range user.Groups {
			if g == group {
				return &user
			}
		}
	}
	return nil
}
