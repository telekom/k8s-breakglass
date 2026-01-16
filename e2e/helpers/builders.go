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

import (
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	telekomv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
)

// EscalationBuilder provides a fluent API for building BreakglassEscalation resources.
// Use this instead of manually constructing escalations to reduce boilerplate.
//
// Example:
//
//	escalation := helpers.NewEscalationBuilder("my-test", namespace).
//	    WithEscalatedGroup("pod-admin").
//	    WithAllowedClusters(clusterName).
//	    WithApproverUsers(helpers.TestUsers.Approver.Email).
//	    Build()
type EscalationBuilder struct {
	name                        string
	namespace                   string
	escalatedGroup              string
	maxValidFor                 string
	approvalTimeout             string
	allowedClusters             []string
	allowedGroups               []string
	approverUsers               []string
	approverGroups              []string
	approverDomains             []string
	hiddenApproverUsers         []string
	hiddenApproverGroups        []string
	labels                      map[string]string
	denyPolicyRefs              []string
	mailProvider                string
	blockSelfApproval           *bool
	retainFor                   string
	clusterConfigRefs           []string
	requestReason               *telekomv1alpha1.ReasonConfig
	approvalReason              *telekomv1alpha1.ReasonConfig
	disableNotifications        *bool
	podSecurityOverrides        *telekomv1alpha1.PodSecurityOverrides
	allowedIDPsForRequests      []string
	allowedIDPsForApprovers     []string
	notificationExclusionUsers  []string
	notificationExclusionGroups []string
}

// NewEscalationBuilder creates a new EscalationBuilder with sensible defaults.
// The defaults match what most E2E tests need:
//   - MaxValidFor: 4h
//   - ApprovalTimeout: 2h
//   - E2E test labels
func NewEscalationBuilder(name, namespace string) *EscalationBuilder {
	return &EscalationBuilder{
		name:            name,
		namespace:       namespace,
		maxValidFor:     DefaultMaxValidFor,
		approvalTimeout: DefaultApprovalTimeout,
		labels:          E2ETestLabels(),
	}
}

// WithEscalatedGroup sets the group that users will be escalated to
func (b *EscalationBuilder) WithEscalatedGroup(group string) *EscalationBuilder {
	b.escalatedGroup = group
	return b
}

// WithMaxValidFor sets the maximum validity period for sessions.
// If the current approvalTimeout exceeds the new maxValidFor, approvalTimeout
// is automatically adjusted to match maxValidFor to avoid validation errors.
func (b *EscalationBuilder) WithMaxValidFor(duration string) *EscalationBuilder {
	b.maxValidFor = duration

	// Auto-adjust approvalTimeout if it exceeds maxValidFor
	// Parse both durations and compare
	maxDur, maxErr := time.ParseDuration(duration)
	approvalDur, approvalErr := time.ParseDuration(b.approvalTimeout)
	if maxErr == nil && approvalErr == nil && approvalDur > maxDur {
		b.approvalTimeout = duration
	}

	return b
}

// WithApprovalTimeout sets the approval timeout
func (b *EscalationBuilder) WithApprovalTimeout(timeout string) *EscalationBuilder {
	b.approvalTimeout = timeout
	return b
}

// WithAllowedClusters sets which clusters this escalation applies to
func (b *EscalationBuilder) WithAllowedClusters(clusters ...string) *EscalationBuilder {
	b.allowedClusters = clusters
	return b
}

// WithAllowedGroups sets which groups can request this escalation.
// If not set, defaults to the test requester's groups.
func (b *EscalationBuilder) WithAllowedGroups(groups ...string) *EscalationBuilder {
	b.allowedGroups = groups
	return b
}

// WithApproverUsers sets users who can approve sessions
func (b *EscalationBuilder) WithApproverUsers(users ...string) *EscalationBuilder {
	b.approverUsers = users
	return b
}

// WithApproverGroups sets groups who can approve sessions
func (b *EscalationBuilder) WithApproverGroups(groups ...string) *EscalationBuilder {
	b.approverGroups = groups
	return b
}

// WithHiddenApproverGroups sets groups who can approve but are hidden from UI
func (b *EscalationBuilder) WithHiddenApproverGroups(groups ...string) *EscalationBuilder {
	b.hiddenApproverGroups = groups
	return b
}

// WithHiddenApproverUsers sets users who can approve but are hidden from UI
func (b *EscalationBuilder) WithHiddenApproverUsers(users ...string) *EscalationBuilder {
	b.hiddenApproverUsers = users
	return b
}

// WithAllowedIDPsForRequests sets identity providers allowed for session requests
func (b *EscalationBuilder) WithAllowedIDPsForRequests(idps ...string) *EscalationBuilder {
	b.allowedIDPsForRequests = idps
	return b
}

// WithAllowedIDPsForApprovers sets identity providers allowed for session approvals
func (b *EscalationBuilder) WithAllowedIDPsForApprovers(idps ...string) *EscalationBuilder {
	b.allowedIDPsForApprovers = idps
	return b
}

// WithLabels sets custom labels (merged with E2E test labels)
func (b *EscalationBuilder) WithLabels(labels map[string]string) *EscalationBuilder {
	for k, v := range labels {
		b.labels[k] = v
	}
	return b
}

// WithDenyPolicyRefs sets the deny policies to attach to this escalation
func (b *EscalationBuilder) WithDenyPolicyRefs(refs ...string) *EscalationBuilder {
	b.denyPolicyRefs = refs
	return b
}

// WithMailProvider sets the mail provider for notifications
func (b *EscalationBuilder) WithMailProvider(provider string) *EscalationBuilder {
	b.mailProvider = provider
	return b
}

// WithBlockSelfApproval sets whether self-approval is blocked
func (b *EscalationBuilder) WithBlockSelfApproval(block bool) *EscalationBuilder {
	b.blockSelfApproval = &block
	return b
}

// WithRetainFor sets how long to retain sessions after expiry
func (b *EscalationBuilder) WithRetainFor(duration string) *EscalationBuilder {
	b.retainFor = duration
	return b
}

// WithClusterConfigRefs sets ClusterConfig references instead of explicit cluster list
func (b *EscalationBuilder) WithClusterConfigRefs(refs ...string) *EscalationBuilder {
	b.clusterConfigRefs = refs
	return b
}

// WithApproverDomains sets allowed approver domains for restricting who can approve
func (b *EscalationBuilder) WithApproverDomains(domains ...string) *EscalationBuilder {
	b.approverDomains = domains
	return b
}

// WithRequestReason sets the request reason configuration
func (b *EscalationBuilder) WithRequestReason(mandatory bool, description string) *EscalationBuilder {
	b.requestReason = &telekomv1alpha1.ReasonConfig{
		Mandatory:   mandatory,
		Description: description,
	}
	return b
}

// WithApprovalReason sets the approval reason configuration
func (b *EscalationBuilder) WithApprovalReason(mandatory bool, description string) *EscalationBuilder {
	b.approvalReason = &telekomv1alpha1.ReasonConfig{
		Mandatory:   mandatory,
		Description: description,
	}
	return b
}

// WithDisableNotifications sets whether to disable email notifications
func (b *EscalationBuilder) WithDisableNotifications(disable bool) *EscalationBuilder {
	b.disableNotifications = &disable
	return b
}

// WithNotificationExclusionUsers sets users to exclude from notifications
func (b *EscalationBuilder) WithNotificationExclusionUsers(users ...string) *EscalationBuilder {
	b.notificationExclusionUsers = users
	return b
}

// WithNotificationExclusionGroups sets groups to exclude from notifications
func (b *EscalationBuilder) WithNotificationExclusionGroups(groups ...string) *EscalationBuilder {
	b.notificationExclusionGroups = groups
	return b
}

// WithPodSecurityOverrides sets pod security overrides for the escalation
func (b *EscalationBuilder) WithPodSecurityOverrides(overrides *telekomv1alpha1.PodSecurityOverrides) *EscalationBuilder {
	b.podSecurityOverrides = overrides
	return b
}

// WithShortDurations sets short durations suitable for expiry testing
func (b *EscalationBuilder) WithShortDurations() *EscalationBuilder {
	b.maxValidFor = ShortMaxValidFor
	b.approvalTimeout = ShortApprovalTimeout
	return b
}

// Build constructs the BreakglassEscalation resource.
// If allowedGroups is not set, it defaults to TestUsers.Requester.Groups.
// If approverUsers is not set, it defaults to TestUsers.Approver.Email.
func (b *EscalationBuilder) Build() *telekomv1alpha1.BreakglassEscalation {
	// Apply defaults
	allowedGroups := b.allowedGroups
	if len(allowedGroups) == 0 {
		allowedGroups = TestUsers.Requester.Groups
	}

	approverUsers := b.approverUsers
	if len(approverUsers) == 0 && len(b.approverGroups) == 0 {
		approverUsers = []string{TestUsers.Approver.Email}
	}

	// Combine hidden approver users and groups
	hiddenFromUI := make([]string, 0, len(b.hiddenApproverUsers)+len(b.hiddenApproverGroups))
	hiddenFromUI = append(hiddenFromUI, b.hiddenApproverUsers...)
	hiddenFromUI = append(hiddenFromUI, b.hiddenApproverGroups...)

	escalation := &telekomv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      b.name,
			Namespace: b.namespace,
			Labels:    b.labels,
		},
		Spec: telekomv1alpha1.BreakglassEscalationSpec{
			EscalatedGroup:  b.escalatedGroup,
			MaxValidFor:     b.maxValidFor,
			ApprovalTimeout: b.approvalTimeout,
			Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
				Clusters: b.allowedClusters,
				Groups:   allowedGroups,
			},
			Approvers: telekomv1alpha1.BreakglassEscalationApprovers{
				Users:        approverUsers,
				Groups:       b.approverGroups,
				HiddenFromUI: hiddenFromUI,
			},
		},
	}

	// Apply optional fields
	if len(b.denyPolicyRefs) > 0 {
		escalation.Spec.DenyPolicyRefs = b.denyPolicyRefs
	}
	if b.mailProvider != "" {
		escalation.Spec.MailProvider = b.mailProvider
	}
	if b.blockSelfApproval != nil {
		escalation.Spec.BlockSelfApproval = b.blockSelfApproval
	}
	if b.retainFor != "" {
		escalation.Spec.RetainFor = b.retainFor
	}
	if len(b.clusterConfigRefs) > 0 {
		escalation.Spec.ClusterConfigRefs = b.clusterConfigRefs
	}
	if len(b.approverDomains) > 0 {
		escalation.Spec.AllowedApproverDomains = b.approverDomains
	}
	if b.requestReason != nil {
		escalation.Spec.RequestReason = b.requestReason
	}
	if b.approvalReason != nil {
		escalation.Spec.ApprovalReason = b.approvalReason
	}
	if b.disableNotifications != nil {
		escalation.Spec.DisableNotifications = b.disableNotifications
	}
	if b.podSecurityOverrides != nil {
		escalation.Spec.PodSecurityOverrides = b.podSecurityOverrides
	}
	if len(b.allowedIDPsForRequests) > 0 {
		escalation.Spec.AllowedIdentityProvidersForRequests = b.allowedIDPsForRequests
	}
	if len(b.allowedIDPsForApprovers) > 0 {
		escalation.Spec.AllowedIdentityProvidersForApprovers = b.allowedIDPsForApprovers
	}
	if len(b.notificationExclusionUsers) > 0 || len(b.notificationExclusionGroups) > 0 {
		escalation.Spec.NotificationExclusions = &telekomv1alpha1.NotificationExclusions{
			Users:  b.notificationExclusionUsers,
			Groups: b.notificationExclusionGroups,
		}
	}

	return escalation
}

// DenyPolicyBuilder provides a fluent API for building DenyPolicy resources.
type DenyPolicyBuilder struct {
	name             string
	namespace        string
	labels           map[string]string
	rules            []telekomv1alpha1.DenyRule
	precedence       *int32
	appliesTo        *telekomv1alpha1.DenyPolicyScope
	podSecurityRules *telekomv1alpha1.PodSecurityRules
}

// NewDenyPolicyBuilder creates a new DenyPolicyBuilder with E2E test labels
func NewDenyPolicyBuilder(name, namespace string) *DenyPolicyBuilder {
	return &DenyPolicyBuilder{
		name:      name,
		namespace: namespace,
		labels:    E2ETestLabels(),
		rules:     []telekomv1alpha1.DenyRule{},
	}
}

// WithLabels sets custom labels (replaces default E2E labels).
func (b *DenyPolicyBuilder) WithLabels(labels map[string]string) *DenyPolicyBuilder {
	b.labels = labels
	return b
}

// WithPrecedence sets the policy precedence (lower wins, defaults to 100)
func (b *DenyPolicyBuilder) WithPrecedence(precedence int32) *DenyPolicyBuilder {
	b.precedence = &precedence
	return b
}

// AppliesToClusters sets the clusters this policy applies to.
func (b *DenyPolicyBuilder) AppliesToClusters(clusters ...string) *DenyPolicyBuilder {
	if b.appliesTo == nil {
		b.appliesTo = &telekomv1alpha1.DenyPolicyScope{}
	}
	b.appliesTo.Clusters = clusters
	return b
}

// AppliesToTenants sets the tenants this policy applies to.
func (b *DenyPolicyBuilder) AppliesToTenants(tenants ...string) *DenyPolicyBuilder {
	if b.appliesTo == nil {
		b.appliesTo = &telekomv1alpha1.DenyPolicyScope{}
	}
	b.appliesTo.Tenants = tenants
	return b
}

// AppliesToSessions sets the sessions this policy applies to.
func (b *DenyPolicyBuilder) AppliesToSessions(sessions ...string) *DenyPolicyBuilder {
	if b.appliesTo == nil {
		b.appliesTo = &telekomv1alpha1.DenyPolicyScope{}
	}
	b.appliesTo.Sessions = sessions
	return b
}

// WithRule adds a deny rule
func (b *DenyPolicyBuilder) WithRule(rule telekomv1alpha1.DenyRule) *DenyPolicyBuilder {
	b.rules = append(b.rules, rule)
	return b
}

// DenySecrets adds a rule to deny access to secrets in specified namespaces
func (b *DenyPolicyBuilder) DenySecrets(namespaces ...string) *DenyPolicyBuilder {
	rule := telekomv1alpha1.DenyRule{
		Verbs:     []string{"get", "list", "watch", "create", "update", "delete"},
		APIGroups: []string{""},
		Resources: []string{"secrets"},
	}
	if len(namespaces) > 0 {
		rule.Namespaces = &telekomv1alpha1.NamespaceFilter{
			Patterns: namespaces,
		}
	}
	return b.WithRule(rule)
}

// DenyPodsExec adds a rule to deny exec on pods
func (b *DenyPolicyBuilder) DenyPodsExec(namespaces ...string) *DenyPolicyBuilder {
	rule := telekomv1alpha1.DenyRule{
		Verbs:     []string{"create"},
		APIGroups: []string{""},
		Resources: []string{"pods/exec"},
	}
	if len(namespaces) > 0 {
		rule.Namespaces = &telekomv1alpha1.NamespaceFilter{
			Patterns: namespaces,
		}
	}
	return b.WithRule(rule)
}

// DenyAll adds a rule to deny all operations on specified resources
func (b *DenyPolicyBuilder) DenyAll(apiGroups, resources []string, namespaces ...string) *DenyPolicyBuilder {
	rule := telekomv1alpha1.DenyRule{
		Verbs:     []string{"*"},
		APIGroups: apiGroups,
		Resources: resources,
	}
	if len(namespaces) > 0 {
		rule.Namespaces = &telekomv1alpha1.NamespaceFilter{
			Patterns: namespaces,
		}
	}
	return b.WithRule(rule)
}

// DenyPods adds a rule to deny specified verbs on pods
func (b *DenyPolicyBuilder) DenyPods(verbs []string, namespaces ...string) *DenyPolicyBuilder {
	rule := telekomv1alpha1.DenyRule{
		Verbs:     verbs,
		APIGroups: []string{""},
		Resources: []string{"pods"},
	}
	if len(namespaces) > 0 {
		rule.Namespaces = &telekomv1alpha1.NamespaceFilter{
			Patterns: namespaces,
		}
	}
	return b.WithRule(rule)
}

// DenyResource adds a rule to deny specified verbs on a resource
func (b *DenyPolicyBuilder) DenyResource(apiGroup, resource string, verbs []string, namespaces ...string) *DenyPolicyBuilder {
	rule := telekomv1alpha1.DenyRule{
		Verbs:     verbs,
		APIGroups: []string{apiGroup},
		Resources: []string{resource},
	}
	if len(namespaces) > 0 {
		rule.Namespaces = &telekomv1alpha1.NamespaceFilter{
			Patterns: namespaces,
		}
	}
	return b.WithRule(rule)
}

// WithPodSecurityRules sets pod security rules for the policy
func (b *DenyPolicyBuilder) WithPodSecurityRules(rules *telekomv1alpha1.PodSecurityRules) *DenyPolicyBuilder {
	b.podSecurityRules = rules
	return b
}

// Build constructs the DenyPolicy resource
func (b *DenyPolicyBuilder) Build() *telekomv1alpha1.DenyPolicy {
	policy := &telekomv1alpha1.DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      b.name,
			Namespace: b.namespace,
			Labels:    b.labels,
		},
		Spec: telekomv1alpha1.DenyPolicySpec{
			Rules: b.rules,
		},
	}

	if b.precedence != nil {
		policy.Spec.Precedence = b.precedence
	}
	if b.appliesTo != nil {
		policy.Spec.AppliesTo = b.appliesTo
	}
	if b.podSecurityRules != nil {
		policy.Spec.PodSecurityRules = b.podSecurityRules
	}

	return policy
}

// =============================================================================
// SessionBuilder - Fluent API for BreakglassSession resources
// =============================================================================

// SessionBuilder provides a fluent API for building BreakglassSession resources.
// Use this for tests that need to create sessions directly (e.g., webhook tests,
// cleanup tests). For normal session workflows, use the API client methods.
type SessionBuilder struct {
	name             string
	namespace        string
	cluster          string
	user             string
	grantedGroup     string
	maxValidFor      string
	retainFor        string
	requestReason    string
	denyPolicyRefs   []string
	clusterConfigRef string
	labels           map[string]string
}

// NewSessionBuilder creates a new SessionBuilder with sensible defaults.
func NewSessionBuilder(name, namespace string) *SessionBuilder {
	return &SessionBuilder{
		name:        name,
		namespace:   namespace,
		maxValidFor: "1h",
		labels:      E2ETestLabels(),
	}
}

// WithCluster sets the target cluster name.
func (b *SessionBuilder) WithCluster(cluster string) *SessionBuilder {
	b.cluster = cluster
	return b
}

// WithUser sets the user email.
func (b *SessionBuilder) WithUser(user string) *SessionBuilder {
	b.user = user
	return b
}

// WithGrantedGroup sets the granted group.
func (b *SessionBuilder) WithGrantedGroup(group string) *SessionBuilder {
	b.grantedGroup = group
	return b
}

// WithMaxValidFor sets the maximum validity duration.
func (b *SessionBuilder) WithMaxValidFor(duration string) *SessionBuilder {
	b.maxValidFor = duration
	return b
}

// WithRetainFor sets the retention duration after expiry.
func (b *SessionBuilder) WithRetainFor(duration string) *SessionBuilder {
	b.retainFor = duration
	return b
}

// WithRequestReason sets the request reason.
func (b *SessionBuilder) WithRequestReason(reason string) *SessionBuilder {
	b.requestReason = reason
	return b
}

// WithDenyPolicyRefs sets the deny policy references.
func (b *SessionBuilder) WithDenyPolicyRefs(refs ...string) *SessionBuilder {
	b.denyPolicyRefs = refs
	return b
}

// WithClusterConfigRef sets the cluster config reference.
func (b *SessionBuilder) WithClusterConfigRef(ref string) *SessionBuilder {
	b.clusterConfigRef = ref
	return b
}

// WithLabels sets custom labels (replaces default E2E labels).
func (b *SessionBuilder) WithLabels(labels map[string]string) *SessionBuilder {
	b.labels = labels
	return b
}

// Build constructs the BreakglassSession resource.
func (b *SessionBuilder) Build() *telekomv1alpha1.BreakglassSession {
	session := &telekomv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      b.name,
			Namespace: b.namespace,
			Labels:    b.labels,
		},
		Spec: telekomv1alpha1.BreakglassSessionSpec{
			Cluster:      b.cluster,
			User:         b.user,
			GrantedGroup: b.grantedGroup,
			MaxValidFor:  b.maxValidFor,
		},
	}

	if b.retainFor != "" {
		session.Spec.RetainFor = b.retainFor
	}
	if b.requestReason != "" {
		session.Spec.RequestReason = b.requestReason
	}
	if len(b.denyPolicyRefs) > 0 {
		session.Spec.DenyPolicyRefs = b.denyPolicyRefs
	}
	if b.clusterConfigRef != "" {
		session.Spec.ClusterConfigRef = b.clusterConfigRef
	}

	return session
}

// =============================================================================
// ClusterConfigBuilder - Fluent API for ClusterConfig resources
// =============================================================================

// ClusterConfigBuilder provides a fluent API for building ClusterConfig resources.
type ClusterConfigBuilder struct {
	name                     string
	namespace                string
	clusterID                string
	tenant                   string
	environment              string
	site                     string
	location                 string
	qps                      *int32
	burst                    *int32
	kubeconfigSecretRef      *telekomv1alpha1.SecretKeyReference
	blockSelfApproval        bool
	identityProviderRefs     []string
	labels                   map[string]string
	authType                 telekomv1alpha1.ClusterAuthType
	oidcAuth                 *telekomv1alpha1.OIDCAuthConfig
	oidcFromIdentityProvider *telekomv1alpha1.OIDCFromIdentityProviderConfig
}

// NewClusterConfigBuilder creates a new ClusterConfigBuilder with sensible defaults.
func NewClusterConfigBuilder(name, namespace string) *ClusterConfigBuilder {
	return &ClusterConfigBuilder{
		name:      name,
		namespace: namespace,
		labels:    E2ETestLabels(),
	}
}

// WithClusterID sets the cluster ID (defaults to name if not set).
func (b *ClusterConfigBuilder) WithClusterID(id string) *ClusterConfigBuilder {
	b.clusterID = id
	return b
}

// WithTenant sets the tenant.
func (b *ClusterConfigBuilder) WithTenant(tenant string) *ClusterConfigBuilder {
	b.tenant = tenant
	return b
}

// WithEnvironment sets the environment (dev, staging, prod).
func (b *ClusterConfigBuilder) WithEnvironment(env string) *ClusterConfigBuilder {
	b.environment = env
	return b
}

// WithSite sets the site.
func (b *ClusterConfigBuilder) WithSite(site string) *ClusterConfigBuilder {
	b.site = site
	return b
}

// WithLocation sets the location/region.
func (b *ClusterConfigBuilder) WithLocation(location string) *ClusterConfigBuilder {
	b.location = location
	return b
}

// WithQPS sets the client QPS for the target cluster.
func (b *ClusterConfigBuilder) WithQPS(qps int32) *ClusterConfigBuilder {
	b.qps = &qps
	return b
}

// WithBurst sets the client burst for the target cluster.
func (b *ClusterConfigBuilder) WithBurst(burst int32) *ClusterConfigBuilder {
	b.burst = &burst
	return b
}

// WithKubeconfigSecret sets the kubeconfig secret reference.
// The namespace defaults to the ClusterConfig's namespace if not provided.
// If secretKey is empty, the default key ("value") will be used by the controller.
func (b *ClusterConfigBuilder) WithKubeconfigSecret(secretName, secretKey string) *ClusterConfigBuilder {
	b.kubeconfigSecretRef = &telekomv1alpha1.SecretKeyReference{
		Name:      secretName,
		Namespace: b.namespace,
	}
	if secretKey != "" {
		b.kubeconfigSecretRef.Key = secretKey
	}
	return b
}

// WithKubeconfigSecretInNamespace sets the kubeconfig secret reference with an explicit namespace.
// If secretKey is empty, the default key ("value") will be used by the controller.
func (b *ClusterConfigBuilder) WithKubeconfigSecretInNamespace(secretName, secretNamespace, secretKey string) *ClusterConfigBuilder {
	b.kubeconfigSecretRef = &telekomv1alpha1.SecretKeyReference{
		Name:      secretName,
		Namespace: secretNamespace,
	}
	if secretKey != "" {
		b.kubeconfigSecretRef.Key = secretKey
	}
	return b
}

// WithBlockSelfApproval enables blocking self-approval for this cluster.
func (b *ClusterConfigBuilder) WithBlockSelfApproval(block bool) *ClusterConfigBuilder {
	b.blockSelfApproval = block
	return b
}

// WithIdentityProviderRefs sets the allowed identity providers.
func (b *ClusterConfigBuilder) WithIdentityProviderRefs(refs ...string) *ClusterConfigBuilder {
	b.identityProviderRefs = refs
	return b
}

// WithLabels sets custom labels (replaces default E2E labels).
func (b *ClusterConfigBuilder) WithLabels(labels map[string]string) *ClusterConfigBuilder {
	b.labels = labels
	return b
}

// WithAuthType sets the authentication type (Kubeconfig or OIDC).
func (b *ClusterConfigBuilder) WithAuthType(authType telekomv1alpha1.ClusterAuthType) *ClusterConfigBuilder {
	b.authType = authType
	return b
}

// WithOIDCAuth sets OIDC authentication configuration.
// This also sets AuthType to OIDC automatically.
func (b *ClusterConfigBuilder) WithOIDCAuth(issuerURL, clientID, server string) *ClusterConfigBuilder {
	b.authType = telekomv1alpha1.ClusterAuthTypeOIDC
	b.oidcAuth = &telekomv1alpha1.OIDCAuthConfig{
		IssuerURL: issuerURL,
		ClientID:  clientID,
		Server:    server,
	}
	return b
}

// WithOIDCClientSecret sets the client secret reference for OIDC auth.
// Must be called after WithOIDCAuth.
func (b *ClusterConfigBuilder) WithOIDCClientSecret(secretName, secretNamespace, secretKey string) *ClusterConfigBuilder {
	if b.oidcAuth == nil {
		b.oidcAuth = &telekomv1alpha1.OIDCAuthConfig{}
	}
	b.oidcAuth.ClientSecretRef = &telekomv1alpha1.SecretKeyReference{
		Name:      secretName,
		Namespace: secretNamespace,
		Key:       secretKey,
	}
	return b
}

// WithOIDCCertificateAuthority sets the CA certificate for validating the OIDC issuer's TLS cert.
// The certificate should be PEM encoded.
func (b *ClusterConfigBuilder) WithOIDCCertificateAuthority(caPEM string) *ClusterConfigBuilder {
	if b.oidcAuth == nil {
		b.oidcAuth = &telekomv1alpha1.OIDCAuthConfig{}
	}
	b.oidcAuth.CertificateAuthority = caPEM
	return b
}

// WithOIDCInsecureSkipTLSVerify sets insecure TLS verification for OIDC (for testing only).
func (b *ClusterConfigBuilder) WithOIDCInsecureSkipTLSVerify(skip bool) *ClusterConfigBuilder {
	if b.oidcAuth == nil {
		b.oidcAuth = &telekomv1alpha1.OIDCAuthConfig{}
	}
	b.oidcAuth.InsecureSkipTLSVerify = skip
	return b
}

// WithOIDCScopes sets additional OIDC scopes to request.
func (b *ClusterConfigBuilder) WithOIDCScopes(scopes ...string) *ClusterConfigBuilder {
	if b.oidcAuth == nil {
		b.oidcAuth = &telekomv1alpha1.OIDCAuthConfig{}
	}
	b.oidcAuth.Scopes = scopes
	return b
}

// WithOIDCAudience sets the OIDC audience for token requests.
func (b *ClusterConfigBuilder) WithOIDCAudience(audience string) *ClusterConfigBuilder {
	if b.oidcAuth == nil {
		b.oidcAuth = &telekomv1alpha1.OIDCAuthConfig{}
	}
	b.oidcAuth.Audience = audience
	return b
}

// WithOIDCFromIdentityProvider configures OIDC settings inherited from an IdentityProvider.
// This also sets AuthType to OIDC automatically.
func (b *ClusterConfigBuilder) WithOIDCFromIdentityProvider(idpName, server string) *ClusterConfigBuilder {
	b.authType = telekomv1alpha1.ClusterAuthTypeOIDC
	b.oidcFromIdentityProvider = &telekomv1alpha1.OIDCFromIdentityProviderConfig{
		Name:   idpName,
		Server: server,
	}
	return b
}

// Build constructs the ClusterConfig resource.
func (b *ClusterConfigBuilder) Build() *telekomv1alpha1.ClusterConfig {
	config := &telekomv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name:      b.name,
			Namespace: b.namespace,
			Labels:    b.labels,
		},
		Spec: telekomv1alpha1.ClusterConfigSpec{
			BlockSelfApproval: b.blockSelfApproval,
		},
	}

	if b.clusterID != "" {
		config.Spec.ClusterID = b.clusterID
	}
	if b.tenant != "" {
		config.Spec.Tenant = b.tenant
	}
	if b.environment != "" {
		config.Spec.Environment = b.environment
	}
	if b.site != "" {
		config.Spec.Site = b.site
	}
	if b.location != "" {
		config.Spec.Location = b.location
	}
	if b.qps != nil {
		config.Spec.QPS = b.qps
	}
	if b.burst != nil {
		config.Spec.Burst = b.burst
	}
	if b.kubeconfigSecretRef != nil {
		config.Spec.KubeconfigSecretRef = b.kubeconfigSecretRef
	}
	if len(b.identityProviderRefs) > 0 {
		config.Spec.IdentityProviderRefs = b.identityProviderRefs
	}
	// OIDC authentication support
	if b.authType != "" {
		config.Spec.AuthType = b.authType
	}
	if b.oidcAuth != nil {
		config.Spec.OIDCAuth = b.oidcAuth
	}
	if b.oidcFromIdentityProvider != nil {
		config.Spec.OIDCFromIdentityProvider = b.oidcFromIdentityProvider
	}

	return config
}
