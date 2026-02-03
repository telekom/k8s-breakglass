package client

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/telekom/k8s-breakglass/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type DebugSessionService struct {
	client *Client
}

func (c *Client) DebugSessions() *DebugSessionService {
	return &DebugSessionService{client: c}
}

type DebugSessionListOptions struct {
	Cluster string
	State   string
	User    string
	Mine    bool
}

type DebugSessionSummary struct {
	Name          string                     `json:"name"`
	TemplateRef   string                     `json:"templateRef"`
	Cluster       string                     `json:"cluster"`
	RequestedBy   string                     `json:"requestedBy"`
	State         v1alpha1.DebugSessionState `json:"state"`
	StatusMessage string                     `json:"statusMessage,omitempty"`
	StartsAt      *metav1.Time               `json:"startsAt,omitempty"`
	ExpiresAt     *metav1.Time               `json:"expiresAt,omitempty"`
	Participants  int                        `json:"participants"`
	AllowedPods   int                        `json:"allowedPods"`
}

type DebugSessionListResponse struct {
	Sessions []DebugSessionSummary `json:"sessions"`
	Total    int                   `json:"total"`
}

// DebugSessionDetailResponse represents the detailed debug session response.
// The DebugSession is embedded to match the server API which returns the session
// at the root level (not wrapped in a "debugSession" field).
type DebugSessionDetailResponse struct {
	v1alpha1.DebugSession
}

type CreateDebugSessionRequest struct {
	TemplateRef              string            `json:"templateRef"`
	Cluster                  string            `json:"cluster"`
	BindingRef               string            `json:"bindingRef,omitempty"` // Optional: explicit binding selection as "namespace/name" when multiple match
	RequestedDuration        string            `json:"requestedDuration,omitempty"`
	NodeSelector             map[string]string `json:"nodeSelector,omitempty"`
	Namespace                string            `json:"namespace,omitempty"`
	Reason                   string            `json:"reason,omitempty"`
	InvitedParticipants      []string          `json:"invitedParticipants,omitempty"`
	TargetNamespace          string            `json:"targetNamespace,omitempty"`
	SelectedSchedulingOption string            `json:"selectedSchedulingOption,omitempty"`
}

type JoinDebugSessionRequest struct {
	Role string `json:"role,omitempty"`
}

type RenewDebugSessionRequest struct {
	ExtendBy string `json:"extendBy"`
}

type ApprovalRequest struct {
	Reason string `json:"reason,omitempty"`
}

type InjectEphemeralContainerRequest struct {
	Namespace       string                 `json:"namespace"`
	PodName         string                 `json:"podName"`
	ContainerName   string                 `json:"containerName"`
	Image           string                 `json:"image"`
	Command         []string               `json:"command,omitempty"`
	SecurityContext map[string]interface{} `json:"securityContext,omitempty"`
}

type CreatePodCopyRequest struct {
	Namespace  string `json:"namespace"`
	PodName    string `json:"podName"`
	DebugImage string `json:"debugImage,omitempty"`
}

type CreateNodeDebugPodRequest struct {
	NodeName string `json:"nodeName"`
}

func (s *DebugSessionService) List(ctx context.Context, opts DebugSessionListOptions) (*DebugSessionListResponse, error) {
	endpoint := "api/debugSessions"
	params := url.Values{}
	if opts.Cluster != "" {
		params.Set("cluster", opts.Cluster)
	}
	if opts.State != "" {
		params.Set("state", opts.State)
	}
	if opts.User != "" {
		params.Set("user", opts.User)
	}
	if opts.Mine {
		params.Set("mine", "true")
	}
	if encoded := params.Encode(); encoded != "" {
		endpoint = fmt.Sprintf("%s?%s", endpoint, encoded)
	}
	var resp DebugSessionListResponse
	if err := s.client.do(ctx, http.MethodGet, endpoint, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (s *DebugSessionService) Get(ctx context.Context, name, namespace string) (*v1alpha1.DebugSession, error) {
	endpoint := fmt.Sprintf("api/debugSessions/%s", url.PathEscape(name))
	if namespace != "" {
		endpoint = endpoint + "?namespace=" + url.QueryEscape(namespace)
	}
	var resp DebugSessionDetailResponse
	if err := s.client.do(ctx, http.MethodGet, endpoint, nil, &resp); err != nil {
		return nil, err
	}
	return &resp.DebugSession, nil
}

func (s *DebugSessionService) Create(ctx context.Context, req CreateDebugSessionRequest) (*v1alpha1.DebugSession, error) {
	endpoint := "api/debugSessions"
	var resp DebugSessionDetailResponse
	if err := s.client.do(ctx, http.MethodPost, endpoint, req, &resp); err != nil {
		return nil, err
	}
	return &resp.DebugSession, nil
}

func (s *DebugSessionService) Join(ctx context.Context, name, role, namespace string) (*v1alpha1.DebugSession, error) {
	payload := JoinDebugSessionRequest{Role: role}
	return s.action(ctx, name, "join", namespace, payload)
}

func (s *DebugSessionService) Leave(ctx context.Context, name, namespace string) (*v1alpha1.DebugSession, error) {
	return s.action(ctx, name, "leave", namespace, nil)
}

func (s *DebugSessionService) Renew(ctx context.Context, name, extendBy, namespace string) (*v1alpha1.DebugSession, error) {
	payload := RenewDebugSessionRequest{ExtendBy: extendBy}
	return s.action(ctx, name, "renew", namespace, payload)
}

func (s *DebugSessionService) Terminate(ctx context.Context, name, namespace string) (*v1alpha1.DebugSession, error) {
	return s.action(ctx, name, "terminate", namespace, nil)
}

func (s *DebugSessionService) Approve(ctx context.Context, name, reason, namespace string) (*v1alpha1.DebugSession, error) {
	payload := ApprovalRequest{Reason: reason}
	return s.action(ctx, name, "approve", namespace, payload)
}

func (s *DebugSessionService) Reject(ctx context.Context, name, reason, namespace string) (*v1alpha1.DebugSession, error) {
	payload := ApprovalRequest{Reason: reason}
	return s.action(ctx, name, "reject", namespace, payload)
}

func (s *DebugSessionService) action(ctx context.Context, name, action, namespace string, payload any) (*v1alpha1.DebugSession, error) {
	endpoint := fmt.Sprintf("api/debugSessions/%s/%s", url.PathEscape(name), action)
	if namespace != "" {
		endpoint = endpoint + "?namespace=" + url.QueryEscape(namespace)
	}
	var resp DebugSessionDetailResponse
	if err := s.client.do(ctx, http.MethodPost, endpoint, payload, &resp); err != nil {
		return nil, err
	}
	return &resp.DebugSession, nil
}

func (s *DebugSessionService) InjectEphemeralContainer(ctx context.Context, name, namespace string, req InjectEphemeralContainerRequest) (map[string]interface{}, error) {
	endpoint := fmt.Sprintf("api/debugSessions/%s/injectEphemeralContainer", url.PathEscape(name))
	if namespace != "" {
		endpoint = endpoint + "?namespace=" + url.QueryEscape(namespace)
	}
	var resp map[string]interface{}
	if err := s.client.do(ctx, http.MethodPost, endpoint, req, &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func (s *DebugSessionService) CreatePodCopy(ctx context.Context, name, namespace string, req CreatePodCopyRequest) (map[string]interface{}, error) {
	endpoint := fmt.Sprintf("api/debugSessions/%s/createPodCopy", url.PathEscape(name))
	if namespace != "" {
		endpoint = endpoint + "?namespace=" + url.QueryEscape(namespace)
	}
	var resp map[string]interface{}
	if err := s.client.do(ctx, http.MethodPost, endpoint, req, &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func (s *DebugSessionService) CreateNodeDebugPod(ctx context.Context, name, namespace string, req CreateNodeDebugPodRequest) (map[string]interface{}, error) {
	endpoint := fmt.Sprintf("api/debugSessions/%s/createNodeDebugPod", url.PathEscape(name))
	if namespace != "" {
		endpoint = endpoint + "?namespace=" + url.QueryEscape(namespace)
	}
	var resp map[string]interface{}
	if err := s.client.do(ctx, http.MethodPost, endpoint, req, &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

type DebugTemplateService struct {
	client *Client
}

// DebugSessionTemplateSummary represents a template summary from the API
type DebugSessionTemplateSummary struct {
	Name                  string                            `json:"name"`
	DisplayName           string                            `json:"displayName"`
	Description           string                            `json:"description,omitempty"`
	Mode                  v1alpha1.DebugSessionTemplateMode `json:"mode"`
	WorkloadType          v1alpha1.DebugWorkloadType        `json:"workloadType,omitempty"`
	PodTemplateRef        string                            `json:"podTemplateRef,omitempty"`
	TargetNamespace       string                            `json:"targetNamespace,omitempty"`
	Constraints           *v1alpha1.DebugSessionConstraints `json:"constraints,omitempty"`
	AllowedClusters       []string                          `json:"allowedClusters,omitempty"`
	AllowedGroups         []string                          `json:"allowedGroups,omitempty"`
	RequiresApproval      bool                              `json:"requiresApproval"`
	HasAvailableClusters  bool                              `json:"hasAvailableClusters"`            // True if at least one cluster is available
	AvailableClusterCount int                               `json:"availableClusterCount,omitempty"` // Number of clusters user can deploy to
}

// DebugTemplateListResponse represents the API response for template list
type DebugTemplateListResponse struct {
	Templates []DebugSessionTemplateSummary `json:"templates"`
	Total     int                           `json:"total"`
}

// DebugTemplateListOptions represents options for listing templates
type DebugTemplateListOptions struct {
	// IncludeUnavailable includes templates with no available clusters
	IncludeUnavailable bool
}

func (c *Client) DebugTemplates() *DebugTemplateService {
	return &DebugTemplateService{client: c}
}

func (d *DebugTemplateService) List(ctx context.Context, opts ...DebugTemplateListOptions) (*DebugTemplateListResponse, error) {
	endpoint := "api/debugSessions/templates"
	// Apply options if provided
	if len(opts) > 0 && opts[0].IncludeUnavailable {
		endpoint += "?includeUnavailable=true"
	}
	var resp DebugTemplateListResponse
	if err := d.client.do(ctx, http.MethodGet, endpoint, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (d *DebugTemplateService) Get(ctx context.Context, name string) (*DebugSessionTemplateSummary, error) {
	endpoint := fmt.Sprintf("api/debugSessions/templates/%s", url.PathEscape(name))
	var template DebugSessionTemplateSummary
	if err := d.client.do(ctx, http.MethodGet, endpoint, nil, &template); err != nil {
		return nil, err
	}
	return &template, nil
}

// TemplateClustersResponse represents the response for GET /templates/{name}/clusters
type TemplateClustersResponse struct {
	TemplateName        string                   `json:"templateName"`
	TemplateDisplayName string                   `json:"templateDisplayName"`
	Clusters            []AvailableClusterDetail `json:"clusters"`
}

// AvailableClusterDetail represents a cluster with resolved constraints for a template.
// When multiple bindings match a cluster, BindingOptions contains all available options.
type AvailableClusterDetail struct {
	Name                          string                            `json:"name"`
	DisplayName                   string                            `json:"displayName,omitempty"`
	Environment                   string                            `json:"environment,omitempty"`
	Location                      string                            `json:"location,omitempty"`
	Site                          string                            `json:"site,omitempty"`
	Tenant                        string                            `json:"tenant,omitempty"`
	BindingRef                    *BindingReference                 `json:"bindingRef,omitempty"`     // Default/primary binding (backward compat)
	BindingOptions                []BindingOption                   `json:"bindingOptions,omitempty"` // All available binding options
	Constraints                   *v1alpha1.DebugSessionConstraints `json:"constraints,omitempty"`
	SchedulingConstraints         *SchedulingConstraintsSummary     `json:"schedulingConstraints,omitempty"`
	SchedulingOptions             *SchedulingOptionsResponse        `json:"schedulingOptions,omitempty"`
	NamespaceConstraints          *NamespaceConstraintsResponse     `json:"namespaceConstraints,omitempty"`
	Impersonation                 *ImpersonationSummary             `json:"impersonation,omitempty"`
	RequiredAuxResourceCategories []string                          `json:"requiredAuxiliaryResourceCategories,omitempty"`
	Approval                      *ApprovalInfo                     `json:"approval,omitempty"`
	Status                        *ClusterStatusInfo                `json:"status,omitempty"`
}

// BindingOption represents a single binding option with its resolved configuration
type BindingOption struct {
	BindingRef                    BindingReference                  `json:"bindingRef"`
	DisplayName                   string                            `json:"displayName,omitempty"`
	Constraints                   *v1alpha1.DebugSessionConstraints `json:"constraints,omitempty"`
	SchedulingConstraints         *SchedulingConstraintsSummary     `json:"schedulingConstraints,omitempty"`
	SchedulingOptions             *SchedulingOptionsResponse        `json:"schedulingOptions,omitempty"`
	NamespaceConstraints          *NamespaceConstraintsResponse     `json:"namespaceConstraints,omitempty"`
	Impersonation                 *ImpersonationSummary             `json:"impersonation,omitempty"`
	RequiredAuxResourceCategories []string                          `json:"requiredAuxiliaryResourceCategories,omitempty"`
	Approval                      *ApprovalInfo                     `json:"approval,omitempty"`
	RequestReason                 *ReasonConfigInfo                 `json:"requestReason,omitempty"`
	ApprovalReason                *ReasonConfigInfo                 `json:"approvalReason,omitempty"`
	Notification                  *NotificationConfigInfo           `json:"notification,omitempty"`
}

// BindingReference identifies the binding that enabled access
type BindingReference struct {
	Name              string `json:"name"`
	Namespace         string `json:"namespace"`
	DisplayNamePrefix string `json:"displayNamePrefix,omitempty"`
}

// SchedulingConstraintsSummary summarizes scheduling constraints for API responses
type SchedulingConstraintsSummary struct {
	Summary          string            `json:"summary,omitempty"`
	DeniedNodeLabels map[string]string `json:"deniedNodeLabels,omitempty"`
}

// SchedulingOptionsResponse represents scheduling options in API responses
type SchedulingOptionsResponse struct {
	Required bool                       `json:"required"`
	Options  []SchedulingOptionResponse `json:"options"`
}

// SchedulingOptionResponse represents a single scheduling option in API responses
type SchedulingOptionResponse struct {
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
	Description string `json:"description,omitempty"`
	Default     bool   `json:"default,omitempty"`
}

// NamespaceConstraintsResponse represents namespace constraints in API responses
type NamespaceConstraintsResponse struct {
	AllowedPatterns       []string                        `json:"allowedPatterns,omitempty"`
	AllowedLabelSelectors []NamespaceSelectorTermResponse `json:"allowedLabelSelectors,omitempty"`
	DeniedPatterns        []string                        `json:"deniedPatterns,omitempty"`
	DeniedLabelSelectors  []NamespaceSelectorTermResponse `json:"deniedLabelSelectors,omitempty"`
	DefaultNamespace      string                          `json:"defaultNamespace,omitempty"`
	AllowUserNamespace    bool                            `json:"allowUserNamespace"`
}

// NamespaceSelectorTermResponse represents a label selector term in API responses
type NamespaceSelectorTermResponse struct {
	MatchLabels      map[string]string                      `json:"matchLabels,omitempty"`
	MatchExpressions []NamespaceSelectorRequirementResponse `json:"matchExpressions,omitempty"`
}

// NamespaceSelectorRequirementResponse represents a label selector requirement in API responses
type NamespaceSelectorRequirementResponse struct {
	Key      string   `json:"key"`
	Operator string   `json:"operator"`
	Values   []string `json:"values,omitempty"`
}

// ImpersonationSummary summarizes impersonation configuration for API responses
type ImpersonationSummary struct {
	Enabled        bool   `json:"enabled"`
	ServiceAccount string `json:"serviceAccount,omitempty"`
	Namespace      string `json:"namespace,omitempty"`
	Reason         string `json:"reason,omitempty"`
}

// ApprovalInfo contains approval requirements for a cluster
type ApprovalInfo struct {
	Required       bool     `json:"required"`
	ApproverGroups []string `json:"approverGroups,omitempty"`
	ApproverUsers  []string `json:"approverUsers,omitempty"`
	CanAutoApprove bool     `json:"canAutoApprove,omitempty"`
}

// ClusterStatusInfo contains cluster health status
type ClusterStatusInfo struct {
	Healthy     bool   `json:"healthy"`
	LastChecked string `json:"lastChecked,omitempty"`
}

// ReasonConfigInfo contains reason configuration for API responses
type ReasonConfigInfo struct {
	Mandatory        bool     `json:"mandatory"`
	Description      string   `json:"description,omitempty"`
	MinLength        int32    `json:"minLength,omitempty"`
	MaxLength        int32    `json:"maxLength,omitempty"`
	SuggestedReasons []string `json:"suggestedReasons,omitempty"`
}

// NotificationConfigInfo contains notification configuration for API responses
type NotificationConfigInfo struct {
	Enabled bool `json:"enabled"`
}

// TemplateClustersOptions contains optional filters for GetClusters
type TemplateClustersOptions struct {
	Environment string
	Location    string
	BindingName string
}

// GetClusters returns cluster-specific details for a template
func (d *DebugTemplateService) GetClusters(ctx context.Context, name string, opts TemplateClustersOptions) (*TemplateClustersResponse, error) {
	endpoint := fmt.Sprintf("api/debugSessions/templates/%s/clusters", url.PathEscape(name))

	// Build query params
	params := url.Values{}
	if opts.Environment != "" {
		params.Set("environment", opts.Environment)
	}
	if opts.Location != "" {
		params.Set("location", opts.Location)
	}
	if opts.BindingName != "" {
		params.Set("bindingName", opts.BindingName)
	}
	if len(params) > 0 {
		endpoint = endpoint + "?" + params.Encode()
	}

	var resp TemplateClustersResponse
	if err := d.client.do(ctx, http.MethodGet, endpoint, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

type DebugPodTemplateService struct {
	client *Client
}

// DebugPodTemplateSummary represents a pod template summary from the API
type DebugPodTemplateSummary struct {
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
	Description string `json:"description,omitempty"`
	Containers  int    `json:"containers"`
}

// DebugPodTemplateListResponse represents the API response for pod template list
type DebugPodTemplateListResponse struct {
	Templates []DebugPodTemplateSummary `json:"templates"`
	Total     int                       `json:"total"`
}

func (c *Client) DebugPodTemplates() *DebugPodTemplateService {
	return &DebugPodTemplateService{client: c}
}

func (d *DebugPodTemplateService) List(ctx context.Context) (*DebugPodTemplateListResponse, error) {
	endpoint := "api/debugSessions/podTemplates"
	var resp DebugPodTemplateListResponse
	if err := d.client.do(ctx, http.MethodGet, endpoint, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (d *DebugPodTemplateService) Get(ctx context.Context, name string) (*v1alpha1.DebugPodTemplate, error) {
	endpoint := fmt.Sprintf("api/debugSessions/podTemplates/%s", url.PathEscape(name))
	var template v1alpha1.DebugPodTemplate
	if err := d.client.do(ctx, http.MethodGet, endpoint, nil, &template); err != nil {
		return nil, err
	}
	return &template, nil
}
