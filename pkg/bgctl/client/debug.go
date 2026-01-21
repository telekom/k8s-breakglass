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
	TemplateRef         string            `json:"templateRef"`
	Cluster             string            `json:"cluster"`
	RequestedDuration   string            `json:"requestedDuration,omitempty"`
	NodeSelector        map[string]string `json:"nodeSelector,omitempty"`
	Namespace           string            `json:"namespace,omitempty"`
	Reason              string            `json:"reason,omitempty"`
	InvitedParticipants []string          `json:"invitedParticipants,omitempty"`
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
	Name             string                            `json:"name"`
	DisplayName      string                            `json:"displayName"`
	Description      string                            `json:"description,omitempty"`
	Mode             v1alpha1.DebugSessionTemplateMode `json:"mode"`
	WorkloadType     v1alpha1.DebugWorkloadType        `json:"workloadType,omitempty"`
	PodTemplateRef   string                            `json:"podTemplateRef,omitempty"`
	TargetNamespace  string                            `json:"targetNamespace,omitempty"`
	Constraints      *v1alpha1.DebugSessionConstraints `json:"constraints,omitempty"`
	AllowedClusters  []string                          `json:"allowedClusters,omitempty"`
	AllowedGroups    []string                          `json:"allowedGroups,omitempty"`
	RequiresApproval bool                              `json:"requiresApproval"`
}

// DebugTemplateListResponse represents the API response for template list
type DebugTemplateListResponse struct {
	Templates []DebugSessionTemplateSummary `json:"templates"`
	Total     int                           `json:"total"`
}

func (c *Client) DebugTemplates() *DebugTemplateService {
	return &DebugTemplateService{client: c}
}

func (d *DebugTemplateService) List(ctx context.Context) (*DebugTemplateListResponse, error) {
	endpoint := "api/debugSessions/templates"
	var resp DebugTemplateListResponse
	if err := d.client.do(ctx, http.MethodGet, endpoint, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (d *DebugTemplateService) Get(ctx context.Context, name string) (*v1alpha1.DebugSessionTemplate, error) {
	endpoint := fmt.Sprintf("api/debugSessions/templates/%s", url.PathEscape(name))
	var template v1alpha1.DebugSessionTemplate
	if err := d.client.do(ctx, http.MethodGet, endpoint, nil, &template); err != nil {
		return nil, err
	}
	return &template, nil
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
