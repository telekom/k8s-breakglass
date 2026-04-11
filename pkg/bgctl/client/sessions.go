package client

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
)

type SessionService struct {
	client *Client
}

func (c *Client) Sessions() *SessionService {
	return &SessionService{client: c}
}

type SessionListOptions struct {
	Cluster      string
	User         string
	Group        string
	Mine         bool
	Approver     bool
	ApprovedByMe bool
	ActiveOnly   bool
	State        []string
}

type SessionRequest struct {
	Cluster          string `json:"cluster"`
	User             string `json:"user"`
	Group            string `json:"group"`
	Reason           string `json:"reason,omitempty"`
	DurationSeconds  int64  `json:"duration,omitempty"`
	ScheduledStartAt string `json:"scheduledStartTime,omitempty"`
}

type SessionActionRequest struct {
	Reason string `json:"reason,omitempty"`
}

func (s *SessionService) List(ctx context.Context, opts SessionListOptions) ([]breakglassv1alpha1.BreakglassSession, error) {
	baseParams := url.Values{}
	if opts.Cluster != "" {
		baseParams.Set("cluster", opts.Cluster)
	}
	if opts.User != "" {
		baseParams.Set("user", opts.User)
	}
	if opts.Group != "" {
		baseParams.Set("group", opts.Group)
	}
	if opts.Mine {
		baseParams.Set("mine", "true")
	}
	if opts.Approver {
		baseParams.Set("approver", "true")
	}
	if opts.ApprovedByMe {
		baseParams.Set("approvedByMe", "true")
	}
	if opts.ActiveOnly {
		baseParams.Set("activeOnly", "true")
	}
	if len(opts.State) > 0 {
		baseParams.Set("state", strings.Join(opts.State, ","))
	}

	var all []breakglassv1alpha1.BreakglassSession
	continueToken := ""
	for {
		params := url.Values{}
		for k, v := range baseParams {
			params[k] = v
		}
		if continueToken != "" {
			params.Set("continue", continueToken)
		}
		endpoint := "api/breakglassSessions"
		if encoded := params.Encode(); encoded != "" {
			endpoint = fmt.Sprintf("%s?%s", endpoint, encoded)
		}
		var envelope struct {
			Items    []breakglassv1alpha1.BreakglassSession `json:"items"`
			Metadata struct {
				Continue string `json:"continue"`
			} `json:"metadata"`
		}
		if err := s.client.do(ctx, http.MethodGet, endpoint, nil, &envelope); err != nil {
			return nil, err
		}
		all = append(all, envelope.Items...)
		if envelope.Metadata.Continue == "" {
			break
		}
		continueToken = envelope.Metadata.Continue
	}
	return all, nil
}

// SessionGetResponse wraps the session with authorization metadata
type SessionGetResponse struct {
	Session      breakglassv1alpha1.BreakglassSession `json:"session"`
	ApprovalMeta map[string]interface{}               `json:"approvalMeta,omitempty"`
}

func (s *SessionService) Get(ctx context.Context, name string) (*breakglassv1alpha1.BreakglassSession, error) {
	endpoint := fmt.Sprintf("api/breakglassSessions/%s", url.PathEscape(name))
	var resp SessionGetResponse
	if err := s.client.do(ctx, http.MethodGet, endpoint, nil, &resp); err != nil {
		return nil, err
	}
	return &resp.Session, nil
}

func (s *SessionService) Request(ctx context.Context, req SessionRequest) (*breakglassv1alpha1.BreakglassSession, error) {
	endpoint := "api/breakglassSessions"
	var session breakglassv1alpha1.BreakglassSession
	if err := s.client.do(ctx, http.MethodPost, endpoint, req, &session); err != nil {
		return nil, err
	}
	return &session, nil
}

func (s *SessionService) Approve(ctx context.Context, name, reason string) (*breakglassv1alpha1.BreakglassSession, error) {
	return s.action(ctx, name, "approve", reason)
}

func (s *SessionService) Reject(ctx context.Context, name, reason string) (*breakglassv1alpha1.BreakglassSession, error) {
	return s.action(ctx, name, "reject", reason)
}

func (s *SessionService) Withdraw(ctx context.Context, name string) (*breakglassv1alpha1.BreakglassSession, error) {
	return s.action(ctx, name, "withdraw", "")
}

func (s *SessionService) Drop(ctx context.Context, name string) (*breakglassv1alpha1.BreakglassSession, error) {
	return s.action(ctx, name, "drop", "")
}

func (s *SessionService) Cancel(ctx context.Context, name string) (*breakglassv1alpha1.BreakglassSession, error) {
	return s.action(ctx, name, "cancel", "")
}

func (s *SessionService) action(ctx context.Context, name, action, reason string) (*breakglassv1alpha1.BreakglassSession, error) {
	endpoint := fmt.Sprintf("api/breakglassSessions/%s/%s", url.PathEscape(name), action)
	var session breakglassv1alpha1.BreakglassSession
	var payload *SessionActionRequest
	if reason != "" {
		payload = &SessionActionRequest{Reason: reason}
	}
	if err := s.client.do(ctx, http.MethodPost, endpoint, payload, &session); err != nil {
		return nil, err
	}
	return &session, nil
}
