package client

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/telekom/k8s-breakglass/api/v1alpha1"
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

func (s *SessionService) List(ctx context.Context, opts SessionListOptions) ([]v1alpha1.BreakglassSession, error) {
	endpoint := "api/breakglassSessions"
	params := url.Values{}
	if opts.Cluster != "" {
		params.Set("cluster", opts.Cluster)
	}
	if opts.User != "" {
		params.Set("user", opts.User)
	}
	if opts.Group != "" {
		params.Set("group", opts.Group)
	}
	if opts.Mine {
		params.Set("mine", "true")
	}
	if opts.Approver {
		params.Set("approver", "true")
	}
	if opts.ApprovedByMe {
		params.Set("approvedByMe", "true")
	}
	if opts.ActiveOnly {
		params.Set("activeOnly", "true")
	}
	if len(opts.State) > 0 {
		params.Set("state", strings.Join(opts.State, ","))
	}
	if encoded := params.Encode(); encoded != "" {
		endpoint = fmt.Sprintf("%s?%s", endpoint, encoded)
	}
	var sessions []v1alpha1.BreakglassSession
	if err := s.client.do(ctx, http.MethodGet, endpoint, nil, &sessions); err != nil {
		return nil, err
	}
	return sessions, nil
}

func (s *SessionService) Get(ctx context.Context, name string) (*v1alpha1.BreakglassSession, error) {
	endpoint := fmt.Sprintf("api/breakglassSessions/%s", url.PathEscape(name))
	var session v1alpha1.BreakglassSession
	if err := s.client.do(ctx, http.MethodGet, endpoint, nil, &session); err != nil {
		return nil, err
	}
	return &session, nil
}

func (s *SessionService) Request(ctx context.Context, req SessionRequest) (*v1alpha1.BreakglassSession, error) {
	endpoint := "api/breakglassSessions"
	var session v1alpha1.BreakglassSession
	if err := s.client.do(ctx, http.MethodPost, endpoint, req, &session); err != nil {
		return nil, err
	}
	return &session, nil
}

func (s *SessionService) Approve(ctx context.Context, name, reason string) (*v1alpha1.BreakglassSession, error) {
	return s.action(ctx, name, "approve", reason)
}

func (s *SessionService) Reject(ctx context.Context, name, reason string) (*v1alpha1.BreakglassSession, error) {
	return s.action(ctx, name, "reject", reason)
}

func (s *SessionService) Withdraw(ctx context.Context, name string) (*v1alpha1.BreakglassSession, error) {
	return s.action(ctx, name, "withdraw", "")
}

func (s *SessionService) Drop(ctx context.Context, name string) (*v1alpha1.BreakglassSession, error) {
	return s.action(ctx, name, "drop", "")
}

func (s *SessionService) Cancel(ctx context.Context, name string) (*v1alpha1.BreakglassSession, error) {
	return s.action(ctx, name, "cancel", "")
}

func (s *SessionService) action(ctx context.Context, name, action, reason string) (*v1alpha1.BreakglassSession, error) {
	endpoint := fmt.Sprintf("api/breakglassSessions/%s/%s", url.PathEscape(name), action)
	var session v1alpha1.BreakglassSession
	var payload *SessionActionRequest
	if reason != "" {
		payload = &SessionActionRequest{Reason: reason}
	}
	if err := s.client.do(ctx, http.MethodPost, endpoint, payload, &session); err != nil {
		return nil, err
	}
	return &session, nil
}
