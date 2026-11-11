// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package helpers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// TerminalStreamResult is the client-visible outcome of one recorded stream.
type TerminalStreamResult struct {
	StatusCode  int
	Output      string
	RecordingID string
	SHA256      string
	Status      string
	Body        string
	// Aborted is set when the server cut the stream before its trailers,
	// for example after revocation or a credential rotation.
	Aborted bool
}

// TerminalRecordingListing is one entry of GET /api/debugSessions/:name/terminal.
type TerminalRecordingListing struct {
	ArtifactID string `json:"artifactID"`
	State      string `json:"state"`
	SHA256     string `json:"sha256"`
	Recording  *struct {
		Complete bool   `json:"complete"`
		PodName  string `json:"podName"`
		Frames   int64  `json:"frames"`
	} `json:"recording"`
}

// TerminalStreamRequest selects the target of a recorded controller exec.
type TerminalStreamRequest struct {
	Session, SessionNamespace, PodNamespace, PodName, Container string
	Command                                                     []string
	// Interact receives the live output channel and the stdin writer. It
	// returns once it has finished typing; stdin is closed afterwards.
	Interact func(output <-chan string, stdin io.Writer) error
	// CorrelationID, when set, is sent as X-Correlation-ID so the stream's
	// audit events can be matched.
	CorrelationID string
}

// StreamRecordedTerminal runs one full-duplex recorded exec through the
// controller endpoint POST /api/debugSessions/:name/terminal.
func (c *APIClient) StreamRecordedTerminal(ctx context.Context, request TerminalStreamRequest) (TerminalStreamResult, error) {
	query := url.Values{"namespace": {request.SessionNamespace}, "podNamespace": {request.PodNamespace}, "podName": {request.PodName}, "operation": {"exec"}, "command": request.Command}
	if request.Container != "" {
		query.Set("container", request.Container)
	}
	stdin, stdinWriter := io.Pipe()
	defer func() { _ = stdinWriter.Close() }()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/api/debugSessions/"+url.PathEscape(request.Session)+"/terminal?"+query.Encode(), stdin)
	if err != nil {
		return TerminalStreamResult{}, err
	}
	req.Header.Set("Authorization", "Bearer "+c.AuthToken)
	req.Header.Set("Content-Type", "application/octet-stream")
	if request.CorrelationID != "" {
		req.Header.Set(CorrelationIDHeader, request.CorrelationID)
	}
	output := make(chan string, 64)
	// Every exit ends the output stream so interaction callbacks never hang.
	var closeOutput sync.Once
	defer closeOutput.Do(func() { close(output) })
	interactErr := make(chan error, 1)
	go func() {
		var err error
		if request.Interact != nil {
			err = request.Interact(output, stdinWriter)
		}
		// Typing is done: end stdin so input-consuming commands can finish.
		_ = stdinWriter.Close()
		interactErr <- err
	}()
	// No client timeout: the stream lasts as long as the remote command.
	// Do returns once the server flushes the first output; input is typed concurrently.
	resp, err := (&http.Client{Transport: c.HTTPClient.Transport}).Do(req)
	if err != nil {
		return TerminalStreamResult{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	result := TerminalStreamResult{StatusCode: resp.StatusCode}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		result.Body = string(body)
		return result, nil
	}
	var all strings.Builder
	buf := make([]byte, 4096)
	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			chunk := string(buf[:n])
			all.WriteString(chunk)
			select {
			case output <- chunk:
			default:
			}
		}
		if readErr != nil {
			result.Aborted = readErr != io.EOF
			break
		}
	}
	closeOutput.Do(func() { close(output) })
	select {
	case err := <-interactErr:
		if err != nil {
			return result, err
		}
	case <-time.After(10 * time.Second):
	}
	result.Output = all.String()
	result.RecordingID = resp.Trailer.Get("X-Breakglass-Recording-ID")
	result.SHA256 = resp.Trailer.Get("X-Breakglass-Recording-SHA256")
	result.Status = resp.Trailer.Get("X-Breakglass-Recording-Status")
	return result, nil
}

// GetRaw performs an authenticated GET and returns status and body.
func (c *APIClient) GetRaw(ctx context.Context, path string) (int, []byte, error) {
	return c.GetRawWithCID(ctx, path, "")
}

// GetRawWithCID is GetRaw with an explicit correlation ID.
func (c *APIClient) GetRawWithCID(ctx context.Context, path, cid string) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+path, nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.AuthToken)
	if cid != "" {
		req.Header.Set(CorrelationIDHeader, cid)
	}
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	return resp.StatusCode, body, err
}

// ReceivedAuditEvent is one event stored by the e2e audit webhook receiver.
type ReceivedAuditEvent struct {
	Type           string                `json:"type"`
	Details        map[string]any        `json:"details"`
	Actor          struct{ User string } `json:"actor"`
	RequestContext *struct {
		CorrelationID string `json:"correlationId"`
	} `json:"requestContext"`
}

// AuditEventsByCorrelation returns the events the e2e audit webhook receiver
// stored for one correlation ID.
func AuditEventsByCorrelation(ctx context.Context, cid string) ([]ReceivedAuditEvent, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, GetAuditWebhookReceiverExternalURL()+"/events", nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("audit receiver returned %d", resp.StatusCode)
	}
	var payload struct {
		Events []ReceivedAuditEvent `json:"events"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, err
	}
	var matched []ReceivedAuditEvent
	for _, event := range payload.Events {
		if event.RequestContext != nil && event.RequestContext.CorrelationID == cid {
			matched = append(matched, event)
		}
	}
	return matched, nil
}
