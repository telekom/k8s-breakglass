// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package helpers

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// TerminalRecordingFrame is one decoded frame of a terminal-recording.v1 artifact.
type TerminalRecordingFrame struct {
	Direction byte
	Payload   []byte
}

// ParseTerminalRecording decodes a recording and verifies its SHA-256 hash chain.
func ParseTerminalRecording(data []byte) ([]TerminalRecordingFrame, error) {
	const header = 1 + 1 + 8 + sha256.Size
	var frames []TerminalRecordingFrame
	var previous [sha256.Size]byte
	for offset := 0; offset < len(data); {
		if len(data)-offset < header {
			return nil, fmt.Errorf("truncated frame header at %d", offset)
		}
		if data[offset] != 1 {
			return nil, fmt.Errorf("unsupported frame version %d at %d", data[offset], offset)
		}
		length := binary.BigEndian.Uint64(data[offset+2 : offset+10])
		if length > uint64(len(data)-offset-header) {
			return nil, fmt.Errorf("truncated frame payload at %d", offset)
		}
		if !bytes.Equal(data[offset+10:offset+header], previous[:]) {
			return nil, fmt.Errorf("hash chain broken at frame %d", len(frames))
		}
		end := offset + header + int(length)
		previous = sha256.Sum256(data[offset:end])
		frames = append(frames, TerminalRecordingFrame{Direction: data[offset+1], Payload: data[offset+header : end]})
		offset = end
	}
	return frames, nil
}

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
	// No client timeout: the stream lasts as long as the remote command.
	responseCh := make(chan *http.Response, 1)
	errCh := make(chan error, 1)
	go func() {
		resp, doErr := (&http.Client{Transport: c.HTTPClient.Transport}).Do(req)
		if doErr != nil {
			errCh <- doErr
			return
		}
		responseCh <- resp
	}()
	output := make(chan string, 64)
	interactErr := make(chan error, 1)
	go func() {
		var err error
		if request.Interact != nil {
			err = request.Interact(output, stdinWriter)
		}
		interactErr <- err
	}()
	var resp *http.Response
	select {
	case resp = <-responseCh:
	case err := <-errCh:
		return TerminalStreamResult{}, err
	case <-ctx.Done():
		return TerminalStreamResult{}, ctx.Err()
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
	close(output)
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+path, nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.AuthToken)
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	return resp.StatusCode, body, err
}
