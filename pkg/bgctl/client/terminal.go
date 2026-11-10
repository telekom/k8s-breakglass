// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Wire contract of the controller terminal endpoint (framed.v1). It mirrors
// pkg/breakglass/debug/terminal_protocol.go without importing server code.
const (
	terminalProtocolHeader = "X-Breakglass-Terminal-Protocol"
	terminalProtocolFramed = "framed.v1"
	terminalFrameStdin     = byte(0)
	terminalFrameResize    = byte(1)
	maxTerminalInputFrame  = 64 << 10
)

// TerminalSize is a client terminal size in cells.
type TerminalSize struct {
	Width  uint16 `json:"width"`
	Height uint16 `json:"height"`
}

// TerminalRequest describes one recorded exec through the controller.
type TerminalRequest struct {
	Session, Namespace    string
	PodNamespace, PodName string
	Container             string
	Command               []string
	Stdin                 io.Reader
	Stdout                io.Writer
	// Resize delivers terminal sizes; the initial size should be sent first.
	Resize <-chan TerminalSize
}

// TerminalResult reports the recording published for the stream.
type TerminalResult struct {
	RecordingID string
	SHA256      string
	// Status is completed, incomplete or finalization-pending; empty when the
	// server ended the stream before publishing trailers (revocation, expiry).
	Status string
}

// Terminal runs a recorded interactive exec through
// POST /api/debugSessions/:name/terminal using the framed protocol.
func (c *Client) Terminal(ctx context.Context, request TerminalRequest) (TerminalResult, error) {
	query := url.Values{"podNamespace": {request.PodNamespace}, "podName": {request.PodName}, "operation": {"exec"}, "command": request.Command}
	if request.Namespace != "" {
		query.Set("namespace", request.Namespace)
	}
	if request.Container != "" {
		query.Set("container", request.Container)
	}
	endpoint := *c.baseURL
	endpoint.Path = path.Join(endpoint.Path, "api/debugSessions", url.PathEscape(request.Session), "terminal")
	endpoint.RawQuery = query.Encode()
	body, bodyWriter := io.Pipe()
	streamCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	req, err := http.NewRequestWithContext(streamCtx, http.MethodPost, endpoint.String(), body)
	if err != nil {
		return TerminalResult{}, err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set(terminalProtocolHeader, terminalProtocolFramed)
	req.Header.Set(CorrelationIDHeader, uuid.NewString())
	if c.userAgent != "" {
		req.Header.Set("User-Agent", c.userAgent)
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	var writeMu sync.Mutex
	writeFrame := func(frameType byte, payload []byte) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		return writeTerminalFrame(bodyWriter, frameType, payload)
	}
	sendSize := func(size TerminalSize) error {
		payload, _ := json.Marshal(size)
		return writeFrame(terminalFrameResize, payload)
	}
	// Sizes queued before the stream (the initial size) precede any input.
	var initial []TerminalSize
	for queued := true; queued && request.Resize != nil; {
		select {
		case size, ok := <-request.Resize:
			if !ok {
				queued = false
				break
			}
			initial = append(initial, size)
		default:
			queued = false
		}
	}
	go func() {
		for _, size := range initial {
			if sendSize(size) != nil {
				return
			}
		}
		go func() {
			if request.Stdin == nil {
				// Without stdin the remote command gets EOF immediately.
				_ = bodyWriter.Close()
				return
			}
			buf := make([]byte, 32<<10)
			for {
				n, readErr := request.Stdin.Read(buf)
				if n > 0 && writeFrame(terminalFrameStdin, buf[:n]) != nil {
					return
				}
				if readErr != nil {
					// Ending stdin ends the request body and therefore the remote stdin.
					_ = bodyWriter.Close()
					return
				}
			}
		}()
		for {
			select {
			case size, ok := <-request.Resize:
				if !ok {
					return
				}
				if sendSize(size) != nil {
					return
				}
			case <-streamCtx.Done():
				return
			}
		}
	}()
	defer func() { _ = bodyWriter.Close() }()

	// The stream lasts as long as the remote command: no client timeout.
	resp, err := (&http.Client{Transport: c.http.Transport}).Do(req)
	if err != nil {
		return TerminalResult{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 400 {
		return TerminalResult{}, decodeError(resp, req.Header.Get(CorrelationIDHeader))
	}
	stdout := request.Stdout
	if stdout == nil {
		stdout = io.Discard
	}
	if _, err := io.Copy(stdout, resp.Body); err != nil {
		return TerminalResult{}, fmt.Errorf("terminal stream ended without a published recording: %w", err)
	}
	return TerminalResult{
		RecordingID: resp.Trailer.Get("X-Breakglass-Recording-ID"),
		SHA256:      resp.Trailer.Get("X-Breakglass-Recording-SHA256"),
		Status:      resp.Trailer.Get("X-Breakglass-Recording-Status"),
	}, nil
}

func writeTerminalFrame(w io.Writer, frameType byte, payload []byte) error {
	for len(payload) > maxTerminalInputFrame {
		if err := writeTerminalFrame(w, frameType, payload[:maxTerminalInputFrame]); err != nil {
			return err
		}
		payload = payload[maxTerminalInputFrame:]
	}
	frame := make([]byte, 5+len(payload))
	frame[0] = frameType
	binary.BigEndian.PutUint32(frame[1:5], uint32(len(payload))) // #nosec G115 -- bounded by maxTerminalInputFrame
	copy(frame[5:], payload)
	_, err := w.Write(frame)
	return err
}

// RecordingMetadata mirrors the recording fields of a listing entry.
type RecordingMetadata struct {
	FormatVersion int32     `json:"formatVersion,omitempty"`
	StartedAt     time.Time `json:"startedAt,omitempty"`
	FinishedAt    time.Time `json:"finishedAt,omitempty"`
	Complete      bool      `json:"complete,omitempty"`
	Frames        int64     `json:"frames,omitempty"`
	PodNamespace  string    `json:"podNamespace,omitempty"`
	PodName       string    `json:"podName,omitempty"`
	ContainerName string    `json:"containerName,omitempty"`
	Operation     string    `json:"operation,omitempty"`
}

// RecordingInfo is one entry of GET /api/debugSessions/:name/terminal.
type RecordingInfo struct {
	ArtifactID string             `json:"artifactID"`
	State      string             `json:"state"`
	Size       int64              `json:"size,omitempty"`
	SHA256     string             `json:"sha256,omitempty"`
	ExpiresAt  time.Time          `json:"expiresAt"`
	Recording  *RecordingMetadata `json:"recording,omitempty"`
}

// Recordings lists the retained terminal recordings of a debug session.
func (s *DebugSessionService) Recordings(ctx context.Context, name, namespace string) ([]RecordingInfo, error) {
	endpoint := fmt.Sprintf("api/debugSessions/%s/terminal", url.PathEscape(name))
	if namespace != "" {
		endpoint += "?namespace=" + url.QueryEscape(namespace)
	}
	var resp []RecordingInfo
	if err := s.client.do(ctx, http.MethodGet, endpoint, nil, &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// DownloadRecording streams one recording to w and returns the digest the
// server published for it. The body is not size-capped like JSON responses.
func (s *DebugSessionService) DownloadRecording(ctx context.Context, name, namespace, id string, w io.Writer) (string, error) {
	c := s.client
	endpoint := *c.baseURL
	endpoint.Path = path.Join(endpoint.Path, "api/debugSessions", url.PathEscape(name), "terminal", url.PathEscape(id))
	if namespace != "" {
		endpoint.RawQuery = "namespace=" + url.QueryEscape(namespace)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return "", err
	}
	correlationID := uuid.NewString()
	req.Header.Set(CorrelationIDHeader, correlationID)
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	// Large recordings outlive the default request timeout; ctx bounds the download.
	resp, err := (&http.Client{Transport: c.http.Transport}).Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 400 {
		return "", decodeError(resp, correlationID)
	}
	if _, err := io.Copy(w, resp.Body); err != nil {
		return "", fmt.Errorf("download recording: %w", err)
	}
	digest := resp.Header.Get("X-Breakglass-Recording-SHA256")
	if digest == "" {
		return "", errors.New("server did not publish a recording digest")
	}
	return digest, nil
}
