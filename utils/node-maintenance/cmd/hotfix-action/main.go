// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

// hotfix-action is the per-node executor of a Breakglass platform hotfix. It
// reads one controller-rendered request, re-validates it, and plans, applies
// or rolls back exactly one typed payload on the node it runs on. Every step
// that mutates the node is bounded by the session deadline and is never
// started when its budget no longer fits.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"regexp"
	"syscall"
	"time"
)

const (
	stagePlan     = "plan"
	stageApply    = "apply"
	stageRollback = "rollback"

	payloadFile          = "node-file"
	payloadDeb           = "node-deb"
	payloadStaticPod     = "static-pod-image"
	payloadHostContainer = "host-container-image"

	stateDir = "/var/lib/breakglass-hotfix"

	// deadlineMargin is kept free before the session deadline for the result report.
	deadlineMargin = 15 * time.Second
	// maxDiffBytes keeps the review diff inside the 4 KiB termination message.
	maxDiffBytes = 2500
)

type request struct {
	Stage         string         `json:"stage"`
	HotfixID      string         `json:"hotfixID"`
	Payload       payload        `json:"payload"`
	AllowedPaths  []string       `json:"allowedPaths,omitempty"`
	Restartable   []string       `json:"restartableServices,omitempty"`
	HostContainer *hostContainer `json:"hostContainer,omitempty"`
	Expected      *expected      `json:"expected,omitempty"`
	DeadlineUnix  int64          `json:"deadlineUnix"`
}

type payload struct {
	Type         string        `json:"type"`
	File         *filePayload  `json:"file,omitempty"`
	Debs         []deb         `json:"debs,omitempty"`
	RollbackDebs []deb         `json:"rollbackDebs,omitempty"`
	Image        *imagePayload `json:"image,omitempty"`
	Restart      []string      `json:"restart,omitempty"`
}

type filePayload struct {
	Path           string   `json:"path"`
	Mode           string   `json:"mode"`
	BeforeSHA256   []string `json:"beforeSHA256,omitempty"`
	AfterSHA256    string   `json:"afterSHA256,omitempty"`
	Content        string   `json:"content,omitempty"`
	URL            string   `json:"url,omitempty"`
	SedExpressions []string `json:"sedExpressions,omitempty"`
	Diff           string   `json:"diff,omitempty"`
}

type deb struct {
	URL     string `json:"url"`
	SHA256  string `json:"sha256"`
	Package string `json:"package"`
	Version string `json:"version"`
}

type imagePayload struct {
	StaticPod     string `json:"staticPod,omitempty"`
	HostContainer string `json:"hostContainer,omitempty"`
	Image         string `json:"image"`
}

type hostContainer struct {
	Name                string `json:"name"`
	ContainerdNamespace string `json:"containerdNamespace"`
	Unit                string `json:"unit"`
	ImageRefFile        string `json:"imageRefFile"`
}

// expected binds apply and rollback to the reviewed plan of this node.
type expected struct {
	BeforeSHA256 string   `json:"beforeSHA256"`
	AfterSHA256  string   `json:"afterSHA256"`
	NewPackages  []string `json:"newPackages,omitempty"`
}

// result is written to the termination message and the evidence directory.
type result struct {
	Result       string   `json:"result"`
	Action       string   `json:"action,omitempty"`
	BeforeSHA256 string   `json:"beforeSHA256,omitempty"`
	AfterSHA256  string   `json:"afterSHA256,omitempty"`
	Diff         string   `json:"diff,omitempty"`
	NewPackages  []string `json:"newPackages,omitempty"`
	Message      string   `json:"message,omitempty"`
}

var hotfixIDPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

func main() {
	if len(os.Args) > 1 {
		fail(errors.New("hotfix-action takes no arguments; the controller renders BREAKGLASS_HOTFIX_REQUEST"))
	}
	var req request
	if err := json.Unmarshal([]byte(os.Getenv("BREAKGLASS_HOTFIX_REQUEST")), &req); err != nil {
		fail(fmt.Errorf("decode request: %w", err))
	}
	if req.Stage != stagePlan {
		// A mutation must not be cut short by SIGTERM: the controller sets the
		// Pod grace period to the remaining deadline, and every step is
		// bounded by that deadline.
		signal.Ignore(syscall.SIGTERM)
	}
	ex := &executor{
		root:     envOr("BREAKGLASS_HOST_ROOT", "/host"),
		hostExec: os.Getenv("BREAKGLASS_HOST_EXEC") == "nsenter",
		work:     envOr("BREAKGLASS_EVIDENCE_DIR", "/evidence"),
		run:      runCommand,
		now:      time.Now,
		poll:     5 * time.Second,
	}
	out, err := ex.execute(&req)
	if err != nil {
		fail(err)
	}
	report(out)
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func fail(err error) {
	report(&result{Result: "failed", Message: err.Error()})
	os.Exit(1)
}

// maxResultBytes keeps the result inside the 4096-byte termination message.
const maxResultBytes = 3800

func encodeResult(out *result) []byte {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(out)
	return bytes.TrimSpace(buf.Bytes())
}

// fitResult shortens the review diff, then the message, until the encoded
// result fits; JSON escaping can grow both well beyond their raw size.
func fitResult(out *result) []byte {
	if len(out.Message) > 1000 {
		out.Message = out.Message[:1000]
	}
	data := encodeResult(out)
	diff := out.Diff
	for len(data) > maxResultBytes && diff != "" {
		diff = diff[:len(diff)/2]
		out.Diff = diff + "\n[truncated]\n"
		data = encodeResult(out)
	}
	for len(data) > maxResultBytes && out.Message != "" {
		out.Message = out.Message[:len(out.Message)/2]
		data = encodeResult(out)
	}
	return data
}

// report writes the result to the termination message, which the controller
// reads from the Pod status, and to stdout for the evidence log.
func report(out *result) {
	data := fitResult(out)
	_ = os.WriteFile(envOr("BREAKGLASS_TERMINATION_LOG", "/dev/termination-log"), data, 0o600)
	fmt.Println(string(data))
}

func (ex *executor) execute(req *request) (*result, error) {
	if err := validateRequest(req); err != nil {
		return nil, err
	}
	ex.deadline = time.Unix(req.DeadlineUnix, 0).Add(-deadlineMargin)
	if !ex.now().Before(ex.deadline) {
		return nil, errors.New("session deadline has passed; nothing was changed")
	}
	if (req.Payload.Type != payloadFile || len(req.Payload.Restart) != 0) && !ex.hostExec {
		return nil, errors.New("this payload needs the host-namespace executor; nothing was changed")
	}
	switch req.Payload.Type {
	case payloadFile:
		return ex.file(req)
	case payloadDeb:
		return ex.debs(req)
	case payloadStaticPod:
		return ex.staticPod(req)
	case payloadHostContainer:
		return ex.hostContainer(req)
	}
	return nil, fmt.Errorf("unsupported payload type %q", req.Payload.Type)
}
