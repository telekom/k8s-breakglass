// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	_ "embed"
	"errors"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strings"
)

// deniedPrefixes is the hard path denylist. It must equal the API denylist
// (api/v1alpha1 hotfixDeniedPrefixes); a test in the API package compares them.
//
//go:embed denylist.txt
var denylistText string

var (
	sha256Pattern  = regexp.MustCompile(`^[a-f0-9]{64}$`)
	packagePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]{1,62}$`)
	versionPattern = regexp.MustCompile(`^[0-9A-Za-z.+~:-]{1,128}$`)
	imagePattern   = regexp.MustCompile(`^((localhost|[a-z0-9-]+(\.[a-z0-9-]+)+)(:[0-9]{1,5})?|[a-z0-9-]+:[0-9]{1,5})(/[a-z0-9]([a-z0-9._-]*[a-z0-9])?)+@sha256:[a-f0-9]{64}$`)
	pathPattern    = regexp.MustCompile(`^/[A-Za-z0-9._@+/-]*$`)
	unitPattern    = regexp.MustCompile(`^[a-zA-Z0-9@_.-]{1,240}\.service$`)
	labelPattern   = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	nsPattern      = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$`)
	sedFlags       = regexp.MustCompile(`^[gI0-9]*$`)
)

var staticPods = []string{"kube-apiserver", "kube-controller-manager", "kube-scheduler", "etcd"}
var services = []string{"containerd.service", "kubelet.service", "ssh.service", "chrony.service", "systemd-networkd.service"}

var deniedPrefixes = func() []string {
	var prefixes []string
	for _, line := range strings.Split(denylistText, "\n") {
		if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
			prefixes = append(prefixes, line)
		}
	}
	return prefixes
}()

func pathDenied(p string) bool {
	for _, prefix := range deniedPrefixes {
		if strings.HasPrefix(p, prefix) || p+"/" == prefix {
			return true
		}
	}
	base := path.Base(p)
	return (path.Dir(p) == "/etc/kubernetes" && strings.HasSuffix(base, ".conf")) || p == "/var/lib/kubelet/kubeconfig" ||
		(path.Dir(p) == "/etc/ssh" && strings.Contains(base, "_key")) || strings.Contains(p, "/.ssh/")
}

func validatePath(p string) error {
	if len(p) < 2 || len(p) > 4096 || !pathPattern.MatchString(p) || path.Clean(p) != p {
		return fmt.Errorf("path %q must be absolute and clean", p)
	}
	if pathDenied(p) {
		return fmt.Errorf("path %q is on the hotfix denylist", p)
	}
	return nil
}

func pathAllowed(allowed []string, p string) bool {
	for _, entry := range allowed {
		if entry == p || (strings.HasSuffix(entry, "/") && strings.HasPrefix(p, entry)) {
			return true
		}
	}
	return false
}

func validateURL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || len(raw) > 2048 || strings.ContainsAny(raw, " \t\r\n") || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" || parsed.RawQuery != "" || parsed.ForceQuery {
		return fmt.Errorf("url %q must be https without credentials, query or fragment", raw)
	}
	return nil
}

func validateDebs(debs []deb) error {
	for _, d := range debs {
		if err := validateURL(d.URL); err != nil {
			return err
		}
		if !sha256Pattern.MatchString(d.SHA256) || !packagePattern.MatchString(d.Package) || !versionPattern.MatchString(d.Version) {
			return fmt.Errorf("deb %q needs a sha256, package and version", d.URL)
		}
	}
	return nil
}

// validateRequest repeats the API validation that matters on the node, so a
// tampered Pod spec cannot widen what the executor does.
func validateRequest(req *request) error {
	if !slices.Contains([]string{stagePlan, stageApply, stageRollback}, req.Stage) || !hotfixIDPattern.MatchString(req.HotfixID) {
		return errors.New("request needs a stage of plan, apply or rollback and a DNS-label hotfixID")
	}
	if req.Stage != stagePlan && (req.Expected == nil || !sha256Pattern.MatchString(req.Expected.BeforeSHA256) ||
		!sha256Pattern.MatchString(req.Expected.AfterSHA256)) {
		return errors.New("apply and rollback need the planned before and after hashes")
	}
	for _, unit := range req.Payload.Restart {
		if !slices.Contains(services, unit) || !slices.Contains(req.Restartable, unit) {
			return fmt.Errorf("service %q is not restartable", unit)
		}
	}
	p := req.Payload
	switch p.Type {
	case payloadFile:
		f := p.File
		if f == nil || p.Image != nil || len(p.Debs)+len(p.RollbackDebs) != 0 {
			return errors.New("node-file needs a file only")
		}
		if err := validatePath(f.Path); err != nil {
			return err
		}
		if !pathAllowed(req.AllowedPaths, f.Path) {
			return fmt.Errorf("path %q is not allowed", f.Path)
		}
		for _, sum := range f.BeforeSHA256 {
			if !sha256Pattern.MatchString(sum) {
				return errors.New("invalid beforeSHA256")
			}
		}
		switch f.Mode {
		case "replace":
			if !sha256Pattern.MatchString(f.AfterSHA256) || len(f.BeforeSHA256) == 0 || (f.Content == "") == (f.URL == "") {
				return errors.New("replace needs content or url, beforeSHA256 and afterSHA256")
			}
			if f.URL != "" {
				return validateURL(f.URL)
			}
		case "sed":
			if len(f.SedExpressions) == 0 {
				return errors.New("sed needs expressions")
			}
			for _, expression := range f.SedExpressions {
				if err := validateSed(expression); err != nil {
					return err
				}
			}
		case "diff":
			if f.Diff == "" {
				return errors.New("diff needs a diff")
			}
		default:
			return fmt.Errorf("unsupported file mode %q", f.Mode)
		}
	case payloadDeb:
		if len(p.Debs) == 0 || p.File != nil || p.Image != nil {
			return errors.New("node-deb needs debs only")
		}
		if err := validateDebs(append(slices.Clone(p.Debs), p.RollbackDebs...)); err != nil {
			return err
		}
		for _, name := range expectedPackages(req) {
			if !packagePattern.MatchString(name) {
				return fmt.Errorf("invalid new package %q", name)
			}
		}
	case payloadStaticPod:
		if p.Image == nil || !slices.Contains(staticPods, p.Image.StaticPod) || !imagePattern.MatchString(p.Image.Image) ||
			p.File != nil || len(p.Debs) != 0 || len(p.Restart) != 0 {
			return errors.New("static-pod-image needs a known static Pod and a digest-pinned image")
		}
	case payloadHostContainer:
		c := req.HostContainer
		if p.Image == nil || c == nil || p.Image.HostContainer != c.Name || !imagePattern.MatchString(p.Image.Image) ||
			!labelPattern.MatchString(c.Name) || !nsPattern.MatchString(c.ContainerdNamespace) ||
			c.ContainerdNamespace == "k8s.io" || c.ContainerdNamespace == "moby" ||
			!unitPattern.MatchString(c.Unit) || p.File != nil || len(p.Debs) != 0 || len(p.Restart) != 0 {
			return errors.New("host-container-image needs the profile host container and a digest-pinned image")
		}
		if err := validatePath(c.ImageRefFile); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported payload type %q", p.Type)
	}
	return nil
}

func expectedPackages(req *request) []string {
	if req.Expected == nil {
		return nil
	}
	return req.Expected.NewPackages
}

// validateSed accepts one s command with the flags g, I and a number, like
// the API. GNU sed --sandbox additionally rejects e, r and w at run time.
func validateSed(expression string) error {
	if len(expression) < 4 || len(expression) > 1024 || expression[0] != 's' || strings.ContainsAny(expression, "\n\r\x00") {
		return fmt.Errorf("sed expression %q must be a single-line s command", expression)
	}
	delimiter := expression[1]
	if delimiter == '\\' || delimiter == ' ' || (delimiter >= 'a' && delimiter <= 'z') ||
		(delimiter >= 'A' && delimiter <= 'Z') || (delimiter >= '0' && delimiter <= '9') {
		return fmt.Errorf("sed expression %q has an invalid delimiter", expression)
	}
	parts, escaped, rest := 0, false, 2
	for i := 2; i < len(expression) && parts < 2; i++ {
		switch {
		case escaped:
			escaped = false
		case expression[i] == '\\':
			escaped = true
		case expression[i] == delimiter:
			parts++
			rest = i + 1
		}
	}
	if parts != 2 || !sedFlags.MatchString(expression[rest:]) {
		return fmt.Errorf("sed expression %q must be s<d>regex<d>replacement<d>[gI0-9]", expression)
	}
	return nil
}
