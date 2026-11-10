// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/spf13/cobra"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/bgctl/client"
	"github.com/telekom/k8s-breakglass/pkg/bgctl/internal/terminal"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/yaml"
)

// defaultNonRootUID is the user the injected container runs as when the
// template requires non-root and the caller sets no --run-as-user. Most debug
// images (busybox, alpine, netshoot) default to root, which runAsNonRoot alone
// makes the kubelet refuse; 65534 ("nobody") exists in all of them.
const defaultNonRootUID int64 = 65534

// ephemeralSecurityContextOptions holds the security-context flags of
// `bgctl debug kubectl inject`.
type ephemeralSecurityContextOptions struct {
	file                     string
	defaults                 bool
	runAsNonRoot             bool
	runAsUser                int64
	runAsGroup               int64
	allowPrivilegeEscalation bool
	addCapabilities          []string
	dropCapabilities         []string
}

var ephemeralSecurityContextFieldFlags = []string{
	"run-as-non-root", "run-as-user", "run-as-group", "allow-privilege-escalation",
	"add-capabilities", "drop-capabilities",
}

func (o *ephemeralSecurityContextOptions) addFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.BoolVar(&o.defaults, "default-security-context", true,
		"Send a security context that satisfies the session template: allowPrivilegeEscalation=false, plus "+
			"runAsNonRoot=true, runAsUser=65534, drop ALL capabilities and seccomp RuntimeDefault when the template "+
			"requires non-root. Set to false to send only the fields given by flags")
	f.BoolVar(&o.runAsNonRoot, "run-as-non-root", false, "Set securityContext.runAsNonRoot")
	f.Int64Var(&o.runAsUser, "run-as-user", 0, "Set securityContext.runAsUser")
	f.Int64Var(&o.runAsGroup, "run-as-group", 0, "Set securityContext.runAsGroup")
	f.BoolVar(&o.allowPrivilegeEscalation, "allow-privilege-escalation", false,
		"Set securityContext.allowPrivilegeEscalation (sent as false by default)")
	f.StringSliceVar(&o.addCapabilities, "add-capabilities", nil,
		"Linux capabilities to add (must be within the template's maxCapabilities)")
	f.StringSliceVar(&o.dropCapabilities, "drop-capabilities", nil,
		"Linux capabilities to drop (replaces the default drop list)")
	f.StringVar(&o.file, "security-context-file", "",
		"Read the container securityContext from a YAML or JSON file; sent verbatim, without defaults")
	for _, name := range append([]string{"default-security-context"}, ephemeralSecurityContextFieldFlags...) {
		cmd.MarkFlagsMutuallyExclusive("security-context-file", name)
	}
}

// build returns the security context to send. policy is the session's resolved
// ephemeral-container policy; nil means unknown and only the base default
// (allowPrivilegeEscalation=false) is applied.
func (o *ephemeralSecurityContextOptions) build(cmd *cobra.Command, policy *breakglassv1alpha1.EphemeralContainersConfig) (*corev1.SecurityContext, error) {
	if o.file != "" {
		data, err := os.ReadFile(o.file)
		if err != nil {
			return nil, fmt.Errorf("read --security-context-file: %w", err)
		}
		sc := &corev1.SecurityContext{}
		if err := yaml.UnmarshalStrict(data, sc); err != nil {
			return nil, fmt.Errorf("parse --security-context-file %s: %w", o.file, err)
		}
		return sc, nil
	}

	sc := &corev1.SecurityContext{}
	if o.defaults {
		sc.AllowPrivilegeEscalation = ptr.To(false)
		if policy != nil && policy.RequireNonRoot {
			sc.RunAsNonRoot = ptr.To(true)
			sc.RunAsUser = ptr.To(defaultNonRootUID)
			sc.Capabilities = &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}}
			sc.SeccompProfile = &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}
		}
	}

	flags := cmd.Flags()
	if flags.Changed("run-as-non-root") {
		sc.RunAsNonRoot = ptr.To(o.runAsNonRoot)
	}
	if flags.Changed("run-as-user") {
		sc.RunAsUser = ptr.To(o.runAsUser)
	}
	if flags.Changed("run-as-group") {
		sc.RunAsGroup = ptr.To(o.runAsGroup)
	}
	if flags.Changed("allow-privilege-escalation") {
		sc.AllowPrivilegeEscalation = ptr.To(o.allowPrivilegeEscalation)
	}
	if flags.Changed("add-capabilities") || flags.Changed("drop-capabilities") {
		if sc.Capabilities == nil {
			sc.Capabilities = &corev1.Capabilities{}
		}
		if flags.Changed("add-capabilities") {
			sc.Capabilities.Add = toCapabilities(o.addCapabilities)
		}
		if flags.Changed("drop-capabilities") {
			sc.Capabilities.Drop = toCapabilities(o.dropCapabilities)
		}
	}
	if (*sc == corev1.SecurityContext{}) {
		return nil, nil
	}
	return sc, nil
}

func toCapabilities(values []string) []corev1.Capability {
	out := make([]corev1.Capability, 0, len(values))
	for _, v := range values {
		out = append(out, corev1.Capability(strings.ToUpper(strings.TrimPrefix(strings.TrimSpace(v), "CAP_"))))
	}
	return out
}

func ephemeralPolicy(session *breakglassv1alpha1.DebugSession) *breakglassv1alpha1.EphemeralContainersConfig {
	if session == nil || session.Status.ResolvedTemplate == nil || session.Status.ResolvedTemplate.KubectlDebug == nil {
		return nil
	}
	return session.Status.ResolvedTemplate.KubectlDebug.EphemeralContainers
}

// explainInjectRejection adds diagnostics to the server's deliberately generic
// 403: what was sent and what the template enforces. The same 403 also covers
// lifecycle and authorization causes, so the hint names those too.
func explainInjectRejection(err error, sent *corev1.SecurityContext, policy *breakglassv1alpha1.EphemeralContainersConfig) error {
	var httpErr *client.HTTPError
	if !errors.As(err, &httpErr) || httpErr.StatusCode != http.StatusForbidden {
		return err
	}
	if !strings.Contains(httpErr.Message, "debug operation is not allowed") {
		return err
	}
	sentJSON := "none"
	if sent != nil {
		if b, mErr := json.Marshal(sent); mErr == nil {
			sentJSON = string(b)
		}
	}
	policyText := "unknown (could not read the session)"
	if policy != nil {
		policyText = fmt.Sprintf("requireNonRoot=%t allowPrivileged=%t maxCapabilities=%q allowedImages=%q requireImageDigest=%t",
			policy.RequireNonRoot, policy.AllowPrivileged, policy.MaxCapabilities, policy.AllowedImages, policy.RequireImageDigest)
	}
	// Policy values come from the server; %q escapes them and SafeText keeps
	// any remaining control characters off the terminal.
	return fmt.Errorf("%w\nthe request was denied: either the template's ephemeral-container policy (image, namespace or "+
		"security context) or the session itself (expired, terminated, participant or lease change).\n"+
		"  template policy: %s\n  sent securityContext: %s\n"+
		"  check `bgctl debug session get` and the target pod before retrying; if the policy is the cause, adjust with "+
		"--run-as-non-root, --run-as-user, --run-as-group, --add-capabilities, --drop-capabilities, "+
		"--allow-privilege-escalation or --security-context-file", err, terminal.SafeText(policyText), terminal.SafeText(sentJSON))
}
