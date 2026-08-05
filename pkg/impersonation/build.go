// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package impersonation

import (
	"fmt"

	"k8s.io/client-go/rest"
)

// BuildResult is the outcome of turning a desired identity plus a spoke's
// capability into a concrete client-go impersonation configuration.
type BuildResult struct {
	// Config is ready to assign to rest.Config.Impersonate.
	Config rest.ImpersonationConfig

	// Mode is the mode the API server will actually select for Config. It may
	// differ from the requested mode when the spoke lacks capability, in which
	// case it is ModeLegacy.
	Mode Mode

	// Downgraded reports that a constrained mode was requested but legacy was
	// produced because the spoke does not support constrained impersonation.
	Downgraded bool

	// DowngradeReason explains the downgrade, for logs and audit records.
	DowngradeReason string

	// Constraint is the identity verb the API server will record in the audit
	// field authenticationMetadata.impersonationConstraint. Empty for legacy,
	// mirroring the API server, which omits the field there.
	Constraint string
}

// Build produces the impersonation configuration for an identity, honouring a
// spoke's detected capability.
//
// Backwards compatibility is the whole point of this function. When the spoke
// cannot do constrained impersonation, Build emits exactly the blanket identity
// that breakglass has always sent — same username, same groups — so a pre-1.35
// spoke behaves byte-identically to before this feature existed. Only when
// capability is present does it strip the fields that would trip the
// only-username-set precondition.
func Build(identity Identity, requested Mode, capability Capability) (BuildResult, error) {
	if requested == "" {
		requested = ModeLegacy
	}

	if !capability.UsesConstrained() && requested.IsConstrained() {
		return BuildResult{
			Config:     legacyConfig(identity),
			Mode:       ModeLegacy,
			Downgraded: true,
			DowngradeReason: fmt.Sprintf(
				"spoke does not support constrained impersonation (detected via %s%s); "+
					"using legacy impersonation",
				orUnknown(capability.DetectedVia), versionSuffix(capability.ServerVersion)),
		}, nil
	}

	if !requested.IsConstrained() {
		return BuildResult{
			Config: legacyConfig(identity),
			Mode:   ModeLegacy,
		}, nil
	}

	if violations := ValidateIdentity(identity, requested); len(violations) > 0 {
		for _, v := range violations {
			if v.Fatal {
				return BuildResult{}, fmt.Errorf(
					"identity is invalid for constrained impersonation mode %q: %s", requested, v.Error())
			}
		}
	}

	cfg := rest.ImpersonationConfig{UserName: identity.UserName}

	// Node and ServiceAccount modes require that ONLY the username be set. We do
	// not merely omit these fields here — ValidateIdentity above has already
	// rejected them — but constructing the config from scratch rather than copying
	// the input guarantees no stray field survives to disable the mode.
	if requested == ModeUserInfo {
		cfg.UID = identity.UID
		if len(identity.Groups) > 0 {
			cfg.Groups = append([]string(nil), identity.Groups...)
		}
		if len(identity.Extra) > 0 {
			cfg.Extra = make(map[string][]string, len(identity.Extra))
			for k, v := range identity.Extra {
				cfg.Extra[k] = append([]string(nil), v...)
			}
		}
	}

	return BuildResult{
		Config:     cfg,
		Mode:       requested,
		Constraint: IdentityVerb(requested),
	}, nil
}

// legacyConfig renders the classic blanket impersonation configuration: every
// field passed through unchanged, exactly as breakglass has always sent it.
func legacyConfig(identity Identity) rest.ImpersonationConfig {
	cfg := rest.ImpersonationConfig{
		UserName: identity.UserName,
		UID:      identity.UID,
	}
	if len(identity.Groups) > 0 {
		cfg.Groups = append([]string(nil), identity.Groups...)
	}
	if len(identity.Extra) > 0 {
		cfg.Extra = make(map[string][]string, len(identity.Extra))
		for k, v := range identity.Extra {
			cfg.Extra[k] = append([]string(nil), v...)
		}
	}
	return cfg
}

func orUnknown(s string) string {
	if s == "" {
		return "no detection yet"
	}
	return s
}

func versionSuffix(v string) string {
	if v == "" {
		return ""
	}
	return ", server version " + v
}
