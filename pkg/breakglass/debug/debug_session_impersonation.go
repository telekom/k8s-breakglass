// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"context"
	"fmt"
	"os"

	"k8s.io/client-go/rest"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	breakglass "github.com/telekom/k8s-breakglass/pkg/breakglass"
	"github.com/telekom/k8s-breakglass/pkg/impersonation"
	"github.com/telekom/k8s-breakglass/pkg/metrics"
)

// breakglassProbeCapability reads the capability the RBAC probe detected for a
// spoke. Indirected through a variable so tests can control it.
var breakglassProbeCapability = func(clusterName string) impersonation.Capability {
	return breakglass.ProbeCapabilityCache().Get(clusterName)
}

// nodeNameEnvVar is the environment variable the breakglass pod is expected to
// carry its own node name in, injected via the downward API:
//
//	env:
//	- name: NODE_NAME
//	  valueFrom:
//	    fieldRef:
//	      fieldPath: spec.nodeName
//
// This is required for associated-node impersonation (KEP-5284 knob 10): the mode
// is only selected when the impersonated node name matches the requestor's own
// node, and the requestor has no other way to learn which node that is.
const nodeNameEnvVar = "NODE_NAME"

// applyImpersonation sets restCfg.Impersonate from an ImpersonationConfig,
// honouring the spoke's constrained-impersonation capability.
//
// Backwards compatibility: when the spoke does not support constrained
// impersonation, impersonation.Build emits the same blanket identity breakglass has
// always sent, so an existing DebugSessionTemplate on an old spoke behaves exactly
// as it does today. Only the mode label and audit metadata differ.
func (c *DebugSessionController) applyImpersonation(
	ctx context.Context,
	restCfg *rest.Config,
	clusterName string,
	impConfig *breakglassv1alpha1.ImpersonationConfig,
) error {
	identity, mode, err := c.buildImpersonationIdentity(impConfig)
	if err != nil {
		return err
	}
	if identity.UserName == "" {
		// Nothing to impersonate: leave the controller's own credentials in place,
		// which is what an ImpersonationConfig with no target has always meant.
		return nil
	}

	capability := c.impersonationCapability(ctx, clusterName)

	built, err := impersonation.Build(identity, mode, capability)
	if err != nil {
		return fmt.Errorf("failed to build impersonation config for cluster %s: %w", clusterName, err)
	}

	if built.Downgraded {
		metrics.ImpersonationDowngrades.WithLabelValues(clusterName, string(mode)).Inc()
		c.log.Infow("Constrained impersonation downgraded to legacy for debug session deployment",
			"cluster", clusterName,
			"requestedMode", string(mode),
			"reason", built.DowngradeReason,
			"impersonatedUser", identity.UserName)
	} else {
		c.log.Debugw("Impersonating identity for debug session deployment",
			"cluster", clusterName,
			"mode", string(built.Mode),
			"impersonationConstraint", built.Constraint,
			"impersonatedUser", identity.UserName)
	}

	restCfg.Impersonate = built.Config
	return nil
}

// buildImpersonationIdentity turns an ImpersonationConfig into an identity plus the
// mode to request.
func (c *DebugSessionController) buildImpersonationIdentity(
	impConfig *breakglassv1alpha1.ImpersonationConfig,
) (impersonation.Identity, impersonation.Mode, error) {
	mode := impersonation.Mode(breakglassv1alpha1.InferImpersonationMode(impConfig))

	identity := impersonation.Identity{
		UserName: breakglassv1alpha1.EffectiveImpersonationUserName(impConfig),
	}

	// Only user-info mode may carry uid/groups/extra. Setting them in any other
	// mode breaks the API server's only-username-set precondition and silently
	// disables constrained impersonation — admission rejects that combination, so
	// reaching here with it set means the object predates the validation.
	if mode == impersonation.ModeUserInfo {
		identity.UID = impConfig.UID
		identity.Groups = impConfig.Groups
		identity.Extra = impConfig.Extra
	}

	if mode == impersonation.ModeAssociatedNode {
		nodeName := os.Getenv(nodeNameEnvVar)
		if nodeName == "" {
			return identity, mode, fmt.Errorf(
				"associated-node impersonation requires the %s environment variable, injected via the "+
					"downward API from spec.nodeName; the breakglass pod does not have it set",
				nodeNameEnvVar)
		}
		identity.UserName = impersonation.UsernameNodePrefix + nodeName
	}

	return identity, mode, nil
}

// impersonationCapability resolves the spoke's constrained-impersonation
// capability, honouring an explicit ClusterConfig setting and otherwise deferring
// to the shared probe cache.
//
// Capability is resolved per spoke, never from the hub's own version: in a
// hub-and-spoke topology the hub and each spoke may be on different Kubernetes
// releases, and all of them must work simultaneously.
func (c *DebugSessionController) impersonationCapability(
	ctx context.Context,
	clusterName string,
) impersonation.Capability {
	cc, err := c.lookupClusterConfig(ctx, clusterName)
	if err == nil && cc != nil && cc.Spec.ConstrainedImpersonation != nil {
		switch cc.Spec.ConstrainedImpersonation.EffectiveSupport() {
		case breakglassv1alpha1.ConstrainedImpersonationEnabled:
			return impersonation.Capability{
				Support:     impersonation.SupportYes,
				DetectedVia: "configured",
			}
		case breakglassv1alpha1.ConstrainedImpersonationDisabled:
			return impersonation.Capability{
				Support:     impersonation.SupportNo,
				DetectedVia: "configured",
			}
		case breakglassv1alpha1.ConstrainedImpersonationAuto:
			// Fall through to the probe cache.
		}
	}

	// The RBAC probe in pkg/breakglass runs against every spoke on every
	// authorization decision, so its cache is the best-informed source of truth
	// available here — and reusing it avoids a second, redundant detection path.
	return breakglassProbeCapability(clusterName)
}

// lookupClusterConfig fetches a spoke's ClusterConfig, tolerating absence.
func (c *DebugSessionController) lookupClusterConfig(
	ctx context.Context,
	clusterName string,
) (*breakglassv1alpha1.ClusterConfig, error) {
	if c.ccProvider == nil {
		return nil, fmt.Errorf("cluster client provider not configured")
	}
	return c.ccProvider.GetAcrossAllNamespaces(ctx, clusterName)
}
