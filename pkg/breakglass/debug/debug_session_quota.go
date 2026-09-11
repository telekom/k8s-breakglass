// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/breakglass"
	"github.com/telekom/k8s-breakglass/pkg/quotas"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

var errDebugSessionCandidateChanged = errors.New("debug quota candidate changed")

func debugQuotaScope(parts ...string) string { b, _ := json.Marshal(parts); return string(b) }
func (c *DebugSessionController) quotaReader() ctrlclient.Reader {
	if c.apiReader != nil {
		return c.apiReader
	}
	return c.client
}
func (c *DebugSessionController) WithQuotaNamespace(namespace string) *DebugSessionController {
	c.quotaNamespace = namespace
	c.quotaEnabled = true
	if c.connectionLeases != nil {
		c.connectionLeases.WithNamespace(namespace)
	}
	return c
}
func (c *DebugSessionAPIController) WithQuotaNamespace(namespace string) *DebugSessionAPIController {
	c.quotaNamespace = namespace
	c.quotaEnabled = true
	if c.connectionLeases != nil {
		c.connectionLeases.WithNamespace(namespace)
	}
	return c
}

func debugSessionTerminal(s *breakglassv1alpha1.DebugSession) bool {
	return s.Status.State == breakglassv1alpha1.DebugSessionStateRejected || s.Status.State == breakglassv1alpha1.DebugSessionStateTerminated || s.Status.State == breakglassv1alpha1.DebugSessionStateExpired || s.Status.State == breakglassv1alpha1.DebugSessionStateFailed
}

// debugQuotaPolicy resolves live policy and legacy auto-discovered binding scope.
func (c *DebugSessionController) debugQuotaPolicy(ctx context.Context, s *breakglassv1alpha1.DebugSession) (quotas.Entry, map[string]int32, string, error) {
	entry := quotas.Entry{Kind: "DebugSession", Namespace: s.Namespace, Name: s.Name, UID: string(s.UID)}
	template, err := c.getTemplate(ctx, s.Spec.TemplateRef)
	if err != nil {
		return entry, nil, "", fmt.Errorf("read quota template: %w", err)
	}
	if template.UID == "" {
		return entry, nil, "", fmt.Errorf("quota template has no UID")
	}
	templateScope := debugQuotaScope("debug-template", string(template.UID))
	entry.Scopes = []string{templateScope}
	limits := map[string]int32{}
	if template.Spec.Constraints != nil && template.Spec.Constraints.MaxConcurrentSessions > 0 {
		limits[templateScope] = template.Spec.Constraints.MaxConcurrentSessions
	}
	var binding *breakglassv1alpha1.DebugSessionClusterBinding
	if s.Spec.BindingRef != nil {
		binding, err = c.getBinding(ctx, s.Spec.BindingRef.Name, s.Spec.BindingRef.Namespace)
	} else if s.Status.ResolvedBinding != nil {
		binding, err = c.getBinding(ctx, s.Status.ResolvedBinding.Name, s.Status.ResolvedBinding.Namespace)
	} else {
		binding, err = c.findBindingForSession(ctx, template, s.Spec.Cluster)
	}
	if err != nil {
		return entry, nil, "", fmt.Errorf("read quota binding: %w", err)
	}
	if binding != nil {
		if binding.UID == "" {
			return entry, nil, "", fmt.Errorf("quota binding has no UID")
		}
		total := debugQuotaScope("debug-binding", string(binding.UID))
		entry.Scopes = append(entry.Scopes, total)
		if binding.Spec.MaxActiveSessionsTotal != nil {
			limits[total] = *binding.Spec.MaxActiveSessionsTotal
		}
		// Preserve username/email alias matching used by the API preflight.
		for _, user := range []string{s.Spec.RequestedBy, s.Spec.RequestedByEmail} {
			if user == "" {
				continue
			}
			scope := debugQuotaScope("debug-binding-user", string(binding.UID), user)
			if slices.Contains(entry.Scopes, scope) {
				continue
			}
			entry.Scopes = append(entry.Scopes, scope)
			if binding.Spec.MaxActiveSessionsPerUser != nil {
				limits[scope] = *binding.Spec.MaxActiveSessionsPerUser
			}
		}
		if constraints := effectiveDebugSessionConstraints(template, binding); constraints != nil && constraints.MaxConcurrentSessions > 0 {
			if existing, ok := limits[templateScope]; !ok || constraints.MaxConcurrentSessions < existing {
				limits[templateScope] = constraints.MaxConcurrentSessions
			}
		}
	}
	retainFor := ""
	if constraints := effectiveDebugSessionConstraints(template, binding); constraints != nil {
		retainFor = constraints.RetainFor
	}
	return entry, limits, retainFor, nil
}

func (c *DebugSessionController) admitDebugSession(ctx context.Context, s *breakglassv1alpha1.DebugSession) error {
	if !c.quotaEnabled {
		return nil
	} // Legacy constructors; production wires the shared namespace.
	reader := c.quotaReader()
	current := &breakglassv1alpha1.DebugSession{}
	if err := reader.Get(ctx, ctrlclient.ObjectKeyFromObject(s), current); err != nil {
		return fmt.Errorf("read quota candidate: %w", err)
	}
	if current.UID != s.UID || debugSessionTerminal(current) {
		return fmt.Errorf("debug quota candidate changed or is terminal")
	}
	if s.ResourceVersion != current.ResourceVersion {
		return fmt.Errorf("%w: %w", errDebugSessionCandidateChanged,
			apierrors.NewConflict(breakglassv1alpha1.GroupVersion.WithResource("debugsessions").GroupResource(), s.Name, errors.New("retry reconciliation")))
	}
	if current.Annotations[quotas.AdmissionAnnotation] == "" && current.Status.State != breakglassv1alpha1.DebugSessionStateActive {
		base := current.DeepCopy()
		if current.Annotations == nil {
			current.Annotations = map[string]string{}
		}
		current.Annotations[quotas.AdmissionAnnotation] = quotas.Pending
		if err := c.client.Patch(ctx, current, ctrlclient.MergeFromWithOptions(base, ctrlclient.MergeFromWithOptimisticLock{})); err != nil {
			if apierrors.IsConflict(err) {
				return fmt.Errorf("%w: mark provisional debug session: %w", errDebugSessionCandidateChanged, err)
			}
			return fmt.Errorf("mark provisional debug session: %w", err)
		}
		s.ResourceVersion = current.ResourceVersion
		s.Annotations = current.Annotations
	}
	entry, limits, retainFor, err := c.debugQuotaPolicy(ctx, current)
	if err != nil {
		return err
	}
	err = (quotas.Store{Client: c.client, Reader: reader, Namespace: c.quotaNamespace}).Reserve(ctx, entry, limits,
		func(ctx context.Context, reserved map[string]quotas.Entry) ([]quotas.Entry, error) {
			list := &breakglassv1alpha1.DebugSessionList{}
			if err := reader.List(ctx, list); err != nil {
				return nil, err
			}
			var entries []quotas.Entry
			for i := range list.Items {
				item := &list.Items[i]
				if _, exists := reserved[string(item.UID)]; exists {
					continue
				}
				if debugSessionTerminal(item) || item.Annotations[quotas.AdmissionAnnotation] == quotas.Pending {
					continue
				}
				entry, _, _, err := c.debugQuotaPolicy(ctx, item)
				if err != nil {
					return nil, err
				}
				entries = append(entries, entry)
			}
			return entries, nil
		}, func(ctx context.Context, entry quotas.Entry) (bool, error) {
			if entry.Kind == "BreakglassSession" {
				obj := &breakglassv1alpha1.BreakglassSession{}
				err := reader.Get(ctx, ctrlclient.ObjectKey{Namespace: entry.Namespace, Name: entry.Name}, obj)
				if apierrors.IsNotFound(err) {
					return false, nil
				}
				if err != nil {
					return false, err
				}
				return string(obj.UID) == entry.UID && !breakglass.IsSessionTerminalState(obj.Status.State), nil
			}
			if entry.Kind != "DebugSession" {
				return false, fmt.Errorf("unsupported quota entry kind")
			}
			obj := &breakglassv1alpha1.DebugSession{}
			err := reader.Get(ctx, ctrlclient.ObjectKey{Namespace: entry.Namespace, Name: entry.Name}, obj)
			if apierrors.IsNotFound(err) {
				return false, nil
			}
			if err != nil {
				return false, err
			}
			return string(obj.UID) == entry.UID && !debugSessionTerminal(obj), nil
		})
	if err != nil {
		if errors.Is(err, quotas.ErrFull) && current.Annotations[quotas.AdmissionAnnotation] == quotas.Pending {
			if statusErr := breakglass.PatchDebugSessionStatusWithOptimisticLock(ctx, c.client, current, func(status *breakglassv1alpha1.DebugSessionStatus) {
				status.State = breakglassv1alpha1.DebugSessionStateFailed
				status.Message = "Session quota reached"
				if status.ResolvedTemplate == nil && status.RetainedUntil == nil && retainFor != "" {
					// Retention is terminal bookkeeping, not an approved activation snapshot.
					retention := breakglassv1alpha1.DebugSessionStatus{State: status.State, ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{Constraints: &breakglassv1alpha1.DebugSessionConstraints{RetainFor: retainFor}}}
					breakglass.StampDebugSessionRetention(&retention, time.Now().UTC())
					status.RetainedUntil = retention.RetainedUntil
				}
			}); statusErr != nil {
				return fmt.Errorf("record debug quota rejection: %w", statusErr)
			}
		}
		return err
	}
	if current.Annotations[quotas.AdmissionAnnotation] != quotas.Ready {
		base := current.DeepCopy()
		if current.Annotations == nil {
			current.Annotations = map[string]string{}
		}
		current.Annotations[quotas.AdmissionAnnotation] = quotas.Ready
		if err := c.client.Patch(ctx, current, ctrlclient.MergeFromWithOptions(base, ctrlclient.MergeFromWithOptimisticLock{})); err != nil {
			if apierrors.IsConflict(err) {
				return fmt.Errorf("%w: complete debug quota admission: %w", errDebugSessionCandidateChanged, err)
			}
			return fmt.Errorf("complete debug quota admission: %w", err)
		}
	}
	s.ResourceVersion = current.ResourceVersion
	s.Annotations = current.Annotations
	return nil
}
