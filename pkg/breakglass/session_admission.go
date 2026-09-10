// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package breakglass

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/quotas"
	"github.com/telekom/k8s-breakglass/pkg/utils"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func sessionScope(parts ...string) string { b, _ := json.Marshal(parts); return string(b) }

// quotaEscalationOwner rejects ambiguous or noncontrolling policy provenance.
func quotaEscalationOwner(s *breakglassv1alpha1.BreakglassSession) (*metav1.OwnerReference, error) {
	var selected *metav1.OwnerReference
	for i := range s.OwnerReferences {
		owner := &s.OwnerReferences[i]
		if owner.Kind != "BreakglassEscalation" {
			if owner.Controller != nil && *owner.Controller {
				return nil, fmt.Errorf("session quota has a different controlling owner")
			}
			continue
		}
		if selected != nil || owner.APIVersion != breakglassv1alpha1.GroupVersion.String() || owner.Controller == nil || !*owner.Controller || owner.Name == "" || owner.UID == "" {
			return nil, fmt.Errorf("session quota requires one unambiguous controlling escalation owner")
		}
		selected = owner
	}
	if selected == nil {
		return nil, fmt.Errorf("session quota requires escalation owner")
	}
	return selected, nil
}

func (c *SessionManager) quotaEscalation(ctx context.Context, s *breakglassv1alpha1.BreakglassSession) (*breakglassv1alpha1.BreakglassEscalation, error) {
	owner, err := quotaEscalationOwner(s)
	if err != nil {
		return nil, err
	}
	escalation := &breakglassv1alpha1.BreakglassEscalation{}
	if err := c.Reader().Get(ctx, client.ObjectKey{Namespace: s.Namespace, Name: owner.Name}, escalation); err != nil {
		return nil, fmt.Errorf("read quota escalation: %w", err)
	}
	if escalation.UID != owner.UID {
		return nil, fmt.Errorf("quota escalation UID changed")
	}
	return escalation, nil
}

func regularQuotaEntry(s *breakglassv1alpha1.BreakglassSession) (quotas.Entry, error) {
	owner, err := quotaEscalationOwner(s)
	if err != nil {
		return quotas.Entry{}, err
	}
	scopes := []string{sessionScope("tuple", s.Spec.User, s.Spec.Cluster, s.Spec.GrantedGroup), sessionScope("user", s.Spec.User), sessionScope("escalation", string(owner.UID))}
	return quotas.Entry{Kind: "BreakglassSession", Namespace: s.Namespace, Name: s.Name, UID: string(s.UID), Scopes: scopes}, nil
}

func (c *SessionManager) reserveSession(ctx context.Context, s *breakglassv1alpha1.BreakglassSession) error {
	if !c.quotaEnabled {
		return nil
	} // Legacy constructors; production always wires the namespace.
	reader := c.Reader()
	live := func(ctx context.Context, entry quotas.Entry) (bool, error) {
		if entry.Kind == "DebugSession" {
			current := &breakglassv1alpha1.DebugSession{}
			err := reader.Get(ctx, client.ObjectKey{Namespace: entry.Namespace, Name: entry.Name}, current)
			if apierrors.IsNotFound(err) {
				return false, nil
			}
			if err != nil {
				return false, err
			}
			terminal := current.Status.State == breakglassv1alpha1.DebugSessionStateTerminated || current.Status.State == breakglassv1alpha1.DebugSessionStateExpired || current.Status.State == breakglassv1alpha1.DebugSessionStateFailed
			return string(current.UID) == entry.UID && !terminal, nil
		}
		if entry.Kind != "BreakglassSession" {
			return false, fmt.Errorf("unsupported quota entry kind")
		}
		current := &breakglassv1alpha1.BreakglassSession{}
		err := reader.Get(ctx, client.ObjectKey{Namespace: entry.Namespace, Name: entry.Name}, current)
		if apierrors.IsNotFound(err) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		return string(current.UID) == entry.UID && !IsSessionTerminalState(current.Status.State), nil
	}
	escalation, err := c.quotaEscalation(ctx, s)
	if err != nil {
		return err
	}
	entry, err := regularQuotaEntry(s)
	if err != nil {
		return err
	}
	limits, err := c.sessionQuotaLimits(ctx, s, escalation)
	if err != nil {
		return err
	}
	return (quotas.Store{Client: c.Client, Reader: reader, Namespace: c.quotaNamespace}).Reserve(ctx, entry, limits,
		func(ctx context.Context, reserved map[string]quotas.Entry) ([]quotas.Entry, error) {
			var sessions breakglassv1alpha1.BreakglassSessionList
			if err := reader.List(ctx, &sessions); err != nil {
				return nil, err
			}
			var entries []quotas.Entry
			for i := range sessions.Items {
				item := &sessions.Items[i]
				if _, exists := reserved[string(item.UID)]; exists {
					continue
				}
				if !IsSessionTerminalState(item.Status.State) && item.Annotations[quotas.AdmissionAnnotation] != quotas.Pending {
					entry, err := regularQuotaEntry(item)
					if err != nil {
						return nil, fmt.Errorf("legacy session %s/%s quota owner: %w", item.Namespace, item.Name, err)
					}
					entries = append(entries, entry)
				}
			}
			return entries, nil
		}, live)
}

func (c *SessionManager) sessionQuotaLimits(ctx context.Context, s *breakglassv1alpha1.BreakglassSession, escalation *breakglassv1alpha1.BreakglassEscalation) (map[string]int32, error) {
	limits := map[string]int32{sessionScope("tuple", s.Spec.User, s.Spec.Cluster, s.Spec.GrantedGroup): 1}
	override := escalation.Spec.SessionLimitsOverride
	if override != nil {
		if override.Unlimited {
			return limits, nil
		}
		if override.MaxActiveSessionsTotal != nil {
			limits[sessionScope("escalation", string(escalation.UID))] = *override.MaxActiveSessionsTotal
		}
		if override.MaxActiveSessionsPerUser != nil {
			limits[sessionScope("user", s.Spec.User)] = *override.MaxActiveSessionsPerUser
			return limits, nil
		}
	}
	if s.Spec.IdentityProviderName == "" {
		return limits, nil
	}
	idp := &breakglassv1alpha1.IdentityProvider{}
	if err := c.Reader().Get(ctx, client.ObjectKey{Name: s.Spec.IdentityProviderName}, idp); err != nil {
		return nil, fmt.Errorf("read quota identity provider: %w", err)
	}
	if idp.Spec.SessionLimits == nil {
		return limits, nil
	}
	perUser := idp.Spec.SessionLimits.MaxActiveSessionsPerUser
	// UserGroups is the admission-time authenticated snapshot persisted by the API.
	var groups []string
	if raw := s.Annotations["breakglass.t-caas.telekom.com/quota-user-groups"]; raw != "" {
		if err := json.Unmarshal([]byte(raw), &groups); err != nil {
			return nil, fmt.Errorf("decode quota groups: %w", err)
		}
	}
outer:
	for _, override := range idp.Spec.SessionLimits.GroupOverrides {
		for _, group := range groups {
			match, err := utils.GlobMatch(override.Group, group)
			if err != nil {
				continue outer
			}
			if match {
				if override.Unlimited {
					return limits, nil
				}
				if override.MaxActiveSessionsPerUser != nil {
					perUser = override.MaxActiveSessionsPerUser
				}
				break outer
			}
		}
	}
	if perUser != nil {
		limits[sessionScope("user", s.Spec.User)] = *perUser
	}
	return limits, nil
}

func (c *SessionManager) admitSession(ctx context.Context, s *breakglassv1alpha1.BreakglassSession) error {
	if c.quotaEnabled && s.Annotations[quotas.AdmissionAnnotation] == "" && (s.Status.State == "" || s.Status.State == breakglassv1alpha1.SessionStatePending) {
		before := s.DeepCopy()
		if s.Annotations == nil {
			s.Annotations = map[string]string{}
		}
		s.Annotations[quotas.AdmissionAnnotation] = quotas.Pending
		if err := c.Client.Patch(ctx, s, client.MergeFromWithOptions(before, client.MergeFromWithOptimisticLock{})); err != nil {
			return fmt.Errorf("mark provisional session: %w", err)
		}
	}

	if err := c.reserveSession(ctx, s); err != nil {
		if errors.Is(err, quotas.ErrFull) && s.Annotations[quotas.AdmissionAnnotation] == quotas.Pending {
			rejected := s.DeepCopy()
			rejected.Status.State = breakglassv1alpha1.SessionStateRejected
			rejected.Status.ReasonEnded = "Session quota reached"
			if statusErr := c.Client.Status().Update(ctx, rejected); statusErr != nil {
				return fmt.Errorf("record quota rejection: %w", statusErr)
			}
		}
		return err
	}
	if !c.quotaEnabled || s.Annotations[quotas.AdmissionAnnotation] == quotas.Ready {
		return nil
	}
	if err := c.completeSessionAdmission(ctx, s); err != nil {
		return fmt.Errorf("complete session admission: %w", err)
	}
	return nil
}

// completeSessionAdmission publishes quota readiness from a fresh same-UID
// object. Reservation is already durable, so an unrelated update must retry
// the annotation write instead of leaving a permanently provisional session.
func (c *SessionManager) completeSessionAdmission(ctx context.Context, session *breakglassv1alpha1.BreakglassSession) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		current := &breakglassv1alpha1.BreakglassSession{}
		if err := c.Reader().Get(ctx, client.ObjectKeyFromObject(session), current); err != nil {
			return err
		}
		if session.UID != "" && current.UID != session.UID {
			return fmt.Errorf("session UID changed while completing admission")
		}
		if IsSessionTerminalState(current.Status.State) {
			return fmt.Errorf("refusing to admit terminal session")
		}
		if current.Annotations[quotas.AdmissionAnnotation] == quotas.Ready {
			*session = *current
			return nil
		}
		before := current.DeepCopy()
		if current.Annotations == nil {
			current.Annotations = map[string]string{}
		}
		current.Annotations[quotas.AdmissionAnnotation] = quotas.Ready
		if err := c.Client.Patch(ctx, current, client.MergeFromWithOptions(before, client.MergeFromWithOptimisticLock{})); err != nil {
			return err
		}
		*session = *current
		return nil
	})
}

// recoverSessionAdmissions finishes durable provisional admissions after an API
// process crashes, including a failed initial status write. It grants no access.
func (c *SessionManager) recoverSessionAdmissions(ctx context.Context) error {
	if !c.quotaEnabled {
		return nil
	}
	list := &breakglassv1alpha1.BreakglassSessionList{}
	if err := c.Reader().List(ctx, list); err != nil {
		return fmt.Errorf("list provisional sessions: %w", err)
	}
	for i := range list.Items {
		session := &list.Items[i]
		if session.Status.State != "" || session.Annotations[quotas.AdmissionAnnotation] == "" {
			continue
		}
		if err := c.admitSession(ctx, session); err != nil {
			c.getLogger().Warnw("Session admission recovery deferred", "session", session.Name, "error", err)
			continue
		}
		escalation, err := c.quotaEscalation(ctx, session)
		if err != nil {
			return fmt.Errorf("resolve recovery escalation: %w", err)
		}
		session.Status.State = breakglassv1alpha1.SessionStatePending
		session.Status.TimeoutAt = metav1.NewTime(time.Now().UTC().Add(ParseApprovalTimeout(escalation.Spec, c.getLogger())))
		if err := c.UpdateBreakglassSessionStatus(ctx, *session); err != nil {
			c.getLogger().Warnw("Session admission status recovery deferred", "session", session.Name, "error", err)
		}
	}
	return nil
}
