// SPDX-FileCopyrightText: 2025 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package breakglass

import (
	"context"
	"fmt"
	"sort"
	"time"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/audit"
	"github.com/telekom/k8s-breakglass/pkg/system"
	"github.com/telekom/k8s-breakglass/pkg/utils"
	"go.uber.org/zap"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type duplicateSessionKey struct {
	Cluster, User, Group string
}

const (
	duplicateCleanupIntentExpire   = "ExpireDecision"
	duplicateCleanupIntentWithdraw = "WithdrawDecision"
	duplicateCleanupLegacyPending  = "PendingDelivery"
)

// sessionStatePriority returns a numeric priority for a given session state.
// Higher values indicate higher priority when choosing which duplicate to keep.
func sessionStatePriority(state breakglassv1alpha1.BreakglassSessionState) int {
	switch state {
	case breakglassv1alpha1.SessionStateApproved:
		return 3
	case breakglassv1alpha1.SessionStateWaitingForScheduledTime:
		return 2
	case breakglassv1alpha1.SessionStatePending:
		return 1
	default:
		return 0
	}
}

func isActiveDuplicateSessionState(state breakglassv1alpha1.BreakglassSessionState) bool {
	return sessionStatePriority(state) > 0
}

func duplicateKeyForSession(session breakglassv1alpha1.BreakglassSession) duplicateSessionKey {
	return duplicateSessionKey{
		Cluster: session.Spec.Cluster,
		User:    session.Spec.User,
		Group:   session.Spec.GrantedGroup,
	}
}

func sortDuplicateSessions(sessions []breakglassv1alpha1.BreakglassSession) {
	sort.Slice(sessions, func(i, j int) bool {
		si := sessions[i]
		sj := sessions[j]

		pi := sessionStatePriority(si.Status.State)
		pj := sessionStatePriority(sj.Status.State)
		if pi != pj {
			return pi > pj
		}

		if !si.CreationTimestamp.Equal(&sj.CreationTimestamp) {
			return si.CreationTimestamp.Before(&sj.CreationTimestamp)
		}

		return si.Name < sj.Name
	})
}

// CleanupDuplicateSessions detects active sessions that share the same
// (cluster, user, grantedGroup) triple — which should be unique — and
// terminates the duplicates, keeping the best candidate alive.
//
// The survivor is chosen by state priority (Approved > WaitingForScheduledTime
// > Pending), then by CreationTimestamp (oldest first), with resource name as
// a deterministic tie-breaker.
//
// Duplicates can occur in multi-replica deployments due to TOCTOU race
// conditions in session creation (the in-flight guard is per-process).
// Running this during the periodic cleanup makes the system eventually
// consistent without hammering the API server.
func CleanupDuplicateSessions(ctx context.Context, log *zap.SugaredLogger, mgr *SessionManager, auditEmitters ...AuditEmitter) {
	if mgr == nil {
		return
	}
	if log == nil {
		log = zap.S()
	}
	auditEmitter := firstAuditEmitter(auditEmitters)
	// Drain persisted intents before looking for new duplicates. This deliberately
	// runs even when there are fewer than two active sessions or auditing was
	// disabled after an intent had already been committed.
	drainPendingDuplicateCleanupAudits(ctx, log, mgr, auditEmitter)

	// Collect active sessions from all "in-flight" states.
	activeStates := []breakglassv1alpha1.BreakglassSessionState{
		breakglassv1alpha1.SessionStatePending,
		breakglassv1alpha1.SessionStateApproved,
		breakglassv1alpha1.SessionStateWaitingForScheduledTime,
	}

	var allActive []breakglassv1alpha1.BreakglassSession
	for _, state := range activeStates {
		sessions, err := mgr.GetSessionsByState(ctx, state)
		if err != nil {
			log.Warnw("Failed to list sessions for duplicate cleanup", "state", state, "error", err)
			continue
		}
		allActive = append(allActive, sessions...)
	}

	if len(allActive) < 2 {
		return // need at least 2 for a duplicate
	}

	// Group by the unique triple: cluster/user/grantedGroup.
	groups := make(map[duplicateSessionKey][]breakglassv1alpha1.BreakglassSession)
	for _, s := range allActive {
		key := duplicateKeyForSession(s)
		groups[key] = append(groups[key], s)
	}

	for key, sessions := range groups {
		if len(sessions) < 2 {
			continue
		}

		var err error
		sessions, err = listLiveActiveDuplicateSessions(ctx, mgr, key)
		if err != nil {
			log.Warnw("Failed to revalidate duplicate session set",
				"cluster", key.Cluster,
				"user", key.User,
				"group", system.RedactGroupName(key.Group),
				"error", err)
			continue
		}
		if len(sessions) < 2 {
			continue
		}

		// Sort by state priority (Approved > WaitingForScheduledTime > Pending),
		// then by CreationTimestamp ascending (oldest first), and finally by name
		// as a deterministic tie-breaker.
		sortDuplicateSessions(sessions)

		// Keep the best candidate (sessions[0]), terminate the rest.
		log.Warnw("Duplicate active sessions detected — terminating duplicates",
			"cluster", key.Cluster,
			"user", key.User,
			"group", system.RedactGroupName(key.Group),
			"keepSession", sessions[0].Name,
			"duplicateCount", len(sessions)-1,
		)

		for _, dup := range sessions[1:] {
			// Check if the context has been cancelled (e.g., leader election loss, shutdown).
			select {
			case <-ctx.Done():
				log.Infow("Duplicate cleanup interrupted by context cancellation",
					"cluster", key.Cluster,
					"user", key.User,
					"group", system.RedactGroupName(key.Group),
				)
				return
			default:
			}

			log.Infow("Handling duplicate session",
				"session", dup.Name,
				"namespace", dup.Namespace,
				"state", dup.Status.State,
				"created", dup.CreationTimestamp.Time,
			)

			if _, err := terminateDuplicateSession(ctx, log, mgr, key, dup, auditEmitter); err != nil {
				log.Warnw("Failed to update duplicate session status", "session", dup.Name, "error", err)
			}
		}
	}
}

func listLiveActiveDuplicateSessions(
	ctx context.Context,
	mgr *SessionManager,
	key duplicateSessionKey,
) ([]breakglassv1alpha1.BreakglassSession, error) {
	list := breakglassv1alpha1.BreakglassSessionList{}
	if err := mgr.Reader().List(ctx, &list); err != nil {
		return nil, fmt.Errorf("list live duplicate sessions: %w", err)
	}

	active := make([]breakglassv1alpha1.BreakglassSession, 0, len(list.Items))
	for i := range list.Items {
		if duplicateKeyForSession(list.Items[i]) == key && isActiveDuplicateSessionState(list.Items[i].Status.State) {
			active = append(active, list.Items[i])
		}
	}
	sortDuplicateSessions(active)
	return active, nil
}

func getLiveDuplicateSession(
	ctx context.Context,
	mgr *SessionManager,
	session breakglassv1alpha1.BreakglassSession,
) (breakglassv1alpha1.BreakglassSession, error) {
	if session.Namespace == "" {
		return breakglassv1alpha1.BreakglassSession{}, fmt.Errorf("get live duplicate session %q: namespace is required for live reader lookup", session.Name)
	}

	live := breakglassv1alpha1.BreakglassSession{}
	if err := mgr.Reader().Get(ctx, types.NamespacedName{Namespace: session.Namespace, Name: session.Name}, &live); err != nil {
		return breakglassv1alpha1.BreakglassSession{}, fmt.Errorf("get live duplicate session %s/%s: %w", session.Namespace, session.Name, err)
	}
	return live, nil
}

func terminateDuplicateSession(
	ctx context.Context,
	log *zap.SugaredLogger,
	mgr *SessionManager,
	key duplicateSessionKey,
	session breakglassv1alpha1.BreakglassSession,
	auditEmitters ...AuditEmitter,
) (bool, error) {
	auditEmitter := firstAuditEmitter(auditEmitters)
	auditRequired := auditConfigured(auditEmitter)
	terminalized := false
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		active, err := listLiveActiveDuplicateSessions(ctx, mgr, key)
		if err != nil {
			return err
		}
		if len(active) < 2 {
			log.Infow("Skipping duplicate session because fewer than two active sessions remain",
				"session", session.Name,
				"namespace", session.Namespace)
			return nil
		}

		var live *breakglassv1alpha1.BreakglassSession
		for i := range active {
			if active[i].Namespace == session.Namespace && active[i].Name == session.Name {
				live = &active[i]
				break
			}
		}
		if live == nil {
			log.Infow("Skipping duplicate session that is no longer in the active duplicate set",
				"session", session.Name,
				"namespace", session.Namespace)
			return nil
		}
		if live.UID != session.UID || live.ResourceVersion != session.ResourceVersion || live.Status.State != session.Status.State {
			log.Infow("Skipping duplicate session that changed after survivor selection",
				"session", live.Name,
				"namespace", live.Namespace,
				"state", live.Status.State)
			return nil
		}
		if active[0].Namespace == live.Namespace && active[0].Name == live.Name {
			log.Infow("Skipping duplicate session that is now the preferred survivor",
				"session", live.Name,
				"namespace", live.Namespace,
				"state", live.Status.State)
			return nil
		}

		base := live.DeepCopy()
		if condition := duplicateCleanupAuditCondition(live); condition != nil && condition.Status == metav1.ConditionFalse {
			auditRequired = true
			return nil
		}
		decisionTime := metav1.NewTime(time.Now().UTC().Truncate(time.Second))
		prepareDuplicateSessionTerminationAt(live, log, !auditRequired, decisionTime)
		live.Status.ObservedGeneration = live.Generation
		if err := mgr.Client.Status().Patch(ctx, live, client.MergeFromWithOptions(base, client.MergeFromWithOptimisticLock{})); err != nil {
			if apierrors.IsNotFound(err) {
				return nil
			}
			return err
		}
		terminalized = true
		return nil
	})
	if err != nil {
		return false, fmt.Errorf("patch duplicate session status %s/%s: %w", session.Namespace, session.Name, err)
	}
	if !auditRequired {
		return terminalized, nil
	}
	if err := drainDuplicateCleanupAudit(ctx, log, mgr, session.Namespace, session.Name, auditEmitter); err != nil {
		return false, fmt.Errorf("drain duplicate cleanup audit for %s/%s: %w", session.Namespace, session.Name, err)
	}
	live, err := getLiveDuplicateSession(ctx, mgr, session)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return false, nil
		}
		return false, err
	}
	return isDuplicateCleanupTerminal(live), nil
}

func firstAuditEmitter(emitters []AuditEmitter) AuditEmitter {
	if len(emitters) == 0 {
		return nil
	}
	return emitters[0]
}

func auditConfigured(emitter AuditEmitter) bool {
	if emitter == nil {
		return false
	}
	if state, ok := emitter.(interface{ IsConfigured() bool }); ok {
		return state.IsConfigured()
	}
	return emitter.IsEnabled()
}

func isDuplicateCleanupTerminal(session breakglassv1alpha1.BreakglassSession) bool {
	condition := duplicateCleanupAuditCondition(&session)
	return condition != nil && condition.Status == metav1.ConditionTrue &&
		(session.Status.State == breakglassv1alpha1.SessionStateExpired || session.Status.State == breakglassv1alpha1.SessionStateWithdrawn)
}

func duplicateCleanupAuditCondition(session *breakglassv1alpha1.BreakglassSession) *metav1.Condition {
	return session.GetCondition(string(breakglassv1alpha1.SessionConditionTypeDuplicateCleanupAuditComplete))
}

func duplicateCleanupTerminalState(condition metav1.Condition) (breakglassv1alpha1.BreakglassSessionState, error) {
	switch condition.Reason {
	case duplicateCleanupIntentExpire:
		return breakglassv1alpha1.SessionStateExpired, nil
	case duplicateCleanupIntentWithdraw:
		return breakglassv1alpha1.SessionStateWithdrawn, nil
	default:
		return "", fmt.Errorf("unknown duplicate cleanup audit intent %q", condition.Reason)
	}
}

func legacyDuplicateCleanupAuditEvent(session *breakglassv1alpha1.BreakglassSession, condition metav1.Condition) *audit.Event {
	eventType := audit.EventSessionExpired
	if session.Status.State == breakglassv1alpha1.SessionStateWithdrawn {
		eventType = audit.EventSessionWithdrawn
	}
	return &audit.Event{
		ID:        "duplicate-cleanup/" + string(session.UID),
		Type:      eventType,
		Severity:  audit.SeverityInfo,
		Timestamp: condition.LastTransitionTime.Time.UTC(),
		Actor:     audit.Actor{User: "system"},
		Target: audit.Target{
			Kind:      "BreakglassSession",
			Name:      session.Name,
			Namespace: session.Namespace,
			Cluster:   session.Spec.Cluster,
		},
		RequestContext: &audit.RequestContext{SessionName: session.Name},
		Details: map[string]interface{}{
			"reason":        "duplicateCleanup",
			"terminalState": string(session.Status.State),
			"grantedGroup":  session.Spec.GrantedGroup,
		},
	}
}

// duplicateCleanupAuditEvent reconstructs the exact event from the persisted
// terminal state and outbox intent. Both are committed before delivery.
func duplicateCleanupAuditEvent(session *breakglassv1alpha1.BreakglassSession, condition metav1.Condition) *audit.Event {
	terminalState, err := duplicateCleanupTerminalState(condition)
	if err != nil {
		return nil
	}
	return &audit.Event{
		ID:        "duplicate-cleanup/" + string(session.UID),
		Type:      audit.EventSessionTerminationIntent,
		Severity:  audit.SeverityInfo,
		Timestamp: condition.LastTransitionTime.Time.UTC(),
		Actor:     audit.Actor{User: "system"},
		Target: audit.Target{
			Kind:      "BreakglassSession",
			Name:      session.Name,
			Namespace: session.Namespace,
			Cluster:   session.Spec.Cluster,
		},
		RequestContext: &audit.RequestContext{SessionName: session.Name},
		Details: map[string]interface{}{
			"reason":              "duplicateCleanup",
			"terminalDecision":    string(terminalState),
			"transitionCommitted": true,
			"grantedGroup":        session.Spec.GrantedGroup,
		},
	}
}

// drainPendingDuplicateCleanupAudits delivers persisted outbox entries. It
// runs independently of duplicate detection so a failed delivery is retried
// on a later tick even after the duplicate set has disappeared.
func drainPendingDuplicateCleanupAudits(ctx context.Context, log *zap.SugaredLogger, mgr *SessionManager, emitter AuditEmitter) int {
	pending := 0
	for _, state := range []breakglassv1alpha1.BreakglassSessionState{
		breakglassv1alpha1.SessionStateExpired,
		breakglassv1alpha1.SessionStateWithdrawn,
	} {
		sessions, err := mgr.GetSessionsByState(ctx, state)
		if err != nil {
			log.Warnw("Failed to list terminal sessions for duplicate cleanup audit drain", "state", state, "error", err)
			continue
		}
		for i := range sessions {
			condition := sessions[i].GetCondition(string(breakglassv1alpha1.SessionConditionTypeDuplicateCleanupAuditComplete))
			if condition == nil || condition.Status == metav1.ConditionTrue {
				continue
			}
			pending++
			if err := drainDuplicateCleanupAudit(ctx, log, mgr, sessions[i].Namespace, sessions[i].Name, emitter); err != nil {
				log.Warnw("Failed to drain duplicate cleanup audit", "session", sessions[i].Name, "namespace", sessions[i].Namespace, "error", err)
			}
		}
	}
	return pending
}

func drainDuplicateCleanupAudit(ctx context.Context, log *zap.SugaredLogger, mgr *SessionManager, namespace, name string, emitter AuditEmitter) error {
	live, err := getLiveDuplicateSession(ctx, mgr, breakglassv1alpha1.BreakglassSession{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name}})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return err
	}
	condition := duplicateCleanupAuditCondition(&live)
	if condition == nil || condition.Status == metav1.ConditionTrue {
		return nil
	}
	if live.UID == "" {
		return fmt.Errorf("persisted duplicate cleanup session %s/%s has no UID", namespace, name)
	}
	if !auditConfigured(emitter) {
		return commitDuplicateCleanupWithoutAudit(ctx, log, mgr, live, *condition)
	}
	if !emitter.IsEnabled() {
		return fmt.Errorf("duplicate cleanup audit is pending but auditing is unavailable")
	}
	legacyPending := condition.Reason == duplicateCleanupLegacyPending
	terminalState := live.Status.State
	if legacyPending {
		if terminalState != breakglassv1alpha1.SessionStateExpired && terminalState != breakglassv1alpha1.SessionStateWithdrawn {
			return fmt.Errorf("legacy duplicate cleanup audit is pending in non-terminal state %q", terminalState)
		}
	} else {
		terminalState, err = duplicateCleanupTerminalState(*condition)
		if err != nil {
			return err
		}
		if live.Status.State != terminalState {
			return fmt.Errorf("duplicate cleanup intent %q does not match terminal state %q", condition.Reason, live.Status.State)
		}
	}

	// Emission happens exactly once per drain attempt, outside the optimistic
	// acknowledgement retry closure. If acknowledgement conflicts or fails,
	// the next drain emits the same durable event again (at-least-once).
	event := duplicateCleanupAuditEvent(&live, *condition)
	if legacyPending {
		event = legacyDuplicateCleanupAuditEvent(&live, *condition)
	}
	if event == nil {
		return fmt.Errorf("construct duplicate cleanup audit event from intent %q", condition.Reason)
	}
	if err := emitDuplicateCleanupAudit(ctx, event, emitter); err != nil {
		return fmt.Errorf("synchronous duplicate cleanup audit delivery: %w", err)
	}

	err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
		current, getErr := getLiveDuplicateSession(ctx, mgr, live)
		if getErr != nil {
			return getErr
		}
		currentCondition := duplicateCleanupAuditCondition(&current)
		if currentCondition == nil || currentCondition.Status == metav1.ConditionTrue {
			return nil
		}
		if currentCondition.Reason != condition.Reason || !currentCondition.LastTransitionTime.Equal(&condition.LastTransitionTime) {
			return fmt.Errorf("duplicate cleanup audit intent changed during acknowledgement")
		}
		if legacyPending {
			if current.Status.State != terminalState {
				return fmt.Errorf("legacy duplicate cleanup terminal state changed during acknowledgement")
			}
		} else if current.Status.State != terminalState {
			return fmt.Errorf("duplicate cleanup terminal state changed during acknowledgement")
		}
		base := current.DeepCopy()
		ackReason := condition.Reason
		if legacyPending {
			ackReason = "EmissionAccepted"
		}
		current.SetCondition(metav1.Condition{
			Type:               string(breakglassv1alpha1.SessionConditionTypeDuplicateCleanupAuditComplete),
			Status:             metav1.ConditionTrue,
			LastTransitionTime: condition.LastTransitionTime,
			Reason:             ackReason,
			Message:            "Duplicate cleanup terminal audit was synchronously accepted by every configured sink.",
		})
		current.Status.ObservedGeneration = current.Generation
		return mgr.Client.Status().Patch(ctx, &current, client.MergeFromWithOptions(base, client.MergeFromWithOptimisticLock{}))
	})
	if err != nil {
		log.Warnw("Duplicate cleanup audit delivered but acknowledgement failed; retaining retryable outbox state", "session", name, "namespace", namespace, "error", err)
		return fmt.Errorf("acknowledge duplicate cleanup audit: %w", err)
	}
	return nil
}

func commitDuplicateCleanupWithoutAudit(
	ctx context.Context,
	log *zap.SugaredLogger,
	mgr *SessionManager,
	live breakglassv1alpha1.BreakglassSession,
	condition metav1.Condition,
) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		current, err := getLiveDuplicateSession(ctx, mgr, live)
		if err != nil {
			return err
		}
		currentCondition := duplicateCleanupAuditCondition(&current)
		if currentCondition == nil || currentCondition.Status == metav1.ConditionTrue {
			return nil
		}
		if currentCondition.Reason != condition.Reason || !currentCondition.LastTransitionTime.Equal(&condition.LastTransitionTime) {
			return fmt.Errorf("duplicate cleanup audit intent changed before disabled commit")
		}

		base := current.DeepCopy()
		if condition.Reason == duplicateCleanupLegacyPending {
			current.SetCondition(metav1.Condition{
				Type:               string(breakglassv1alpha1.SessionConditionTypeDuplicateCleanupAuditComplete),
				Status:             metav1.ConditionTrue,
				LastTransitionTime: condition.LastTransitionTime,
				Reason:             "AuditingDisabledAtCommit",
				Message:            "Duplicate cleanup terminal audit was not required because auditing was intentionally disabled at commit.",
			})
		} else {
			terminalState, stateErr := duplicateCleanupTerminalState(condition)
			if stateErr != nil {
				return stateErr
			}
			if current.Status.State != terminalState {
				return fmt.Errorf("duplicate cleanup intent %q does not match terminal state %q", condition.Reason, current.Status.State)
			}
			current.SetCondition(metav1.Condition{
				Type:               string(breakglassv1alpha1.SessionConditionTypeDuplicateCleanupAuditComplete),
				Status:             metav1.ConditionTrue,
				LastTransitionTime: condition.LastTransitionTime,
				Reason:             condition.Reason,
				Message:            "Duplicate cleanup audit was not required because auditing is intentionally disabled.",
			})
		}
		current.Status.ObservedGeneration = current.Generation
		return mgr.Client.Status().Patch(ctx, &current, client.MergeFromWithOptions(base, client.MergeFromWithOptimisticLock{}))
	})
}

func emitDuplicateCleanupAudit(ctx context.Context, event *audit.Event, emitter AuditEmitter) error {
	if emitter == nil || !emitter.IsEnabled() {
		return fmt.Errorf("duplicate cleanup audit emitter is unavailable")
	}
	if syncEmitter, ok := emitter.(interface {
		EmitSync(context.Context, *audit.Event) error
	}); ok {
		return syncEmitter.EmitSync(ctx, event)
	}
	return fmt.Errorf("duplicate cleanup audit emitter does not support true synchronous delivery")
}

func prepareDuplicateSessionTerminationAt(session *breakglassv1alpha1.BreakglassSession, log *zap.SugaredLogger, auditDisabled bool, now metav1.Time) {
	var (
		targetState      breakglassv1alpha1.BreakglassSessionState
		conditionType    breakglassv1alpha1.BreakglassSessionConditionType
		conditionReason  string
		conditionMessage string
		reasonEnded      string
	)

	switch session.Status.State {
	case breakglassv1alpha1.SessionStatePending, breakglassv1alpha1.SessionStateWaitingForScheduledTime:
		// Pending/Waiting sessions must be withdrawn, not expired,
		// to satisfy the webhook state machine.
		targetState = breakglassv1alpha1.SessionStateWithdrawn
		conditionType = breakglassv1alpha1.SessionConditionTypeCanceled
		conditionReason = "DuplicateSessionWithdrawn"
		conditionMessage = "Withdrawn by cleanup routine: duplicate session for the same cluster/user/group triple."
		reasonEnded = "withdrawn"
	case breakglassv1alpha1.SessionStateApproved:
		// Approved sessions can be directly expired.
		targetState = breakglassv1alpha1.SessionStateExpired
		conditionType = breakglassv1alpha1.SessionConditionTypeExpired
		conditionReason = "DuplicateSessionTerminated"
		conditionMessage = "Terminated by cleanup routine: duplicate session for the same cluster/user/group triple."
		reasonEnded = "duplicateCleanup"
	default:
		return
	}

	// Populate terminal-state timestamps that the rest of the system expects.
	if targetState == breakglassv1alpha1.SessionStateWithdrawn && session.Status.WithdrawnAt.IsZero() {
		session.Status.WithdrawnAt = now
	}
	// Terminal metadata must never move a malformed or elapsed lease beyond
	// its natural boundary, regardless of whether cleanup withdraws or expires
	// the duplicate.
	session.Status.ExpiresAt = utils.ClampBreakglassSessionExpiry(session.Status.ExpiresAt, now.Time)
	// Set RetainedUntil so the cleanup routine can later garbage-collect the session.
	if session.Status.RetainedUntil.IsZero() {
		retainFor := ParseRetainFor(session.Spec, log)
		session.Status.RetainedUntil = metav1.NewTime(now.Time.Add(retainFor))
	}

	session.Status.State = targetState
	session.Status.ReasonEnded = reasonEnded
	session.SetCondition(metav1.Condition{
		Type:               string(conditionType),
		Status:             metav1.ConditionTrue,
		LastTransitionTime: now,
		Reason:             conditionReason,
		Message:            conditionMessage,
	})
	auditStatus := metav1.ConditionFalse
	auditReason := "PendingDelivery"
	auditMessage := "Duplicate cleanup terminal audit is pending synchronous delivery."
	if auditDisabled {
		auditStatus = metav1.ConditionTrue
		auditReason = "AuditingDisabledAtCommit"
		auditMessage = "Duplicate cleanup terminal audit was not required because auditing was intentionally disabled at commit."
	}
	if !auditDisabled {
		auditReason = duplicateCleanupIntentWithdraw
		if targetState == breakglassv1alpha1.SessionStateExpired {
			auditReason = duplicateCleanupIntentExpire
		}
	}
	session.SetCondition(metav1.Condition{
		Type:               string(breakglassv1alpha1.SessionConditionTypeDuplicateCleanupAuditComplete),
		Status:             auditStatus,
		LastTransitionTime: now,
		Reason:             auditReason,
		Message:            auditMessage,
	})
}
