// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

// Named public-behaviour tests for the generic DebugSession contract. They are
// indexed by docs/debug-session-acceptance-matrix.md; keep their names stable
// (hack/check-acceptance-matrix.sh fails when a matrix row loses its test).

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	breakglass "github.com/telekom/k8s-breakglass/pkg/breakglass"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func acceptancePost(router *gin.Engine, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

// A requester may only choose what the create request type declares. Every
// runtime, identity and lifecycle field is refused instead of being dropped, so
// nothing a requester sends can reach the rendered workload or the stored spec.
func TestAcceptanceCreateRejectsRequesterSuppliedRuntimeFields(t *testing.T) {
	forbidden := map[string]string{
		"volumes":            `[{"name":"s","secret":{"secretName":"tenant-secret"}}]`,
		"volumeMounts":       `[{"name":"s","mountPath":"/s"}]`,
		"secrets":            `["tenant-secret"]`,
		"envFrom":            `[{"secretRef":{"name":"tenant-secret"}}]`,
		"image":              `"attacker/image"`,
		"debugImage":         `"attacker/image"`,
		"command":            `["sh"]`,
		"args":               `["-c","id"]`,
		"hostPath":           `"/"`,
		"hostNetwork":        `true`,
		"hostPID":            `true`,
		"hostIPC":            `true`,
		"privileged":         `true`,
		"capabilities":       `{"add":["SYS_ADMIN"]}`,
		"securityContext":    `{"privileged":true}`,
		"runtimeClassName":   `"unsafe"`,
		"serviceAccountName": `"cluster-admin"`,
		"podTemplate":        `{"spec":{"hostNetwork":true}}`,
		"labels":             `{"breakglass.telekom.com/debug-session":"forged"}`,
		"annotations":        `{"breakglass.telekom.com/debug-session-uid":"forged"}`,
		"ownerReferences":    `[{"apiVersion":"v1","kind":"Pod","name":"x","uid":"u"}]`,
		"metadata":           `{"labels":{"a":"b"}}`,
		"requestedBy":        `"admin@example.com"`,
		"userGroups":         `["system:masters"]`,
		"state":              `"Active"`,
		"status":             `{"state":"Active"}`,
		"expiresAt":          `"2999-01-01T00:00:00Z"`,
		"approval":           `{"approvedBy":"me"}`,
		"targetNode":         `"other-node"`,
		"targetPod":          `"other-pod"`,
	}
	_, ctrl := setupTestRouter(t)
	router := setupAuthenticatedDebugSessionRouter(t, ctrl, "alice@example.com", "alice@example.com", nil)
	for field, value := range forbidden {
		t.Run(field, func(t *testing.T) {
			body := `{"templateRef":"standard-debug","cluster":"production","` + field + `":` + value + `}`
			w := acceptancePost(router, "/api/debugSessions", body)
			require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
			assert.Contains(t, w.Body.String(), "unknown field")
		})
	}
	var sessions breakglassv1alpha1.DebugSessionList
	require.NoError(t, ctrl.client.List(context.Background(), &sessions))
	assert.Empty(t, sessions.Items, "a rejected request must not persist a session")
}

// Rejection, expiry, termination and failure are terminal. A stale snapshot
// that still shows a future expiresAt (or a pending approval that was never
// granted) must not let anyone renew, join, or reach the target.
func TestAcceptanceInactiveSessionDeniesEveryOperation(t *testing.T) {
	operations := []struct{ name, path, body string }{
		{"renew", "renew", `{"extendBy":"1h"}`},
		{"join", "join", `{"role":"participant"}`},
		{"terminate", "terminate", ``},
		{"injectEphemeralContainer", "injectEphemeralContainer", `{"namespace":"default","podName":"p","containerName":"d","image":"busybox"}`},
		{"createPodCopy", "createPodCopy", `{"namespace":"default","podName":"p"}`},
		{"createNodeDebugPod", "createNodeDebugPod", `{"nodeName":"n"}`},
	}
	for _, state := range []breakglassv1alpha1.DebugSessionState{
		breakglassv1alpha1.DebugSessionStateRejected,
		breakglassv1alpha1.DebugSessionStateExpired,
		breakglassv1alpha1.DebugSessionStateTerminated,
		breakglassv1alpha1.DebugSessionStateFailed,
		breakglassv1alpha1.DebugSessionStatePendingApproval,
	} {
		for _, op := range operations {
			if state == breakglassv1alpha1.DebugSessionStatePendingApproval && op.name == "terminate" {
				continue // the owner may retire a pending request
			}
			t.Run(string(state)+"/"+op.name, func(t *testing.T) {
				session := newActiveKubectlDebugSession("stale", "owner", time.Now().Add(time.Hour).Truncate(time.Second))
				session.Status.State = state
				_, ctrl := setupTestRouter(t, session)
				router := setupAuthenticatedDebugSessionRouter(t, ctrl, "owner", "", nil)

				w := acceptancePost(router, "/api/debugSessions/stale/"+op.path, op.body)
				assert.GreaterOrEqual(t, w.Code, 400, "%s on %s session: %s", op.name, state, w.Body.String())
				assert.Less(t, w.Code, 500, w.Body.String())

				var stored breakglassv1alpha1.DebugSession
				require.NoError(t, ctrl.client.Get(context.Background(), client.ObjectKeyFromObject(session), &stored))
				assert.Equal(t, state, stored.Status.State, "denied operation must not change the state")
				assert.True(t, stored.Status.ExpiresAt.Equal(session.Status.ExpiresAt), "denied operation must not move the deadline")
				assert.Equal(t, session.Status.RenewalCount, stored.Status.RenewalCount)
				assert.Nil(t, stored.Status.KubectlDebugStatus, "no target operation may be recorded")
			})
		}
	}
}

// The hard deadline is exclusive: the session is usable strictly before
// status.expiresAt and expired at that instant and after it.
func TestAcceptanceExpiryDeadlineBoundary(t *testing.T) {
	deadline := time.Date(2030, 1, 1, 12, 0, 0, 0, time.UTC)
	session := newActiveKubectlDebugSession("boundary", "owner", deadline)
	for _, tc := range []struct {
		name    string
		now     time.Time
		expired bool
	}{
		{"just before", deadline.Add(-time.Nanosecond), false},
		{"at the deadline", deadline, true},
		{"just after", deadline.Add(time.Nanosecond), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expired, isDebugSessionExpired(session, tc.now))
		})
	}

	idleSession := newActiveKubectlDebugSession("idle-boundary", "owner", deadline.Add(24*time.Hour))
	activity := metav1.NewTime(deadline.Add(-5 * time.Minute))
	idleSession.Status.LastActivity = &activity
	idleSession.Status.ResolvedTemplate.Constraints = &breakglassv1alpha1.DebugSessionConstraints{IdleTimeout: "5m"}
	for _, tc := range []struct {
		name    string
		now     time.Time
		expired bool
	}{
		{"idle just before", deadline.Add(-time.Nanosecond), false},
		{"idle at the deadline", deadline, true},
		{"idle just after", deadline.Add(time.Nanosecond), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expired, isDebugSessionExpired(idleSession, tc.now))
			assert.Equal(t, tc.expired, breakglass.DebugSessionIdleExpired(idleSession, tc.now))
		})
	}
}

// A renewal may land exactly on startsAt+maxDuration but not a second later,
// and an elapsed deadline cannot be renewed.
func TestAcceptanceRenewMaxDurationBoundary(t *testing.T) {
	newSession := func(expiresIn time.Duration) *breakglassv1alpha1.DebugSession {
		start := time.Now().Add(-10 * time.Minute).Truncate(time.Second)
		session := newActiveKubectlDebugSession("renew-bound", "owner", time.Now().Add(expiresIn).Truncate(time.Second))
		startsAt := metav1.NewTime(start)
		session.Status.StartsAt = &startsAt
		session.Status.ResolvedTemplate.Constraints = &breakglassv1alpha1.DebugSessionConstraints{MaxDuration: "2h"}
		expires := metav1.NewTime(start.Add(time.Hour))
		if expiresIn <= 0 {
			expires = metav1.NewTime(time.Now().Add(expiresIn).Truncate(time.Second))
		}
		session.Status.ExpiresAt = &expires
		return session
	}
	renew := func(session *breakglassv1alpha1.DebugSession, extendBy string) (*httptest.ResponseRecorder, *breakglassv1alpha1.DebugSession) {
		_, ctrl := setupTestRouter(t, session)
		router := setupAuthenticatedDebugSessionRouter(t, ctrl, "owner", "", nil)
		w := acceptancePost(router, "/api/debugSessions/renew-bound/renew", `{"extendBy":"`+extendBy+`"}`)
		var stored breakglassv1alpha1.DebugSession
		require.NoError(t, ctrl.client.Get(context.Background(), client.ObjectKeyFromObject(session), &stored))
		return w, &stored
	}

	session := newSession(time.Hour)
	w, stored := renew(session, "1h") // expiresAt = startsAt+1h, so +1h lands exactly on startsAt+2h
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.True(t, stored.Status.ExpiresAt.Time.Equal(session.Status.StartsAt.Add(2*time.Hour)))

	session = newSession(time.Hour)
	w, stored = renew(session, "1h1s")
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	assert.True(t, stored.Status.ExpiresAt.Equal(session.Status.ExpiresAt))
	assert.Zero(t, stored.Status.RenewalCount)

	session = newSession(-time.Second)
	w, stored = renew(session, "1m")
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
	assert.True(t, stored.Status.ExpiresAt.Equal(session.Status.ExpiresAt))
}

// Renew, terminate and the reconciler's expiry write race on one session. The
// optimistic lock plus terminal-state monotonicity must leave exactly one
// terminal outcome, and a later renewal can never revive it.
func TestAcceptanceConcurrentRenewTerminateExpire(t *testing.T) {
	for i := 0; i < 25; i++ {
		session := newActiveKubectlDebugSession("race", "owner", time.Now().Add(time.Hour).Truncate(time.Second))
		session.UID = "race-uid"
		session.ResourceVersion = ""
		_, ctrl := setupTestRouter(t, session)
		router := setupAuthenticatedDebugSessionRouter(t, ctrl, "owner", "", nil)

		var wg sync.WaitGroup
		var renewCode, terminateCode int
		var expireErr error
		start := make(chan struct{})
		wg.Add(3)
		go func() {
			defer wg.Done()
			<-start
			renewCode = acceptancePost(router, "/api/debugSessions/race/renew", `{"extendBy":"1h"}`).Code
		}()
		go func() {
			defer wg.Done()
			<-start
			terminateCode = acceptancePost(router, "/api/debugSessions/race/terminate", ``).Code
		}()
		go func() {
			defer wg.Done()
			<-start
			live := &breakglassv1alpha1.DebugSession{}
			if err := ctrl.client.Get(context.Background(), client.ObjectKeyFromObject(session), live); err != nil {
				expireErr = err
				return
			}
			expireErr = breakglass.PatchDebugSessionStatusWithOptimisticLock(context.Background(), ctrl.client, live, func(s *breakglassv1alpha1.DebugSessionStatus) {
				s.State = breakglassv1alpha1.DebugSessionStateExpired
				s.Message = "Session expired"
			})
		}()
		close(start)
		wg.Wait()

		var final breakglassv1alpha1.DebugSession
		require.NoError(t, ctrl.client.Get(context.Background(), client.ObjectKeyFromObject(session), &final))
		terminated := terminateCode == http.StatusOK
		expired := expireErr == nil
		// Terminate and expire both move Active to a terminal state from the same
		// resourceVersion, so at most one of them can win.
		assert.False(t, terminated && expired, "iteration %d: terminate and expire both committed", i)
		switch final.Status.State {
		case breakglassv1alpha1.DebugSessionStateTerminated:
			assert.True(t, terminated, "iteration %d: terminated without a 200", i)
		case breakglassv1alpha1.DebugSessionStateExpired:
			assert.True(t, expired, "iteration %d: expired without a committed write", i)
		case breakglassv1alpha1.DebugSessionStateActive:
			// Both writers lost to a successful renewal; still a single coherent state.
			assert.Equal(t, http.StatusOK, renewCode, "iteration %d: active without a renewal win", i)
			assert.False(t, terminated || expired)
		default:
			t.Fatalf("iteration %d: unexpected state %q", i, final.Status.State)
		}
		assert.LessOrEqual(t, final.Status.RenewalCount, int32(1))

		if final.Status.State != breakglassv1alpha1.DebugSessionStateActive {
			before := final.Status.ExpiresAt.DeepCopy()
			w := acceptancePost(router, "/api/debugSessions/race/renew", `{"extendBy":"1h"}`)
			assert.GreaterOrEqual(t, w.Code, 400, "iteration %d: renewal after the terminal state must fail", i)
			require.NoError(t, ctrl.client.Get(context.Background(), client.ObjectKeyFromObject(session), &final))
			assert.True(t, final.Status.ExpiresAt.Equal(before), "iteration %d: renewal after the terminal state moved the deadline", i)
			assert.True(t, final.Status.State != breakglassv1alpha1.DebugSessionStateActive)
		}
	}
}
