// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package quotas

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func testStore(t *testing.T) Store {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	return Store{Client: c, Reader: c, Namespace: "controller"}
}
func noLegacy(context.Context, map[string]Entry) ([]Entry, error) { return nil, nil }
func alwaysLive(context.Context, Entry) (bool, error)             { return true, nil }
func claimant(uid string) Entry {
	return Entry{Kind: "Session", Namespace: "sessions", Name: uid, UID: uid, Scopes: []string{"global-user", "total"}}
}

func TestDurableReservationAcrossReplicasAndRestart(t *testing.T) {
	store := testStore(t)
	var wg sync.WaitGroup
	start := make(chan struct{})
	result := make(chan struct {
		entry Entry
		err   error
	}, 2)
	for _, uid := range []string{"one", "two"} {
		entry := claimant(uid)
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			err := store.Reserve(t.Context(), entry, map[string]int32{"total": 1}, noLegacy, alwaysLive)
			result <- struct {
				entry Entry
				err   error
			}{entry, err}
		}()
	}
	close(start)
	wg.Wait()
	close(result)
	var winner, loser Entry
	for r := range result {
		if r.err == nil {
			require.Empty(t, winner.UID)
			winner = r.entry
		} else {
			require.ErrorIs(t, r.err, ErrFull)
			loser = r.entry
		}
	}
	require.NotEmpty(t, winner.UID)
	require.NotEmpty(t, loser.UID)
	// An unrelated worker/process retry cannot expire a committed reservation.
	restarted := Store{Client: store.Client, Reader: store.Reader, Namespace: store.Namespace}
	require.NoError(t, restarted.Reserve(t.Context(), winner, map[string]int32{"total": 0}, noLegacy, alwaysLive))
	require.ErrorIs(t, restarted.Reserve(t.Context(), loser, map[string]int32{"total": 1}, noLegacy, alwaysLive), ErrFull)
	live := func(_ context.Context, e Entry) (bool, error) { return e.UID != winner.UID, nil }
	require.NoError(t, restarted.Reserve(t.Context(), loser, map[string]int32{"total": 1}, noLegacy, live))
}

func TestReservationUsesAllScopesAndHeterogeneousLimits(t *testing.T) {
	store := testStore(t)
	for _, uid := range []string{"a", "b", "c"} {
		require.NoError(t, store.Reserve(t.Context(), claimant(uid), map[string]int32{"global-user": 3}, noLegacy, alwaysLive))
	}
	// Removing a low-order reservation does not let a stricter limit use a hole.
	live := func(_ context.Context, e Entry) (bool, error) { return e.UID != "a", nil }
	require.ErrorIs(t, store.Reserve(t.Context(), claimant("d"), map[string]int32{"global-user": 2, "total": 100}, noLegacy, live), ErrFull)
	require.NoError(t, store.Reserve(t.Context(), claimant("d"), map[string]int32{"global-user": 3, "total": 100}, noLegacy, live))
}

type failingCAS struct{ client.Client }

func (c failingCAS) Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	return apierrors.NewAlreadyExists(schema.GroupResource{Resource: "configmaps"}, obj.GetName())
}
func (c failingCAS) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	return apierrors.NewConflict(schema.GroupResource{Resource: "configmaps"}, obj.GetName(), errors.New("concurrent writer"))
}
func TestReservationCASExhaustionNeverSucceeds(t *testing.T) {
	for _, exists := range []bool{false, true} {
		t.Run(map[bool]string{false: "already-exists", true: "conflict"}[exists], func(t *testing.T) {
			store := testStore(t)
			if exists {
				require.NoError(t, store.Reserve(t.Context(), claimant("seed"), map[string]int32{}, noLegacy, alwaysLive))
			}
			store.Client = failingCAS{Client: store.Client}
			err := store.Reserve(t.Context(), claimant("candidate"), map[string]int32{"total": 10}, noLegacy, alwaysLive)
			require.ErrorContains(t, err, "CAS retries exhausted")
		})
	}
}

func TestReservationNeverPrunesFromMissingOrStaleBootstrap(t *testing.T) {
	store := testStore(t)
	old := claimant("old")
	require.NoError(t, store.Reserve(t.Context(), old, map[string]int32{"total": 1}, noLegacy, alwaysLive))
	// An empty list does not prove deletion of an extant UID.
	require.ErrorIs(t, store.Reserve(t.Context(), claimant("new"), map[string]int32{"total": 1}, noLegacy, alwaysLive), ErrFull)
	// Conversely, a stale list cannot revive a UID proved terminal by live GET.
	stale := func(context.Context, map[string]Entry) ([]Entry, error) { return []Entry{old}, nil }
	live := func(_ context.Context, e Entry) (bool, error) { return e.UID != "old", nil }
	require.NoError(t, store.Reserve(t.Context(), claimant("new"), map[string]int32{"total": 1}, stale, live))
	// A name reuse cannot revive old reservation identity.
	reused := claimant("replacement")
	reused.Name = "new"
	require.ErrorIs(t, store.Reserve(t.Context(), reused, map[string]int32{"total": 1}, noLegacy, alwaysLive), ErrFull)
}

func TestReservationReadErrorsRetainCapacity(t *testing.T) {
	store := testStore(t)
	old := claimant("old")
	require.NoError(t, store.Reserve(t.Context(), old, map[string]int32{"total": 1}, noLegacy, alwaysLive))
	unavailable := func(context.Context, Entry) (bool, error) { return false, errors.New("API unavailable") }
	require.ErrorContains(t, store.Reserve(t.Context(), claimant("new"), map[string]int32{"total": 1}, noLegacy, unavailable), "API unavailable")
	require.ErrorIs(t, store.Reserve(t.Context(), claimant("new"), map[string]int32{"total": 1}, noLegacy, alwaysLive), ErrFull)
	require.Error(t, store.Reserve(t.Context(), Entry{}, nil, noLegacy, alwaysLive))
}

func readLedger(t *testing.T, store Store) ledger {
	t.Helper()
	cm := &corev1.ConfigMap{}
	require.NoError(t, store.Reader.Get(t.Context(), client.ObjectKey{Namespace: store.Namespace, Name: ledgerName}, cm))
	var state ledger
	require.NoError(t, json.Unmarshal([]byte(cm.Data["ledger"]), &state))
	return state
}

func TestReservationPrunesOnlySaturatedScopes(t *testing.T) {
	store := testStore(t)
	unrelated := claimant("unrelated")
	unrelated.Scopes = []string{"other"}
	require.NoError(t, store.Reserve(t.Context(), unrelated, nil, noLegacy, alwaysLive))
	calls := map[string]int{}
	live := func(_ context.Context, entry Entry) (bool, error) {
		calls[entry.UID]++
		if entry.UID == unrelated.UID {
			return false, errors.New("unrelated API unavailable")
		}
		return true, nil
	}
	require.NoError(t, store.Reserve(t.Context(), claimant("candidate"), map[string]int32{"total": 10}, noLegacy, live))
	require.Equal(t, map[string]int{"candidate": 1}, calls)
	require.Contains(t, readLedger(t, store).Entries, unrelated.UID)
}

func TestReservationPrunesOverlappingScopesOnce(t *testing.T) {
	store := testStore(t)
	// Two scopes each require removing their own expired member. The shared
	// member may be examined in either scope, but never twice in one attempt.
	for _, entry := range []Entry{
		{Kind: "Session", UID: "shared", Scopes: []string{"a", "b"}},
		{Kind: "Session", UID: "expired-a", Scopes: []string{"a"}},
		{Kind: "Session", UID: "expired-b", Scopes: []string{"b"}},
	} {
		require.NoError(t, store.Reserve(t.Context(), entry, nil, noLegacy, alwaysLive))
	}
	calls := map[string]int{}
	live := func(_ context.Context, entry Entry) (bool, error) {
		calls[entry.UID]++
		return !strings.HasPrefix(entry.UID, "expired-"), nil
	}
	candidate := Entry{Kind: "Session", UID: "candidate", Scopes: []string{"a", "b"}}
	require.NoError(t, store.Reserve(t.Context(), candidate, map[string]int32{"a": 2, "b": 2}, noLegacy, live))
	for _, count := range calls {
		require.Equal(t, 1, count)
	}
	state := readLedger(t, store)
	require.Contains(t, state.Entries, "shared")
	require.Contains(t, state.Entries, "candidate")
	require.NotContains(t, state.Entries, "expired-a")
	require.NotContains(t, state.Entries, "expired-b")
	require.ErrorIs(t, store.Reserve(t.Context(), claimant("zero"), map[string]int32{"unused": 0}, noLegacy, alwaysLive), ErrFull)
}

func TestReservationCapacityPrunesUnrelatedKinds(t *testing.T) {
	for _, outcome := range []string{"terminal", "live", "unreadable"} {
		t.Run(outcome, func(t *testing.T) {
			store := testStore(t)
			old := Entry{Kind: "DebugSession", Namespace: "debug", Name: "old", UID: "old", Scopes: []string{strings.Repeat("x", 400*1024)}}
			require.NoError(t, store.Reserve(t.Context(), old, nil, noLegacy, alwaysLive))
			candidate := claimant("candidate")
			candidate.Scopes = []string{strings.Repeat("y", 150*1024)}
			calls := map[string]int{}
			live := func(_ context.Context, entry Entry) (bool, error) {
				calls[entry.UID]++
				if entry.UID == "old" {
					if outcome == "unreadable" {
						return false, errors.New("API unavailable")
					}
					return outcome == "live", nil
				}
				return true, nil
			}
			err := store.Reserve(t.Context(), candidate, nil, noLegacy, live)
			state := readLedger(t, store)
			if outcome == "terminal" {
				require.NoError(t, err)
				require.Contains(t, state.Entries, candidate.UID)
				require.NotContains(t, state.Entries, old.UID)
			} else {
				require.Error(t, err)
				require.Contains(t, state.Entries, old.UID)
				require.NotContains(t, state.Entries, candidate.UID)
			}
			require.Equal(t, map[string]int{"old": 1, "candidate": 1}, calls)
		})
	}
}

func TestReservationCapacityPruningContinuesAfterUnreadableReservation(t *testing.T) {
	store := testStore(t)
	entries := map[string]Entry{}
	for _, uid := range []string{"first", "second"} {
		entries[uid] = Entry{Kind: "DebugSession", Namespace: "debug", Name: uid, UID: uid, Scopes: []string{strings.Repeat("x", 240*1024)}}
	}
	data, err := json.Marshal(ledger{Version: 1, Entries: entries})
	require.NoError(t, err)
	require.NoError(t, store.Client.Create(t.Context(), &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: ledgerName, Namespace: store.Namespace},
		Data:       map[string]string{"ledger": string(data)},
	}))
	var reads []string
	live := func(_ context.Context, entry Entry) (bool, error) {
		if entry.UID == "candidate" {
			return true, nil
		}
		reads = append(reads, entry.UID)
		if len(reads) == 1 {
			return false, errors.New("reservation GET unavailable")
		}
		return false, nil
	}
	candidate := claimant("candidate")
	candidate.Scopes = []string{strings.Repeat("y", 50*1024)}
	require.NoError(t, store.Reserve(t.Context(), candidate, nil, noLegacy, live))
	// One existing entry is unreadable and remains occupied; the other is
	// terminal and must be pruned so the candidate fits under the size bound.
	require.Len(t, reads, 2)
	state := readLedger(t, store)
	require.Contains(t, state.Entries, reads[0])
	require.NotContains(t, state.Entries, reads[1])
	require.Contains(t, state.Entries, candidate.UID)
}

type competingQuotaWriter struct {
	client.Client
	competing Entry
	injected  bool
}

func (c *competingQuotaWriter) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	if !c.injected {
		c.injected = true
		cm := &corev1.ConfigMap{}
		if err := c.Client.Get(ctx, client.ObjectKeyFromObject(obj), cm); err != nil {
			return err
		}
		var state ledger
		if err := json.Unmarshal([]byte(cm.Data["ledger"]), &state); err != nil {
			return err
		}
		state.Entries[c.competing.UID] = c.competing
		data, err := json.Marshal(state)
		if err != nil {
			return err
		}
		cm.Data["ledger"] = string(data)
		if err := c.Client.Update(ctx, cm); err != nil {
			return err
		}
		return apierrors.NewConflict(schema.GroupResource{Resource: "configmaps"}, obj.GetName(), errors.New("competitor committed"))
	}
	return c.Client.Update(ctx, obj, opts...)
}
func TestLazyPruneCASRetryPreservesConcurrentReservation(t *testing.T) {
	store := testStore(t)
	require.NoError(t, store.Reserve(t.Context(), claimant("expired"), nil, noLegacy, alwaysLive))
	writer := &competingQuotaWriter{Client: store.Client, competing: claimant("competitor")}
	store.Client = writer
	calls := map[string]int{}
	live := func(_ context.Context, entry Entry) (bool, error) {
		calls[entry.UID]++
		return entry.UID != "expired", nil
	}
	require.ErrorIs(t, store.Reserve(t.Context(), claimant("candidate"), map[string]int32{"total": 1}, noLegacy, live), ErrFull)
	state := readLedger(t, store)
	require.Contains(t, state.Entries, "competitor")
	require.NotContains(t, state.Entries, "candidate")
	require.Equal(t, 2, calls["candidate"], "candidate must be rechecked after CAS conflict")
	require.Equal(t, 1, calls["competitor"])
}

func TestLazyPruneStillValidatesLedgerUIDs(t *testing.T) {
	store := testStore(t)
	data, err := json.Marshal(ledger{Version: 1, Entries: map[string]Entry{"wrong-key": claimant("old")}})
	require.NoError(t, err)
	require.NoError(t, store.Client.Create(t.Context(), &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: ledgerName, Namespace: store.Namespace}, Data: map[string]string{"ledger": string(data)}}))
	require.ErrorContains(t, store.Reserve(t.Context(), claimant("candidate"), nil, noLegacy, alwaysLive), "invalid quota ledger UID")
}

func TestLazyPruneContinuesAfterUnreadableReservation(t *testing.T) {
	store := testStore(t)
	for _, uid := range []string{"first", "second"} {
		require.NoError(t, store.Reserve(t.Context(), claimant(uid), nil, noLegacy, alwaysLive))
	}
	var reads []string
	live := func(_ context.Context, entry Entry) (bool, error) {
		if entry.UID == "candidate" {
			return true, nil
		}
		reads = append(reads, entry.UID)
		if len(reads) == 1 {
			return false, errors.New("reservation GET unavailable")
		}
		return false, nil
	}
	require.NoError(t, store.Reserve(t.Context(), claimant("candidate"), map[string]int32{"total": 2}, noLegacy, live))
	// Whichever entry the map iteration examines first is unreadable; the
	// other is terminal. Both must be checked so the terminal slot can be freed.
	require.Len(t, reads, 2)
	state := readLedger(t, store)
	require.Contains(t, state.Entries, reads[0])
	require.NotContains(t, state.Entries, reads[1])
	require.Contains(t, state.Entries, "candidate")
}

func TestLazyPruneDoesNotFreeUnreadableReservation(t *testing.T) {
	store := testStore(t)
	old := claimant("old")
	require.NoError(t, store.Reserve(t.Context(), old, nil, noLegacy, alwaysLive))
	live := func(_ context.Context, entry Entry) (bool, error) {
		if entry.UID == old.UID {
			return false, errors.New("reservation GET unavailable")
		}
		return true, nil
	}
	require.ErrorContains(t, store.Reserve(t.Context(), claimant("candidate"), map[string]int32{"total": 1}, noLegacy, live), "reservation GET unavailable")
	state := readLedger(t, store)
	require.Contains(t, state.Entries, old.UID)
	require.NotContains(t, state.Entries, "candidate")
}
