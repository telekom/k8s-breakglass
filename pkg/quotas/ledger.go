// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

// Package quotas implements durable session admission with API-server CAS.
package quotas

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const AdmissionAnnotation = "breakglass.t-caas.telekom.com/quota-admission"
const Pending = "pending"
const Ready = "ready"
const ledgerName = "breakglass-session-quota-v1"
const maxLedgerBytes = 512 * 1024

var ErrFull = errors.New("session quota reached")

// Entry identifies an immutable session and every quota population it occupies.
type Entry struct {
	Kind      string   `json:"kind"`
	Namespace string   `json:"namespace"`
	Name      string   `json:"name"`
	UID       string   `json:"uid"`
	Scopes    []string `json:"scopes"`
}

type ledger struct {
	Version int              `json:"version"`
	Entries map[string]Entry `json:"entries"`
}

// Store uses one bounded ledger for all scopes, so multi-scope admission is one
// atomic CAS. Entries never expire with worker lifetime. Namespace must be the
// same configured controller namespace for every API and lifecycle replica.
// Higher capacity requires coordinating reservations across shards.
type Store struct {
	Client    client.Client
	Reader    client.Reader
	Namespace string
}

// Reserve bootstraps legacy sessions and prunes entries only after Live proves
// that their exact UID is terminal/deleted. Unknown or failed reads retain slots.
// Existing reservations are grandfathered when policy limits are tightened.
func (s Store) Reserve(ctx context.Context, candidate Entry, limits map[string]int32,
	bootstrap func(context.Context, map[string]Entry) ([]Entry, error), live func(context.Context, Entry) (bool, error)) error {
	if s.Reader == nil || s.Namespace == "" || candidate.UID == "" {
		return fmt.Errorf("quota admission requires live reader, controller namespace, and session UID")
	}
	key := client.ObjectKey{Namespace: s.Namespace, Name: ledgerName}
	for attempt := 0; attempt < 12; attempt++ {
		cm := &corev1.ConfigMap{}
		getErr := s.Reader.Get(ctx, key, cm)
		if apierrors.IsNotFound(getErr) {
			cm = &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: key.Name, Namespace: key.Namespace}}
		} else if getErr != nil {
			return fmt.Errorf("read quota ledger: %w", getErr)
		}
		state := ledger{Version: 1, Entries: map[string]Entry{}}
		if raw := cm.Data["ledger"]; raw != "" {
			if err := json.Unmarshal([]byte(raw), &state); err != nil {
				return fmt.Errorf("decode quota ledger: %w", err)
			}
			if state.Version != 1 || state.Entries == nil {
				return fmt.Errorf("unsupported quota ledger schema")
			}
		}
		for uid, entry := range state.Entries {
			if uid != entry.UID || uid == "" {
				return fmt.Errorf("invalid quota ledger UID")
			}
		}
		// Reuse exact-UID probes only within this CAS attempt. A retry starts
		// with a fresh ledger and fresh authoritative observations.
		probed := map[string]bool{}
		verify := func(entry Entry) (bool, error) {
			if occupied, ok := probed[entry.UID]; ok {
				return occupied, nil
			}
			occupied, err := live(ctx, entry)
			if err == nil {
				probed[entry.UID] = occupied
			}
			return occupied, err
		}
		legacy, err := bootstrap(ctx, state.Entries)
		if err != nil {
			return fmt.Errorf("bootstrap quota ledger: %w", err)
		}
		for _, entry := range legacy {
			if entry.UID == "" {
				return fmt.Errorf("legacy session has no UID")
			}
			if entry.UID != candidate.UID {
				occupied, err := verify(entry)
				if err != nil {
					return fmt.Errorf("verify legacy quota reservation: %w", err)
				}
				if !occupied {
					continue
				}
				if _, exists := state.Entries[entry.UID]; !exists {
					state.Entries[entry.UID] = entry
				}
			}
		}
		occupied, err := verify(candidate)
		if err != nil {
			return fmt.Errorf("verify quota candidate: %w", err)
		}
		if !occupied {
			return fmt.Errorf("quota candidate is terminal or deleted")
		}
		if existing, reserved := state.Entries[candidate.UID]; reserved {
			if existing.Kind != candidate.Kind || existing.Namespace != candidate.Namespace || existing.Name != candidate.Name || !slices.Equal(existing.Scopes, candidate.Scopes) {
				return fmt.Errorf("reserved session identity or quota scopes changed")
			}
		} else {
			for scope, limit := range limits {
				var count int32
				for _, entry := range state.Entries {
					if slices.Contains(entry.Scopes, scope) {
						count++
					}
				}
				// Unchecked records remain occupied. Only a saturated scope
				// needs authoritative reads to recover terminal reservations.
				if count >= limit {
					var verifyErr error
					// An unreadable reservation remains occupied, but it must not
					// prevent checking other entries that may be terminal.
					for uid, entry := range state.Entries {
						if !slices.Contains(entry.Scopes, scope) {
							continue
						}
						occupied, err := verify(entry)
						if err != nil {
							if verifyErr == nil {
								verifyErr = err
							}
							continue
						}
						if !occupied {
							delete(state.Entries, uid)
							count--
						}
						if count < limit {
							break
						}
					}
					if count >= limit && verifyErr != nil {
						return fmt.Errorf("verify quota reservation: %w", verifyErr)
					}
				}
				if count >= limit {
					return fmt.Errorf("%w: limit %d", ErrFull, limit)
				}
			}
			state.Entries[candidate.UID] = candidate
		}
		encoded, err := json.Marshal(state)
		if err != nil {
			return fmt.Errorf("encode quota ledger: %w", err)
		}
		if len(encoded) > maxLedgerBytes {
			// Unrelated terminal entries must not permanently exhaust storage.
			// Global pruning is exceptional and still requires exact-UID proof.
			var verifyErr error
			for uid, entry := range state.Entries {
				occupied, err := verify(entry)
				if err != nil {
					if verifyErr == nil {
						verifyErr = err
					}
					continue
				}
				if !occupied {
					delete(state.Entries, uid)
				}
			}
			encoded, err = json.Marshal(state)
			if err != nil {
				return fmt.Errorf("encode pruned quota ledger: %w", err)
			}
			if len(encoded) > maxLedgerBytes {
				if verifyErr != nil {
					return fmt.Errorf("verify quota capacity reservation: %w", verifyErr)
				}
				return fmt.Errorf("quota ledger capacity reached")
			}
		}
		cm.Data = map[string]string{"ledger": string(encoded)}
		if getErr != nil {
			err = s.Client.Create(ctx, cm)
		} else {
			err = s.Client.Update(ctx, cm)
		}
		if err == nil {
			return nil
		}
		if !apierrors.IsAlreadyExists(err) && !apierrors.IsConflict(err) {
			return fmt.Errorf("write quota reservation: %w", err)
		}
	}
	return fmt.Errorf("quota reservation CAS retries exhausted")
}
