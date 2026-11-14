//go:build e2e_ha

// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"context"
	"os"

	"go.uber.org/zap"
)

// holdCleanupAcknowledgementClaim is e2e fault injection, compiled only with
// the e2e_ha build tag: the first claimant of the acknowledgement named by
// BREAKGLASS_E2E_HOLD_CLEANUP_ACKNOWLEDGEMENT_CLAIM stalls until its context
// ends, so the HA e2e test can kill the claim holder while the
// acknowledgement is Processing.
func holdCleanupAcknowledgementClaim(ctx context.Context, log *zap.SugaredLogger, name string) bool {
	if hold := os.Getenv("BREAKGLASS_E2E_HOLD_CLEANUP_ACKNOWLEDGEMENT_CLAIM"); hold == "" || hold != name {
		return false
	}
	log.Warnw("e2e fault injection: holding cleanup acknowledgement claim", "acknowledgement", name, "pod", os.Getenv("HOSTNAME"))
	<-ctx.Done()
	return true
}
