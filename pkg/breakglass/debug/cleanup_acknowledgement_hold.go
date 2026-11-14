//go:build !e2e_ha

// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"context"

	"go.uber.org/zap"
)

// holdCleanupAcknowledgementClaim never holds: the fault injection exists
// only in e2e_ha builds (cleanup_acknowledgement_hold_e2e.go).
func holdCleanupAcknowledgementClaim(context.Context, *zap.SugaredLogger, string) bool { return false }
