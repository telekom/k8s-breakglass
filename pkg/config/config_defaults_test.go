// SPDX-FileCopyrightText: 2025 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDefaultConfigSecureDefaults(t *testing.T) {
	var cfg Config
	// Zero value config should be secure: insecure skip flags must be false
	assert.False(t, cfg.Mail.InsecureSkipVerify, "mail.InsecureSkipVerify should be false by default")
	assert.False(t, cfg.AuthorizationServer.InsecureSkipVerify, "authorizationServer.InsecureSkipVerify should be false by default")
}
