// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEffectiveDebugSessionMOTD(t *testing.T) {
	templateMOTD := &MessageOfTheDay{Message: "template", RunbookURL: "https://example.com/runbook#template"}
	bindingMOTD := &MessageOfTheDay{Message: "binding"}
	template := &DebugSessionTemplateSpec{MOTD: templateMOTD}

	require.Nil(t, EffectiveDebugSessionMOTD(nil, nil))
	require.Same(t, templateMOTD, EffectiveDebugSessionMOTD(template, nil))
	require.Same(t, templateMOTD, EffectiveDebugSessionMOTD(template, &DebugSessionClusterBindingSpec{}))
	require.Same(t, bindingMOTD, EffectiveDebugSessionMOTD(template, &DebugSessionClusterBindingSpec{MOTD: bindingMOTD}),
		"a binding MOTD replaces the template MOTD instead of merging runbook links")
	require.Same(t, bindingMOTD, EffectiveDebugSessionMOTD(nil, &DebugSessionClusterBindingSpec{MOTD: bindingMOTD}))
}
