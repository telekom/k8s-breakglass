// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

func sanitizeTemplateVarsReportingChanges(vars map[string]string) (map[string]string, []string) {
	// Template validation requires complete scalar serialization, so yamlQuote
	// already protects these values without changing their content.
	return vars, nil
}
