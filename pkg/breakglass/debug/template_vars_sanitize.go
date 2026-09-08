package debug

import (
	"sort"
	"strings"
)

func sanitizeTemplateVarsReportingChanges(vars map[string]string) (map[string]string, []string) {
	changed := make([]string, 0)
	for name, value := range vars {
		sanitized := strings.NewReplacer("\r\n", " ", "\n", " ", "\r", " ", "\u0085", " ", "\u2028", " ", "\u2029", " ").Replace(value)
		if strings.HasPrefix(sanitized, "---") || strings.HasPrefix(sanitized, "...") {
			sanitized = " " + sanitized
		}
		if sanitized != value {
			vars[name] = sanitized
			changed = append(changed, name)
		}
	}
	sort.Strings(changed)
	return vars, changed
}
