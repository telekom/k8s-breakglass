package config

// StepUp configures fresh, action-bound authentication for critical API
// mutations (PSA PSM-14.47). It is disabled by default; see
// docs/design/step-up-authentication.md.
type StepUp struct {
	// Enabled turns on step-up checks for the configured actions.
	Enabled bool `yaml:"enabled"`
	// MaxAuthAge is the maximum age of the token's auth_time claim, as a Go
	// duration such as "5m". Tokens without auth_time are rejected when set.
	MaxAuthAge string `yaml:"maxAuthAge"`
	// RequiredACR lists the acr claim values that are accepted. Empty means
	// the acr claim is not checked.
	RequiredACR []string `yaml:"requiredACR"`
	// Actions names the critical actions that require step-up. Empty means
	// the default set documented in the design doc.
	Actions []string `yaml:"actions"`
}
