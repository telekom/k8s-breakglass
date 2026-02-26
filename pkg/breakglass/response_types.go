package breakglass

// ReasonConfigInfo represents the reason configuration for approvals and requests.
// Shared between root and debug sub-package to avoid import cycles.
type ReasonConfigInfo struct {
	Mandatory        bool     `json:"mandatory"`
	Description      string   `json:"description,omitempty"`
	MinLength        int32    `json:"minLength,omitempty"`
	MaxLength        int32    `json:"maxLength,omitempty"`
	SuggestedReasons []string `json:"suggestedReasons,omitempty"`
}
