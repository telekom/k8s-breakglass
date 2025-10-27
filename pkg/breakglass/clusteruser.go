package breakglass

type ClusterUserGroup struct {
	Clustername string `json:"cluster,omitempty"`
	Username    string `json:"user,omitempty"`
	// NOTE: previously json tag was `clustergroup` which did not match request body key `groupname`
	// causing empty GroupName and 422 on session requests. Aligning tag with request payload.
	// API now expects key `group` instead of `groupname`.
	GroupName string `json:"group,omitempty"`
}

// BreakglassSessionRequest is the expected payload when requesting a session via the API.
type BreakglassSessionRequest struct {
	Clustername string `json:"cluster,omitempty"`
	Username    string `json:"user,omitempty"`
	GroupName   string `json:"group,omitempty"`
	// Reason is an optional free-text field supplied by the requester. Its requirement and description
	// are driven by the escalation's RequestReason configuration.
	Reason string `json:"reason,omitempty"`
}
