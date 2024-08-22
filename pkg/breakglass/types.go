package breakglass

import "gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/pkg/config"

type BreakglassApprovalRequest struct {
	Token string `json:"token" binding:"required"`
}

type BreakglassState struct {
	Group  string `json:"group"`
	Expiry int64  `json:"expiry"`
}

type BreakglassRequestRequest struct {
	Transition config.Transition `json:"transition"`
}

type PermissionRequest struct {
	UserName    string `json:"user_name" binding:"required"`
	ClusterName string `json:"cluster_name" binding:"required"`
}
