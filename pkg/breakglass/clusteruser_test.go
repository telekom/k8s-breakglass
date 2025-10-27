package breakglass

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestClusterUserGroup_JSONMapping(t *testing.T) {
	valid := `{"cluster":"c1","user":"alice","group":"admins"}`
	var cg ClusterUserGroup
	err := json.Unmarshal([]byte(valid), &cg)
	require.NoError(t, err)
	require.Equal(t, "c1", cg.Clustername)
	require.Equal(t, "alice", cg.Username)
	require.Equal(t, "admins", cg.GroupName)

	// Missing group should produce empty GroupName
	missing := `{"cluster":"c2","user":"bob"}`
	var cg2 ClusterUserGroup
	err = json.Unmarshal([]byte(missing), &cg2)
	require.NoError(t, err)
	require.Equal(t, "", cg2.GroupName)

	// Extra fields should be ignored
	extra := `{"cluster":"c3","user":"eve","group":"ops","extra":"x"}`
	var cg3 ClusterUserGroup
	err = json.Unmarshal([]byte(extra), &cg3)
	require.NoError(t, err)
	require.Equal(t, "ops", cg3.GroupName)
}

func TestBreakglassSessionRequest_JSONMapping(t *testing.T) {
	valid := `{"cluster":"c1","user":"alice","group":"admins","reason":"need access"}`
	var req BreakglassSessionRequest
	err := json.Unmarshal([]byte(valid), &req)
	require.NoError(t, err)
	require.Equal(t, "c1", req.Clustername)
	require.Equal(t, "alice", req.Username)
	require.Equal(t, "admins", req.GroupName)
	require.Equal(t, "need access", req.Reason)

	// Empty JSON should succeed but fields empty
	var empty BreakglassSessionRequest
	err = json.Unmarshal([]byte(`{}`), &empty)
	require.NoError(t, err)
	require.Equal(t, "", empty.Clustername)
	require.Equal(t, "", empty.Username)
	require.Equal(t, "", empty.GroupName)
}
