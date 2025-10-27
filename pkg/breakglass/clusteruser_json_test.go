package breakglass

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

// Test that providing a wrong JSON type for string fields results in an error.
func TestClusterUserGroup_JSONTypeMismatch(t *testing.T) {
	// cluster is a number, but struct expects string -> should error
	bad := `{"cluster":123,"user":"alice","group":"admins"}`
	var cg ClusterUserGroup
	err := json.Unmarshal([]byte(bad), &cg)
	require.Error(t, err)
}

// Round-trip marshal/unmarshal for ClusterUserGroup and BreakglassSessionRequest.
func TestClusterUserGroup_RoundTripJSON(t *testing.T) {
	orig := ClusterUserGroup{
		Clustername: "round-1",
		Username:    "tester@example.com",
		GroupName:   "round-group",
	}

	b, err := json.Marshal(&orig)
	require.NoError(t, err)

	var got ClusterUserGroup
	err = json.Unmarshal(b, &got)
	require.NoError(t, err)
	require.Equal(t, orig.Clustername, got.Clustername)
	require.Equal(t, orig.Username, got.Username)
	require.Equal(t, orig.GroupName, got.GroupName)
}

func TestBreakglassSessionRequest_RoundTripJSON(t *testing.T) {
	orig := BreakglassSessionRequest{
		Clustername: "rc-1",
		Username:    "req@example.com",
		GroupName:   "admins",
		Reason:      "unit test",
	}

	b, err := json.Marshal(&orig)
	require.NoError(t, err)

	var got BreakglassSessionRequest
	err = json.Unmarshal(b, &got)
	require.NoError(t, err)
	require.Equal(t, orig.Clustername, got.Clustername)
	require.Equal(t, orig.Username, got.Username)
	require.Equal(t, orig.GroupName, got.GroupName)
	require.Equal(t, orig.Reason, got.Reason)
}
