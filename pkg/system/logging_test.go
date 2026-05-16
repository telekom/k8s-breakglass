package system

import (
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func TestGetReqLoggerFallbackWhenContextNil(t *testing.T) {
	fallback := zap.NewNop().Sugar()
	require.Same(t, fallback, GetReqLogger(nil, fallback))
}

func TestGetReqLoggerFromContext(t *testing.T) {
	gin.SetMode(gin.TestMode)
	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	fallback := zap.NewNop().Sugar()
	stored := zap.NewNop().Sugar()
	ctx.Set(ReqLoggerKey, stored)
	require.Same(t, stored, GetReqLogger(ctx, fallback))
}

func TestGetReqLoggerIgnoresInvalidTypes(t *testing.T) {
	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	fallback := zap.NewNop().Sugar()
	ctx.Set(ReqLoggerKey, "not-a-logger")
	require.Same(t, fallback, GetReqLogger(ctx, fallback))
}

func TestEnrichReqLoggerWithAuthAddsFields(t *testing.T) {
	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx.Set("email", "user@example.com")
	ctx.Set("username", "alice")
	ctx.Set("groups", []string{"g1", "g2"})

	core, recorded := observer.New(zap.DebugLevel)
	logger := zap.New(core).Sugar()
	enriched := EnrichReqLoggerWithAuth(ctx, logger)
	enriched.Infow("final-log")

	entries := recorded.All()
	require.Len(t, entries, 2, "expected debug log for groups and final info log")

	infoCtx := entries[1].ContextMap()
	require.Equal(t, "user@example.com", infoCtx["email"])
	require.Equal(t, "alice", infoCtx["username"])
	require.EqualValues(t, 2, infoCtx["groupCount"])
}

func TestEnrichReqLoggerGroupsLoggedWhenRedactionOff(t *testing.T) {
	SetLogRedaction(false)
	defer SetLogRedaction(false)

	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx.Set("groups", []string{"secret-role-admin", "internal-ops"})

	core, recorded := observer.New(zap.DebugLevel)
	logger := zap.New(core).Sugar()
	EnrichReqLoggerWithAuth(ctx, logger)

	entries := recorded.All()
	require.Len(t, entries, 1)

	fields := entries[0].ContextMap()
	groupsVal, hasGroups := fields["groups"]
	require.True(t, hasGroups, "groups field must be present")
	require.NotEqual(t, "[2 items]", groupsVal, "groups should NOT be redacted when redaction is off")
}

func TestEnrichReqLoggerGroupsRedactedWhenEnabled(t *testing.T) {
	SetLogRedaction(true)
	defer SetLogRedaction(false)

	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx.Set("groups", []string{"secret-role-admin", "internal-ops"})

	core, recorded := observer.New(zap.DebugLevel)
	logger := zap.New(core).Sugar()
	EnrichReqLoggerWithAuth(ctx, logger)

	entries := recorded.All()
	require.Len(t, entries, 1)

	fields := entries[0].ContextMap()
	groupsVal, hasGroups := fields["groups"]
	require.True(t, hasGroups, "groups field must be present")
	require.Equal(t, "[2 items]", groupsVal, "groups should be redacted when enabled")
}

func TestEnrichReqLoggerWithAuthHandlesNil(t *testing.T) {
	sugar := zap.NewNop().Sugar()
	require.Same(t, sugar, EnrichReqLoggerWithAuth(nil, sugar))
	require.Nil(t, EnrichReqLoggerWithAuth(&gin.Context{}, nil))
}

func TestNamespacedFields(t *testing.T) {
	require.Equal(t, []interface{}{"name", "obj", "namespace", "ns-1"}, NamespacedFields("obj", "ns-1"))
	require.Equal(t, []interface{}{"name", "obj"}, NamespacedFields("obj", ""))
}

func TestRedactGroupNameOff(t *testing.T) {
	SetLogRedaction(false)
	defer SetLogRedaction(false)

	require.Equal(t, "", RedactGroupName(""))
	require.Equal(t, "admin", RedactGroupName("admin"))
	require.Equal(t, "platform-team", RedactGroupName("platform-team"))
}

func TestRedactGroupNameOn(t *testing.T) {
	SetLogRedaction(true)
	defer SetLogRedaction(false)

	require.Equal(t, "", RedactGroupName(""))
	require.Equal(t, "[REDACTED]", RedactGroupName("a"))
	require.Equal(t, "[REDACTED]", RedactGroupName("admin"))
	require.Equal(t, "[REDACTED]", RedactGroupName("platform-team"))
	require.Equal(t, "[REDACTED]", RedactGroupName("グループ管理者"))
}

func TestRedactSliceOff(t *testing.T) {
	SetLogRedaction(false)
	defer SetLogRedaction(false)

	result := RedactSlice([]string{"a", "b", "c"})
	slice, ok := result.([]string)
	require.True(t, ok, "should return original slice when redaction is off")
	require.Equal(t, []string{"a", "b", "c"}, slice)
}

func TestRedactSliceOn(t *testing.T) {
	SetLogRedaction(true)
	defer SetLogRedaction(false)

	result := RedactSlice([]string{"a", "b", "c"})
	str, ok := result.(string)
	require.True(t, ok, "should return string summary when redaction is on")
	require.Equal(t, "[3 items]", str)
}
