package apiresponses

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestErrorHelpersShareOneSchema asserts that every error helper writes the
// same body: the unchanged error text, a machine-readable code and the
// request correlation ID.
func TestErrorHelpersShareOneSchema(t *testing.T) {
	tests := []struct {
		name    string
		respond func(*gin.Context)
		status  int
		code    string
		message string
		details string
	}{
		{"not found", func(c *gin.Context) { RespondNotFound(c, "session", "s1") }, http.StatusNotFound, "NOT_FOUND", "session not found: s1", ""},
		{"not found simple", func(c *gin.Context) { RespondNotFoundSimple(c, "gone") }, http.StatusNotFound, "NOT_FOUND", "gone", ""},
		{"unauthorized", RespondUnauthorized, http.StatusUnauthorized, "UNAUTHORIZED", "user not authenticated", ""},
		{"unauthorized message", func(c *gin.Context) { RespondUnauthorizedWithMessage(c, "bad token") }, http.StatusUnauthorized, "UNAUTHORIZED", "bad token", ""},
		{"forbidden", func(c *gin.Context) { RespondForbidden(c, "") }, http.StatusForbidden, "FORBIDDEN", "access denied", ""},
		{"bad request", func(c *gin.Context) { RespondBadRequest(c, "bad") }, http.StatusBadRequest, "BAD_REQUEST", "bad", ""},
		{"bad request details", func(c *gin.Context) { RespondBadRequestWithDetails(c, "bad", "a; b") }, http.StatusBadRequest, "BAD_REQUEST", "bad", "a; b"},
		{"conflict", func(c *gin.Context) { RespondConflict(c, "busy") }, http.StatusConflict, "CONFLICT", "busy", ""},
		{"internal", func(c *gin.Context) { RespondInternalError(c, "get x", errors.New("boom"), nil) }, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to get x", ""},
		{"internal simple", func(c *gin.Context) { RespondInternalErrorSimple(c, "oops") }, http.StatusInternalServerError, "INTERNAL_ERROR", "oops", ""},
		{"too many", func(c *gin.Context) { RespondTooManyRequests(c, "") }, http.StatusTooManyRequests, "TOO_MANY_REQUESTS", "too many requests", ""},
		{"too many retry", func(c *gin.Context) { RespondTooManyRequestsWithRetryAfter(c, "1", "slow") }, http.StatusTooManyRequests, "TOO_MANY_REQUESTS", "slow", ""},
		{"bad gateway", func(c *gin.Context) { RespondBadGateway(c, "") }, http.StatusBadGateway, "BAD_GATEWAY", "bad gateway", ""},
		{"unavailable", func(c *gin.Context) { RespondServiceUnavailable(c, "idp") }, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "service unavailable: idp", ""},
		{"unprocessable", func(c *gin.Context) { RespondUnprocessableEntity(c, "nope") }, http.StatusUnprocessableEntity, "UNPROCESSABLE_ENTITY", "nope", ""},
		{"generic gone", func(c *gin.Context) { RespondError(c, http.StatusGone, "expired", "") }, http.StatusGone, "GONE", "expired", ""},
		{"generic too large", func(c *gin.Context) { RespondError(c, http.StatusRequestEntityTooLarge, "big", "") }, http.StatusRequestEntityTooLarge, "PAYLOAD_TOO_LARGE", "big", ""},
		{"generic path", func(c *gin.Context) { RespondError(c, http.StatusNotFound, "API endpoint not found", "/api/x") }, http.StatusNotFound, "NOT_FOUND", "API endpoint not found", "/api/x"},
	}
	for _, tt := range tests {
		for _, withCID := range []bool{true, false} {
			name := tt.name + "/generated cid"
			if withCID {
				name = tt.name + "/request cid"
			}
			t.Run(name, func(t *testing.T) {
				w := httptest.NewRecorder()
				c, _ := gin.CreateTestContext(w)
				c.Request = httptest.NewRequest(http.MethodGet, "/api/x", nil)
				if withCID {
					c.Set(CIDKey, "cid-123")
				}

				tt.respond(c)

				require.Equal(t, tt.status, w.Code)
				var raw map[string]any
				require.NoError(t, json.Unmarshal(w.Body.Bytes(), &raw))
				assert.Equal(t, tt.message, raw["error"])
				assert.Equal(t, tt.code, raw["code"])
				cid, _ := raw["cid"].(string)
				require.NotEmpty(t, cid, "cid must always be present")
				if withCID {
					assert.Equal(t, "cid-123", cid)
				} else {
					assert.Equal(t, cid, w.Header().Get(RequestIDHeader), "generated cid must be echoed in the response header")
				}
				if tt.details == "" {
					assert.NotContains(t, raw, "details")
				} else {
					assert.Equal(t, tt.details, raw["details"])
				}
			})
		}
	}
}

func TestNewErrorEmbedsExtraFields(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Set(CIDKey, "cid-9")

	c.JSON(http.StatusConflict, struct {
		APIError
		Candidates []string `json:"candidates"`
	}{NewError(c, "AMBIGUOUS_ESCALATION", "pick one"), []string{"a", "b"}})

	var raw map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &raw))
	assert.Equal(t, map[string]any{"error": "pick one", "code": "AMBIGUOUS_ESCALATION", "cid": "cid-9", "candidates": []any{"a", "b"}}, raw)
}

func TestCodeForStatus(t *testing.T) {
	assert.Equal(t, "ERROR", CodeForStatus(http.StatusTeapot))
	assert.Equal(t, "INTERNAL_ERROR", CodeForStatus(http.StatusGatewayTimeout))
}
