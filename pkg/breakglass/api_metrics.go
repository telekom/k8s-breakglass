package breakglass

import (
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/telekom/k8s-breakglass/pkg/metrics"
)

// instrumentedHandler wraps a gin handler to record API metrics consistently.
// It tracks request counts, latency, and error status codes for the provided endpoint label.
func instrumentedHandler(endpoint string, handler gin.HandlerFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		metrics.APIEndpointRequests.WithLabelValues(endpoint).Inc()
		handler(c)
		metrics.APIEndpointDuration.WithLabelValues(endpoint).Observe(time.Since(start).Seconds())
		status := c.Writer.Status()
		if status >= 400 {
			metrics.APIEndpointErrors.WithLabelValues(endpoint, strconv.Itoa(status)).Inc()
		}
	}
}
