package breakglass

import "go.uber.org/zap"

// nopLogger is a cached no-op logger used as a fallback when a component's logger
// has not been initialized (e.g., during tests or before dependency injection).
var nopLogger = zap.NewNop().Sugar()

// getLoggerOrDefault returns the first non-nil logger from the variadic args,
// falling back to the global zap.S() logger. This eliminates the repeated
// if-len-check pattern across constructors.
func getLoggerOrDefault(log ...*zap.SugaredLogger) *zap.SugaredLogger {
	for _, l := range log {
		if l != nil {
			return l
		}
	}
	return zap.S()
}
