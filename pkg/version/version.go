package version

import (
	"runtime"
	"time"
)

var (
	// Version is the semantic version, injected at build time via -ldflags
	Version = "dev"
	// GitCommit is the git commit hash, injected at build time
	GitCommit = "unknown"
	// BuildDate is the build timestamp, injected at build time
	BuildDate = "unknown"
	// GoVersion is the Go compiler version
	GoVersion = runtime.Version()
	// Platform is the OS/Arch
	Platform = runtime.GOOS + "/" + runtime.GOARCH
)

// BuildInfo contains metadata about the build
type BuildInfo struct {
	Version   string    `json:"version"`
	GitCommit string    `json:"gitCommit"`
	BuildDate string    `json:"buildDate"`
	GoVersion string    `json:"goVersion"`
	Platform  string    `json:"platform"`
	BuildTime time.Time `json:"buildTime,omitempty"`
}

// GetBuildInfo returns full build metadata including infrastructure details.
// Use GetPublicBuildInfo for unauthenticated endpoints to avoid exposing
// Go version, platform, and commit hash that could aid reconnaissance (SEC-008).
func GetBuildInfo() BuildInfo {
	info := BuildInfo{
		Version:   Version,
		GitCommit: GitCommit,
		BuildDate: BuildDate,
		GoVersion: GoVersion,
		Platform:  Platform,
	}

	// Try to parse BuildDate as RFC3339
	if t, err := time.Parse(time.RFC3339, BuildDate); err == nil {
		info.BuildTime = t
	}

	return info
}

// PublicBuildInfo contains only non-sensitive build metadata safe for
// unauthenticated exposure. Go version, platform, and commit hash are
// omitted to prevent infrastructure reconnaissance.
type PublicBuildInfo struct {
	Version   string `json:"version"`
	BuildDate string `json:"buildDate"`
}

// GetPublicBuildInfo returns build metadata safe for unauthenticated endpoints.
// Infrastructure details (Go version, platform, commit hash) are omitted to
// prevent reconnaissance (SEC-008).
func GetPublicBuildInfo() PublicBuildInfo {
	return PublicBuildInfo{
		Version:   Version,
		BuildDate: BuildDate,
	}
}
