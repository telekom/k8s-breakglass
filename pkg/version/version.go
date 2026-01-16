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

// GetBuildInfo returns build metadata
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
