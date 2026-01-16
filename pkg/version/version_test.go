package version

import (
	"testing"
	"time"
)

func TestGetBuildInfo(t *testing.T) {
	info := GetBuildInfo()
	if info.Version == "" {
		t.Error("Version should not be empty")
	}
	if info.GitCommit == "" {
		t.Error("GitCommit should not be empty")
	}
	if info.BuildDate == "" {
		t.Error("BuildDate should not be empty")
	}
	if info.GoVersion == "" {
		t.Error("GoVersion should not be empty")
	}
	if info.Platform == "" {
		t.Error("Platform should not be empty")
	}
}

func TestGetBuildInfo_ParsesValidDate(t *testing.T) {
	originalBuildDate := BuildDate
	defer func() { BuildDate = originalBuildDate }()

	validDate := "2026-01-13T20:00:00Z"
	BuildDate = validDate

	info := GetBuildInfo()

	if info.BuildTime.IsZero() {
		t.Error("BuildTime should be parsed from valid RFC3339 date")
	}

	expectedTime, _ := time.Parse(time.RFC3339, validDate)
	if !info.BuildTime.Equal(expectedTime) {
		t.Errorf("BuildTime = %v, want %v", info.BuildTime, expectedTime)
	}
}

func TestDefaultValues(t *testing.T) {
	if GoVersion == "" {
		t.Error("GoVersion should be set by runtime.Version()")
	}
	if Platform == "" {
		t.Error("Platform should be set by runtime.GOOS/GOARCH")
	}
}
