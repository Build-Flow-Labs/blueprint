package webhook

import (
	"testing"
	"time"

	gh "github.com/build-flow-labs/blueprint/internal/pbom/github"
)

func TestExtractRunner(t *testing.T) {
	tests := []struct {
		name       string
		jobs       []gh.Job
		wantOS     string
		wantArch   string
		wantSelf   bool
		wantName   string
		wantNil    bool
	}{
		{
			name:    "empty jobs",
			jobs:    nil,
			wantNil: true,
		},
		{
			name: "github-hosted ubuntu",
			jobs: []gh.Job{{
				Labels:          []string{"ubuntu-latest"},
				RunnerName:      "GitHub Actions 42",
				RunnerGroupName: "GitHub Actions",
			}},
			wantOS:   "Linux",
			wantArch: "X64",
			wantSelf: false,
			wantName: "GitHub Actions 42",
		},
		{
			name: "github-hosted macos",
			jobs: []gh.Job{{
				Labels:          []string{"macos-14"},
				RunnerName:      "GitHub Actions 99",
				RunnerGroupName: "GitHub Actions",
			}},
			wantOS:   "macOS",
			wantArch: "X64",
			wantSelf: false,
		},
		{
			name: "self-hosted with labels",
			jobs: []gh.Job{{
				Labels:          []string{"self-hosted", "linux", "x64"},
				RunnerName:      "my-runner-01",
				RunnerGroupName: "Custom Runners",
			}},
			wantOS:   "Linux",
			wantArch: "X64",
			wantSelf: true,
			wantName: "my-runner-01",
		},
		{
			name: "self-hosted arm64",
			jobs: []gh.Job{{
				Labels:          []string{"self-hosted", "linux", "arm64"},
				RunnerName:      "arm-runner",
				RunnerGroupName: "ARM Pool",
			}},
			wantOS:   "Linux",
			wantArch: "ARM64",
			wantSelf: true,
		},
		{
			name: "windows runner",
			jobs: []gh.Job{{
				Labels:          []string{"windows-latest"},
				RunnerName:      "GitHub Actions 7",
				RunnerGroupName: "GitHub Actions",
			}},
			wantOS:   "Windows",
			wantArch: "X64",
			wantSelf: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runner := ExtractRunner(tt.jobs)
			if tt.wantNil {
				if runner != nil {
					t.Error("expected nil runner")
				}
				return
			}
			if runner == nil {
				t.Fatal("expected non-nil runner")
			}
			if runner.OS != tt.wantOS {
				t.Errorf("OS = %q, want %q", runner.OS, tt.wantOS)
			}
			if runner.Arch != tt.wantArch {
				t.Errorf("Arch = %q, want %q", runner.Arch, tt.wantArch)
			}
			if runner.SelfHosted != tt.wantSelf {
				t.Errorf("SelfHosted = %v, want %v", runner.SelfHosted, tt.wantSelf)
			}
			if tt.wantName != "" && runner.Name != tt.wantName {
				t.Errorf("Name = %q, want %q", runner.Name, tt.wantName)
			}
		})
	}
}

func TestExtractTimestamps(t *testing.T) {
	t1 := time.Date(2026, 1, 31, 10, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 1, 31, 10, 5, 0, 0, time.UTC)
	t3 := time.Date(2026, 1, 31, 10, 2, 0, 0, time.UTC)
	t4 := time.Date(2026, 1, 31, 10, 8, 0, 0, time.UTC)

	tests := []struct {
		name          string
		jobs          []gh.Job
		wantStarted   *time.Time
		wantCompleted *time.Time
	}{
		{
			name:          "empty jobs",
			jobs:          nil,
			wantStarted:   nil,
			wantCompleted: nil,
		},
		{
			name: "single job",
			jobs: []gh.Job{{StartedAt: t1, CompletedAt: t2}},
			wantStarted:   &t1,
			wantCompleted: &t2,
		},
		{
			name: "multiple jobs picks earliest and latest",
			jobs: []gh.Job{
				{StartedAt: t3, CompletedAt: t2},
				{StartedAt: t1, CompletedAt: t4},
			},
			wantStarted:   &t1,
			wantCompleted: &t4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			started, completed := ExtractTimestamps(tt.jobs)
			if (started == nil) != (tt.wantStarted == nil) {
				t.Errorf("started nil mismatch: got %v, want %v", started, tt.wantStarted)
			}
			if started != nil && tt.wantStarted != nil && !started.Equal(*tt.wantStarted) {
				t.Errorf("started = %v, want %v", *started, *tt.wantStarted)
			}
			if (completed == nil) != (tt.wantCompleted == nil) {
				t.Errorf("completed nil mismatch: got %v, want %v", completed, tt.wantCompleted)
			}
			if completed != nil && tt.wantCompleted != nil && !completed.Equal(*tt.wantCompleted) {
				t.Errorf("completed = %v, want %v", *completed, *tt.wantCompleted)
			}
		})
	}
}
