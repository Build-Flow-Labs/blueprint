package webhook

import (
	"strings"
	"time"

	gh "github.com/build-flow-labs/blueprint/internal/pbom/github"
	"github.com/build-flow-labs/blueprint/pbom/schema"
)

// ExtractRunner builds a schema.Runner from the Jobs API response.
// Uses the first job's runner metadata to determine OS, arch, and self-hosted status.
func ExtractRunner(jobs []gh.Job) *schema.Runner {
	if len(jobs) == 0 {
		return nil
	}

	job := jobs[0]
	runner := &schema.Runner{
		Name: job.RunnerName,
	}

	// Detect self-hosted: GitHub-hosted runners have group name "GitHub Actions"
	runner.SelfHosted = job.RunnerGroupName != "" && job.RunnerGroupName != "GitHub Actions"

	// Parse OS and arch from labels
	for _, label := range job.Labels {
		lower := strings.ToLower(label)
		switch {
		case lower == "self-hosted":
			runner.SelfHosted = true
		case strings.Contains(lower, "ubuntu") || lower == "linux":
			runner.OS = "Linux"
		case strings.Contains(lower, "macos") || lower == "macos":
			runner.OS = "macOS"
		case strings.Contains(lower, "windows"):
			runner.OS = "Windows"
		case lower == "x64" || lower == "amd64":
			runner.Arch = "X64"
		case lower == "arm64" || lower == "aarch64":
			runner.Arch = "ARM64"
		}
	}

	// Defaults if not detected from labels
	if runner.OS == "" {
		runner.OS = guessOSFromRunnerName(job.RunnerName)
	}
	if runner.Arch == "" {
		runner.Arch = "X64"
	}

	return runner
}

func guessOSFromRunnerName(name string) string {
	lower := strings.ToLower(name)
	switch {
	case strings.Contains(lower, "ubuntu") || strings.Contains(lower, "linux"):
		return "Linux"
	case strings.Contains(lower, "macos"):
		return "macOS"
	case strings.Contains(lower, "windows"):
		return "Windows"
	default:
		return "Linux"
	}
}

// ExtractTimestamps returns the earliest started_at and latest completed_at across all jobs.
func ExtractTimestamps(jobs []gh.Job) (started, completed *time.Time) {
	if len(jobs) == 0 {
		return nil, nil
	}

	var earliest, latest time.Time
	for _, job := range jobs {
		if !job.StartedAt.IsZero() && (earliest.IsZero() || job.StartedAt.Before(earliest)) {
			earliest = job.StartedAt
		}
		if !job.CompletedAt.IsZero() && (latest.IsZero() || job.CompletedAt.After(latest)) {
			latest = job.CompletedAt
		}
	}

	if !earliest.IsZero() {
		started = &earliest
	}
	if !latest.IsZero() {
		completed = &latest
	}
	return started, completed
}
