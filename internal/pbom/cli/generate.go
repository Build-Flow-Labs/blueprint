package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/build-flow-labs/blueprint/internal/pbom/detect"
	"github.com/build-flow-labs/blueprint/pbom/schema"
	"github.com/spf13/cobra"
)

var (
	generateOutput string
)

var generateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate a PBOM from the current GitHub Actions environment",
	Long: `Reads GitHub Actions environment variables to produce a PBOM document.

Designed to run inside a Required Workflow. Captures source, build,
runner environment, and detected tool versions automatically with
zero configuration.

Environment variables read:
  GITHUB_SHA, GITHUB_REPOSITORY, GITHUB_REF, GITHUB_REF_NAME,
  GITHUB_ACTOR, GITHUB_RUN_ID, GITHUB_WORKFLOW, GITHUB_EVENT_NAME,
  GITHUB_WORKFLOW_REF, RUNNER_OS, RUNNER_ARCH, RUNNER_NAME,
  RUNNER_ENVIRONMENT`,
	RunE: runGenerate,
}

func init() {
	generateCmd.Flags().StringVarP(&generateOutput, "output", "o", "", "Write PBOM to file (default: stdout)")
}

func runGenerate(cmd *cobra.Command, args []string) error {
	now := time.Now().UTC()

	// Detect runner environment
	runner := buildRunner()

	// Detect installed build tools
	toolVersions := detect.ToolVersions()

	pbom := schema.PBOM{
		PBOMVersion: schema.Version,
		ID:          uuid.New().String(),
		Timestamp:   now,
		Source: schema.Source{
			Repository: envOrEmpty("GITHUB_REPOSITORY"),
			CommitSHA:  envOrEmpty("GITHUB_SHA"),
			Branch:     envOrEmpty("GITHUB_REF_NAME"),
			Ref:        envOrEmpty("GITHUB_REF"),
			Author:     envOrEmpty("GITHUB_ACTOR"),
		},
		Build: schema.Build{
			WorkflowRunID: envOrEmpty("GITHUB_RUN_ID"),
			WorkflowName:  envOrEmpty("GITHUB_WORKFLOW"),
			WorkflowFile:  envOrEmpty("GITHUB_WORKFLOW_REF"),
			Trigger:       mapTrigger(envOrEmpty("GITHUB_EVENT_NAME")),
			Actor:         envOrEmpty("GITHUB_ACTOR"),
			Runner:        runner,
			ToolVersions:  toolVersions,
			StartedAt:     &now,
			Status:        "success",
		},
	}

	data, err := json.MarshalIndent(pbom, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling PBOM: %w", err)
	}

	if generateOutput != "" {
		if err := os.WriteFile(generateOutput, data, 0644); err != nil {
			return fmt.Errorf("writing file %s: %w", generateOutput, err)
		}
		fmt.Fprintf(cmd.ErrOrStderr(), "PBOM written to %s\n", generateOutput)
		return nil
	}

	fmt.Fprintln(cmd.OutOrStdout(), string(data))
	return nil
}

func envOrEmpty(key string) string {
	return os.Getenv(key)
}

// buildRunner detects the runner environment from RUNNER_* env vars
// (set by GitHub Actions) with fallback to Go's runtime package.
func buildRunner() *schema.Runner {
	osName := envOrEmpty("RUNNER_OS")
	if osName == "" {
		osName = runtime.GOOS
	}

	arch := envOrEmpty("RUNNER_ARCH")
	if arch == "" {
		arch = runtime.GOARCH
	}

	name := envOrEmpty("RUNNER_NAME")

	selfHosted := false
	if env := envOrEmpty("RUNNER_ENVIRONMENT"); strings.EqualFold(env, "self-hosted") {
		selfHosted = true
	}

	return &schema.Runner{
		OS:         osName,
		Arch:       arch,
		Name:       name,
		SelfHosted: selfHosted,
	}
}

func mapTrigger(event string) string {
	switch event {
	case "push", "pull_request", "workflow_dispatch", "schedule", "release":
		return event
	case "":
		return ""
	default:
		return "other"
	}
}
