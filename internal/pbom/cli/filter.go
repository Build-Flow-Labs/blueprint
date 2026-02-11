package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/build-flow-labs/blueprint/internal/pbom/filter"
	"github.com/spf13/cobra"
)

var (
	filterConfigPath string
	filterProperties string
	filterRepo       string
)

var filterCmd = &cobra.Command{
	Use:   "filter",
	Short: "Evaluate repo filter rules against custom properties",
	Long: `Evaluates the filtering rules from a pbom-config.yml file against
a set of GitHub custom properties for a repository.

Exit codes:
  0 = include (repo should run PBOM collection)
  1 = exclude (repo should skip PBOM collection)

The config file and properties JSON are passed in by the Required Workflow,
which fetches them from the GitHub API. The CLI itself never calls GitHub.`,
	SilenceErrors: true,
	RunE:          runFilter,
}

func init() {
	filterCmd.Flags().StringVar(&filterConfigPath, "config", "", "Path to pbom-config.yml (required)")
	filterCmd.Flags().StringVar(&filterProperties, "properties", "", "JSON object of repo custom properties (required)")
	filterCmd.Flags().StringVar(&filterRepo, "repo", "", "Repository name for logging context (optional)")
	_ = filterCmd.MarkFlagRequired("config")
	_ = filterCmd.MarkFlagRequired("properties")
}

func runFilter(cmd *cobra.Command, args []string) error {
	cfg, err := filter.LoadConfig(filterConfigPath)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	var properties map[string]string
	if err := json.Unmarshal([]byte(filterProperties), &properties); err != nil {
		return fmt.Errorf("parsing properties JSON: %w", err)
	}

	included, reason := filter.Evaluate(cfg, properties)

	repoLabel := filterRepo
	if repoLabel == "" {
		repoLabel = "(unknown)"
	}

	if included {
		fmt.Fprintf(cmd.ErrOrStderr(), "repo %s: included (%s)\n", repoLabel, reason)
		return nil
	}

	fmt.Fprintf(cmd.ErrOrStderr(), "repo %s: excluded (%s)\n", repoLabel, reason)
	os.Exit(1)
	return nil // unreachable, but satisfies the compiler
}
