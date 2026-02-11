package cli

import (
	"fmt"
	"os"

	"github.com/build-flow-labs/blueprint/internal/pbom/setup"
	"github.com/spf13/cobra"
)

var (
	initDryRun bool
	initOrg    string
	initToken  string
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Interactive setup wizard for org onboarding",
	Long: `Automates the PBOM setup process for a GitHub organization:

  1. Validates GitHub token and org access
  2. Creates custom properties (pbom-enabled, tier, lifecycle)
  3. Generates a filter config (pbom-config.yml)
  4. Pushes config and collector workflow to the .github repo
  5. Creates an org webhook for workflow_run events
  6. Optionally sets properties on selected repos

Use --dry-run to preview changes without executing them.`,
	RunE: runInit,
}

func init() {
	initCmd.Flags().BoolVar(&initDryRun, "dry-run", false, "Preview changes without executing")
	initCmd.Flags().StringVar(&initOrg, "org", "", "GitHub organization name (required)")
	initCmd.Flags().StringVar(&initToken, "token", "", "GitHub token (or GITHUB_TOKEN env var)")
}

func runInit(cmd *cobra.Command, args []string) error {
	// Resolve token
	if initToken == "" {
		initToken = os.Getenv("GITHUB_TOKEN")
	}
	if initToken == "" {
		return fmt.Errorf("GitHub token required (--token or GITHUB_TOKEN env var)")
	}

	// Resolve org
	if initOrg == "" {
		return fmt.Errorf("organization name required (--org)")
	}

	wiz := setup.NewWizard(initToken, initDryRun)
	return wiz.Run(cmd.Context(), initOrg)
}
