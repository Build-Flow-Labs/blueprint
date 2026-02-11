package cli

import (
	"github.com/spf13/cobra"
)

// RootCmd is the PBOM subcommand for the Blueprint CLI.
var RootCmd = &cobra.Command{
	Use:   "pbom",
	Short: "Pipeline Bill of Materials — track how artifacts reach production",
	Long: `PBOM captures the lineage of code as it transforms into a deployed artifact.

An SBOM tells you what is inside the artifact.
A PBOM tells you how it got there.

Use pbom to generate, validate, inspect, and push pipeline metadata
across your GitHub Actions and Kargo environments.`,
	SilenceUsage: true,
}

func init() {
	RootCmd.AddCommand(generateCmd)
	RootCmd.AddCommand(validateCmd)
	RootCmd.AddCommand(inspectCmd)
	RootCmd.AddCommand(pushCmd)
	RootCmd.AddCommand(versionCmd)
	RootCmd.AddCommand(filterCmd)
	RootCmd.AddCommand(webhookCmd)
	RootCmd.AddCommand(scoreCmd)
	RootCmd.AddCommand(initCmd)
}
