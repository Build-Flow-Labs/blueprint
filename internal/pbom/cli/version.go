package cli

import (
	"fmt"
	"runtime/debug"

	"github.com/build-flow-labs/blueprint/pbom/schema"
	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print PBOM CLI and schema version",
	Run:   runVersion,
}

func runVersion(cmd *cobra.Command, args []string) {
	cliVersion := "dev"
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" {
		cliVersion = info.Main.Version
	}

	fmt.Fprintf(cmd.OutOrStdout(), "pbom %s (schema %s)\n", cliVersion, schema.Version)
}
