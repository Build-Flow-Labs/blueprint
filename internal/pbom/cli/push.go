package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var pushCmd = &cobra.Command{
	Use:   "push <file> <artifact-ref>",
	Short: "Push a PBOM to an OCI registry as a referrer artifact",
	Long: `Pushes a PBOM JSON document to an OCI-compliant registry using the
Referrers API (OCI 1.1). The PBOM is stored as a separate artifact
linked to the target artifact via its digest.

Requires ORAS libraries. This is a placeholder until the ORAS
integration is implemented.

Example:
  pbom push pbom.json ghcr.io/acme-corp/my-app@sha256:abc123...`,
	Args: cobra.ExactArgs(2),
	RunE: runPush,
}

func runPush(cmd *cobra.Command, args []string) error {
	pbomFile := args[0]
	artifactRef := args[1]

	// TODO: Implement ORAS-based push logic
	// 1. Read and validate the PBOM file
	// 2. Resolve the artifact reference to a digest
	// 3. Push the PBOM as a referrer with artifact-type: application/vnd.pbom.v1+json
	// 4. Print the resulting referrer digest

	fmt.Fprintf(cmd.ErrOrStderr(), "push not yet implemented (file=%s, ref=%s)\n", pbomFile, artifactRef)
	return fmt.Errorf("not implemented")
}
