package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/build-flow-labs/blueprint/pbom/schema"
	"github.com/spf13/cobra"
)

var validateCmd = &cobra.Command{
	Use:   "validate <file>",
	Short: "Validate a PBOM document",
	Long: `Checks that a PBOM JSON file is well-formed and contains all required fields.

Validates:
  - JSON structure matches the PBOM schema
  - Required fields are present (source.repository, source.commit_sha, build.workflow_run_id, etc.)
  - Commit SHA format (40-char hex)
  - Artifact digests format (sha256:64-char hex)`,
	Args: cobra.ExactArgs(1),
	RunE: runValidate,
}

func runValidate(cmd *cobra.Command, args []string) error {
	data, err := os.ReadFile(args[0])
	if err != nil {
		return fmt.Errorf("reading file: %w", err)
	}

	var pbom schema.PBOM
	if err := json.Unmarshal(data, &pbom); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}

	var errs []string

	if pbom.PBOMVersion == "" {
		errs = append(errs, "missing pbom_version")
	} else if pbom.PBOMVersion != schema.Version {
		errs = append(errs, fmt.Sprintf("unsupported pbom_version %q (expected %q)", pbom.PBOMVersion, schema.Version))
	}

	if pbom.ID == "" {
		errs = append(errs, "missing id")
	}

	if pbom.Timestamp.IsZero() {
		errs = append(errs, "missing timestamp")
	}

	if pbom.Source.Repository == "" {
		errs = append(errs, "missing source.repository")
	}

	if pbom.Source.CommitSHA == "" {
		errs = append(errs, "missing source.commit_sha")
	} else if !isValidSHA(pbom.Source.CommitSHA) {
		errs = append(errs, fmt.Sprintf("invalid source.commit_sha %q (expected 40-char hex)", pbom.Source.CommitSHA))
	}

	if pbom.Build.WorkflowRunID == "" {
		errs = append(errs, "missing build.workflow_run_id")
	}

	if pbom.Build.WorkflowName == "" {
		errs = append(errs, "missing build.workflow_name")
	}

	if pbom.Build.Actor == "" {
		errs = append(errs, "missing build.actor")
	}

	if pbom.Build.Status == "" {
		errs = append(errs, "missing build.status")
	}

	for i, a := range pbom.Artifacts {
		if a.Name == "" {
			errs = append(errs, fmt.Sprintf("missing artifacts[%d].name", i))
		}
		if a.Type == "" {
			errs = append(errs, fmt.Sprintf("missing artifacts[%d].type", i))
		}
		if a.Digest == "" {
			errs = append(errs, fmt.Sprintf("missing artifacts[%d].digest", i))
		} else if !isValidDigest(a.Digest) {
			errs = append(errs, fmt.Sprintf("invalid artifacts[%d].digest %q (expected sha256:<64-char hex>)", i, a.Digest))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("validation failed:\n  %s", strings.Join(errs, "\n  "))
	}

	fmt.Fprintln(cmd.OutOrStdout(), "valid")
	return nil
}

func isValidSHA(s string) bool {
	if len(s) != 40 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func isValidDigest(s string) bool {
	if !strings.HasPrefix(s, "sha256:") {
		return false
	}
	hex := strings.TrimPrefix(s, "sha256:")
	if len(hex) != 64 {
		return false
	}
	for _, c := range hex {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}
