package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/build-flow-labs/blueprint/pbom/schema"
	"github.com/spf13/cobra"
)

var (
	inspectJSON bool
)

var inspectCmd = &cobra.Command{
	Use:   "inspect <file>",
	Short: "Display the lineage of an artifact from a PBOM document",
	Long: `Reads a PBOM file and prints a human-readable summary of the artifact's
pipeline lineage: source commit, build details, artifact digests, and
promotion history.

Use --json to output the raw PBOM instead.`,
	Args: cobra.ExactArgs(1),
	RunE: runInspect,
}

func init() {
	inspectCmd.Flags().BoolVar(&inspectJSON, "json", false, "Output raw JSON instead of formatted summary")
}

func runInspect(cmd *cobra.Command, args []string) error {
	data, err := os.ReadFile(args[0])
	if err != nil {
		return fmt.Errorf("reading file: %w", err)
	}

	var pbom schema.PBOM
	if err := json.Unmarshal(data, &pbom); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}

	if inspectJSON {
		pretty, _ := json.MarshalIndent(pbom, "", "  ")
		fmt.Fprintln(cmd.OutOrStdout(), string(pretty))
		return nil
	}

	out := cmd.OutOrStdout()
	w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)

	fmt.Fprintf(out, "PBOM %s\n\n", pbom.ID)

	fmt.Fprintln(out, "SOURCE")
	fmt.Fprintf(w, "  Repository\t%s\n", pbom.Source.Repository)
	fmt.Fprintf(w, "  Commit\t%s\n", pbom.Source.CommitSHA)
	if pbom.Source.Branch != "" {
		fmt.Fprintf(w, "  Branch\t%s\n", pbom.Source.Branch)
	}
	if pbom.Source.Author != "" {
		fmt.Fprintf(w, "  Author\t%s\n", pbom.Source.Author)
	}
	w.Flush()

	fmt.Fprintln(out)
	fmt.Fprintln(out, "BUILD")
	fmt.Fprintf(w, "  Workflow\t%s (run %s)\n", pbom.Build.WorkflowName, pbom.Build.WorkflowRunID)
	fmt.Fprintf(w, "  Trigger\t%s\n", pbom.Build.Trigger)
	fmt.Fprintf(w, "  Actor\t%s\n", pbom.Build.Actor)
	fmt.Fprintf(w, "  Status\t%s\n", pbom.Build.Status)
	if pbom.Build.Runner != nil {
		fmt.Fprintf(w, "  Runner\t%s/%s\n", pbom.Build.Runner.OS, pbom.Build.Runner.Arch)
	}
	if len(pbom.Build.ToolVersions) > 0 {
		for k, v := range pbom.Build.ToolVersions {
			fmt.Fprintf(w, "  Tool\t%s %s\n", k, v)
		}
	}
	if len(pbom.Build.SecretsAccessed) > 0 {
		for _, s := range pbom.Build.SecretsAccessed {
			fmt.Fprintf(w, "  Secret\t%s\n", s)
		}
	}
	w.Flush()

	for i, a := range pbom.Artifacts {
		fmt.Fprintln(out)
		fmt.Fprintf(out, "ARTIFACT #%d\n", i+1)
		fmt.Fprintf(w, "  Name\t%s\n", a.Name)
		fmt.Fprintf(w, "  Type\t%s\n", a.Type)
		fmt.Fprintf(w, "  Digest\t%s\n", a.Digest)
		if a.URI != "" {
			fmt.Fprintf(w, "  URI\t%s\n", a.URI)
		}
		if len(a.Tags) > 0 {
			for _, t := range a.Tags {
				fmt.Fprintf(w, "  Tag\t%s\n", t)
			}
		}
		if a.Provenance != nil {
			fmt.Fprintf(w, "  SLSA Level\t%d\n", a.Provenance.SLSALevel)
		}
		if a.Vulnerabilities != nil {
			fmt.Fprintf(w, "  Vulns\tC:%d H:%d M:%d L:%d (%s)\n",
				a.Vulnerabilities.Critical,
				a.Vulnerabilities.High,
				a.Vulnerabilities.Medium,
				a.Vulnerabilities.Low,
				a.Vulnerabilities.Scanner,
			)
		}
		w.Flush()
	}

	if pbom.HealthScore != nil {
		fmt.Fprintln(out)
		fmt.Fprintln(out, "HEALTH SCORE")
		fmt.Fprintf(w, "  Grade\t%s (%d/100)\n", pbom.HealthScore.Grade, pbom.HealthScore.Score)
		fmt.Fprintf(w, "  Tool Currency\t%s (%d/100)\n", pbom.HealthScore.ToolCurrency.Grade, pbom.HealthScore.ToolCurrency.Score)
		fmt.Fprintf(w, "  Secret Hygiene\t%s (%d/100)\n", pbom.HealthScore.SecretHygiene.Grade, pbom.HealthScore.SecretHygiene.Score)
		fmt.Fprintf(w, "  Provenance\t%s (%d/100)\n", pbom.HealthScore.Provenance.Grade, pbom.HealthScore.Provenance.Score)
		fmt.Fprintf(w, "  Vulnerability\t%s (%d/100)\n", pbom.HealthScore.Vulnerability.Grade, pbom.HealthScore.Vulnerability.Score)
		w.Flush()
	}

	if pbom.Promotion != nil && pbom.Promotion.FreightID != "" {
		fmt.Fprintln(out)
		fmt.Fprintln(out, "PROMOTION")
		fmt.Fprintf(w, "  Freight\t%s\n", pbom.Promotion.FreightID)
		fmt.Fprintf(w, "  Stage\t%s\n", pbom.Promotion.Stage)
		fmt.Fprintf(w, "  Promoted By\t%s\n", pbom.Promotion.PromotedBy)
		if pbom.Promotion.PromotedAt != nil {
			fmt.Fprintf(w, "  Promoted At\t%s\n", pbom.Promotion.PromotedAt.Format("2006-01-02 15:04:05 UTC"))
		}
		w.Flush()
		if len(pbom.Promotion.EnvironmentSnapshot) > 0 {
			fmt.Fprintln(out)
			fmt.Fprintln(out, "  CO-DEPLOYED SERVICES")
			for _, svc := range pbom.Promotion.EnvironmentSnapshot {
				fmt.Fprintf(w, "    %s\t%s\t%s\n", svc.Name, svc.Version, svc.Digest)
			}
		}
	}
	w.Flush()

	fmt.Fprintln(out)
	return nil
}
