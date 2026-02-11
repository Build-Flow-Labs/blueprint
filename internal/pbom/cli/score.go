package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/build-flow-labs/blueprint/internal/pbom/score"
	"github.com/build-flow-labs/blueprint/pbom/schema"
	"github.com/spf13/cobra"
)

var (
	scoreJSON  bool
	scoreWrite bool
)

var scoreCmd = &cobra.Command{
	Use:   "score <file|directory>",
	Short: "Score the pipeline health of a PBOM document",
	Long: `Evaluates a PBOM on 4 axes and produces a composite health grade (A-F).

Axes:
  Tool Currency    — Are build tools up to date?
  Secret Hygiene   — Are secrets properly scoped?
  Provenance       — Is the build verifiable?
  Vulnerability    — Is the artifact clean?

Pass a single .pbom.json file or a directory to score all PBOMs in it.
Use --json for machine-readable output.
Use --write to save scores back into the PBOM files.`,
	Args: cobra.ExactArgs(1),
	RunE: runScore,
}

func init() {
	scoreCmd.Flags().BoolVar(&scoreJSON, "json", false, "Output JSON instead of formatted table")
	scoreCmd.Flags().BoolVar(&scoreWrite, "write", false, "Write scores back into the PBOM files")
}

type scoreResult struct {
	File        string              `json:"file"`
	Repository  string              `json:"repository"`
	HealthScore *schema.HealthScore `json:"health_score"`
}

func runScore(cmd *cobra.Command, args []string) error {
	path := args[0]
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("cannot access %s: %w", path, err)
	}

	var files []string
	if info.IsDir() {
		entries, err := os.ReadDir(path)
		if err != nil {
			return fmt.Errorf("reading directory: %w", err)
		}
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".pbom.json") {
				files = append(files, filepath.Join(path, e.Name()))
			}
		}
		if len(files) == 0 {
			return fmt.Errorf("no .pbom.json files found in %s", path)
		}
	} else {
		files = []string{path}
	}

	var results []scoreResult

	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "warning: skipping %s: %v\n", f, err)
			continue
		}

		var pbom schema.PBOM
		if err := json.Unmarshal(data, &pbom); err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "warning: skipping %s: invalid JSON: %v\n", f, err)
			continue
		}

		hs := score.Score(&pbom)
		results = append(results, scoreResult{
			File:        filepath.Base(f),
			Repository:  pbom.Source.Repository,
			HealthScore: hs,
		})

		// Write score back into file if --write is set
		if scoreWrite {
			pbom.HealthScore = hs
			updated, err := json.MarshalIndent(&pbom, "", "  ")
			if err != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "warning: could not marshal %s: %v\n", f, err)
				continue
			}
			if err := os.WriteFile(f, updated, 0o644); err != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "warning: could not write %s: %v\n", f, err)
			}
		}
	}

	if len(results) == 0 {
		return fmt.Errorf("no valid PBOM files to score")
	}

	if scoreJSON {
		out, _ := json.MarshalIndent(results, "", "  ")
		fmt.Fprintln(cmd.OutOrStdout(), string(out))
		return nil
	}

	out := cmd.OutOrStdout()

	if len(results) == 1 {
		r := results[0]
		printDetailedScore(out, r)
	} else {
		// Summary table for multiple PBOMs
		w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
		fmt.Fprintf(w, "REPO\tGRADE\tSCORE\tTOOLS\tSECRETS\tPROV\tVULN\n")
		fmt.Fprintf(w, "----\t-----\t-----\t-----\t-------\t----\t----\n")
		for _, r := range results {
			hs := r.HealthScore
			fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%s\t%s\t%s\n",
				r.Repository,
				hs.Grade, hs.Score,
				hs.ToolCurrency.Grade,
				hs.SecretHygiene.Grade,
				hs.Provenance.Grade,
				hs.Vulnerability.Grade,
			)
		}
		w.Flush()

		// Print detailed view for each
		fmt.Fprintln(out)
		for _, r := range results {
			printDetailedScore(out, r)
			fmt.Fprintln(out)
		}
	}

	return nil
}

func printDetailedScore(out io.Writer, r scoreResult) {
	w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)

	fmt.Fprintf(out, "PIPELINE HEALTH: %s  [%s] %d/100\n", r.Repository, r.HealthScore.Grade, r.HealthScore.Score)
	fmt.Fprintln(out, strings.Repeat("─", 60))

	printAxis(w, out, "Tool Currency", r.HealthScore.ToolCurrency)
	printAxis(w, out, "Secret Hygiene", r.HealthScore.SecretHygiene)
	printAxis(w, out, "Provenance", r.HealthScore.Provenance)
	printAxis(w, out, "Vulnerability", r.HealthScore.Vulnerability)

	w.Flush()
}

func printAxis(w *tabwriter.Writer, out io.Writer, name string, axis schema.AxisScore) {
	fmt.Fprintf(w, "  %s\t[%s] %d/100\n", name, axis.Grade, axis.Score)
	w.Flush()
	for _, f := range axis.Findings {
		fmt.Fprintf(out, "    - %s\n", f)
	}
}
