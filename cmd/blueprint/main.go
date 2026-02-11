package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/build-flow-labs/blueprint/internal/pbom/cli"
	"github.com/build-flow-labs/blueprint/sbom"
	"github.com/build-flow-labs/blueprint/templates"
	"github.com/build-flow-labs/blueprint/vulnscan"
	"github.com/google/go-github/v60/github"
	"github.com/spf13/cobra"
	"golang.org/x/oauth2"
)

const version = "1.1.0"

var rootCmd = &cobra.Command{
	Use:   "blueprint",
	Short: "SBOM, PBOM, and supply chain security toolkit",
	Long: `Blueprint is the bootstrap layer for secure software delivery.

Generate Software Bill of Materials (SBOM) to know what's inside your artifacts.
Generate Pipeline Bill of Materials (PBOM) to know how they got there.

Part of the Build Flow Labs ecosystem.`,
	Version: version,
}

// SBOM command
var sbomCmd = &cobra.Command{
	Use:   "sbom",
	Short: "Generate Software Bill of Materials",
}

var sbomGenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate SBOM from local directory or GitHub repository",
	Run:   runSBOMGenerate,
}

// SBOM flags
var (
	sbomPath   string
	sbomOrg    string
	sbomRepo   string
	sbomFormat string
	sbomOutput string
)

// Vuln command
var vulnCmd = &cobra.Command{
	Use:   "vuln",
	Short: "Analyze vulnerability scan results",
}

var vulnAnalyzeCmd = &cobra.Command{
	Use:   "analyze",
	Short: "Analyze Trivy JSON output",
	Run:   runVulnAnalyze,
}

// Vuln flags
var (
	vulnInput        string
	vulnThreshold    string
	vulnIgnoreUnfixed bool
	vulnJSON         bool
)

// Template command
var templateCmd = &cobra.Command{
	Use:   "template",
	Short: "Manage workflow templates",
}

var templateListCmd = &cobra.Command{
	Use:   "list",
	Short: "List available templates",
	Run:   runTemplateList,
}

var templateGetCmd = &cobra.Command{
	Use:   "get [name]",
	Short: "Get template content",
	Args:  cobra.ExactArgs(1),
	Run:   runTemplateGet,
}

var templateApplyCmd = &cobra.Command{
	Use:   "apply",
	Short: "Apply template to a repository",
	Run:   runTemplateApply,
}

// Template apply flags
var (
	templateOrg      string
	templateRepo     string
	templateID       string
	templateDirectPush bool
)

func init() {
	// SBOM generate flags
	sbomGenerateCmd.Flags().StringVar(&sbomPath, "path", "", "Local directory to scan")
	sbomGenerateCmd.Flags().StringVarP(&sbomOrg, "org", "o", "", "GitHub organization")
	sbomGenerateCmd.Flags().StringVarP(&sbomRepo, "repo", "r", "", "GitHub repository")
	sbomGenerateCmd.Flags().StringVarP(&sbomFormat, "format", "f", "cyclonedx-json", "Output format: cyclonedx-json, cyclonedx-xml, spdx-json")
	sbomGenerateCmd.Flags().StringVar(&sbomOutput, "output", "", "Output file (default: stdout)")

	sbomCmd.AddCommand(sbomGenerateCmd)

	// Vuln analyze flags
	vulnAnalyzeCmd.Flags().StringVarP(&vulnInput, "input", "i", "", "Trivy JSON output file (required)")
	vulnAnalyzeCmd.Flags().StringVarP(&vulnThreshold, "threshold", "t", "no_critical_high", "Gate threshold")
	vulnAnalyzeCmd.Flags().BoolVar(&vulnIgnoreUnfixed, "ignore-unfixed", false, "Ignore vulnerabilities without fixes")
	vulnAnalyzeCmd.Flags().BoolVar(&vulnJSON, "json", false, "Output as JSON")
	vulnAnalyzeCmd.MarkFlagRequired("input")

	vulnCmd.AddCommand(vulnAnalyzeCmd)

	// Template apply flags
	templateApplyCmd.Flags().StringVarP(&templateOrg, "org", "o", "", "GitHub organization")
	templateApplyCmd.Flags().StringVarP(&templateRepo, "repo", "r", "", "GitHub repository")
	templateApplyCmd.Flags().StringVarP(&templateID, "template", "t", "", "Template ID")
	templateApplyCmd.Flags().BoolVar(&templateDirectPush, "direct-push", false, "Push directly instead of creating PR")

	templateCmd.AddCommand(templateListCmd)
	templateCmd.AddCommand(templateGetCmd)
	templateCmd.AddCommand(templateApplyCmd)

	// Add all commands to root
	rootCmd.AddCommand(sbomCmd)
	rootCmd.AddCommand(vulnCmd)
	rootCmd.AddCommand(templateCmd)
	rootCmd.AddCommand(cli.RootCmd) // PBOM subcommand
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// SBOM generate implementation
func runSBOMGenerate(cmd *cobra.Command, args []string) {
	sbomFormatParsed, err := sbom.ParseFormat(sbomFormat)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	var files map[string]string
	org, repo := sbomOrg, sbomRepo

	if sbomPath != "" {
		files, err = scanLocalDirectory(sbomPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error scanning directory: %v\n", err)
			os.Exit(1)
		}
		if org == "" {
			org = "local"
		}
		if repo == "" {
			repo = filepath.Base(sbomPath)
		}
	} else if org != "" && repo != "" {
		token := os.Getenv("GITHUB_TOKEN")
		if token == "" {
			fmt.Fprintln(os.Stderr, "Error: GITHUB_TOKEN environment variable required for GitHub mode")
			os.Exit(1)
		}
		files, err = fetchGitHubFiles(org, repo, token)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error fetching from GitHub: %v\n", err)
			os.Exit(1)
		}
	} else {
		fmt.Fprintln(os.Stderr, "Error: Either --path or --org/--repo required")
		os.Exit(1)
	}

	if len(files) == 0 {
		fmt.Fprintln(os.Stderr, "No dependency files found")
		os.Exit(1)
	}

	generator := sbom.NewGenerator()
	result, err := generator.Generate(&sbom.GeneratorInput{
		OrgName:  org,
		RepoName: repo,
		Files:    files,
		Format:   sbomFormatParsed,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating SBOM: %v\n", err)
		os.Exit(1)
	}

	if sbomOutput != "" {
		if err := os.WriteFile(sbomOutput, []byte(result.Content), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing output: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "SBOM written to %s\n", sbomOutput)
	} else {
		fmt.Println(result.Content)
	}

	fmt.Fprintf(os.Stderr, "\nSBOM Stats:\n")
	fmt.Fprintf(os.Stderr, "  Total dependencies: %d\n", result.Stats.TotalDependencies)
	fmt.Fprintf(os.Stderr, "  Direct dependencies: %d\n", result.Stats.DirectDependencies)
	fmt.Fprintf(os.Stderr, "  With license: %d\n", result.Stats.WithLicense)
	fmt.Fprintf(os.Stderr, "  Ecosystems: %d\n", result.Stats.Ecosystems)
}

// Vuln analyze implementation
func runVulnAnalyze(cmd *cobra.Command, args []string) {
	data, err := os.ReadFile(vulnInput)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading input: %v\n", err)
		os.Exit(1)
	}

	gateThreshold := vulnscan.ParseGateThreshold(vulnThreshold)
	analyzer := vulnscan.NewAnalyzer(gateThreshold)
	analyzer.IgnoreUnfixed = vulnIgnoreUnfixed

	analysis, err := analyzer.AnalyzeFromJSON(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error analyzing vulnerabilities: %v\n", err)
		os.Exit(1)
	}

	if vulnJSON {
		out, _ := json.MarshalIndent(analysis, "", "  ")
		fmt.Println(string(out))
	} else {
		fmt.Printf("Vulnerability Analysis\n")
		fmt.Printf("======================\n\n")
		fmt.Printf("Gate Threshold: %s\n", vulnThreshold)
		fmt.Printf("Gate Status: %s\n\n", map[bool]string{true: "PASSED", false: "FAILED"}[analysis.PassesGate])

		fmt.Printf("Summary:\n")
		fmt.Printf("  Critical: %d\n", analysis.Summary.Critical)
		fmt.Printf("  High:     %d\n", analysis.Summary.High)
		fmt.Printf("  Medium:   %d\n", analysis.Summary.Medium)
		fmt.Printf("  Low:      %d\n", analysis.Summary.Low)
		fmt.Printf("  Total:    %d\n\n", analysis.Summary.Total)

		if len(analysis.TopFindings) > 0 {
			fmt.Printf("Top Findings:\n")
			for _, f := range analysis.TopFindings {
				fix := "no fix"
				if f.HasFix {
					fix = f.FixVersion
				}
				fmt.Printf("  [%s] %s in %s@%s (%s)\n", f.Severity, f.ID, f.Package, f.Version, fix)
			}
		}

		if analysis.GateMessage != "" {
			fmt.Printf("\n%s\n", analysis.GateMessage)
		}
	}

	if !analysis.PassesGate {
		os.Exit(1)
	}
}

// Template commands implementation
func runTemplateList(cmd *cobra.Command, args []string) {
	registry := templates.NewRegistry()
	tmplList := registry.List()
	fmt.Printf("Available Templates (%d):\n\n", len(tmplList))
	for _, t := range tmplList {
		fmt.Printf("  %s\n", t.ID)
		fmt.Printf("    %s\n", t.Description)
		fmt.Printf("    Category: %s\n", t.Category)
		fmt.Printf("    Frameworks: %s\n\n", strings.Join(t.Frameworks, ", "))
	}
}

func runTemplateGet(cmd *cobra.Command, args []string) {
	registry := templates.NewRegistry()
	content, err := registry.Generate(args[0], &templates.TemplateContext{
		OrgName:       "example-org",
		RepoName:      "example-repo",
		DefaultBranch: "main",
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(content)
}

func runTemplateApply(cmd *cobra.Command, args []string) {
	if templateOrg == "" || templateRepo == "" || templateID == "" {
		fmt.Fprintln(os.Stderr, "Error: --org, --repo, and --template required")
		os.Exit(1)
	}

	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		fmt.Fprintln(os.Stderr, "Error: GITHUB_TOKEN environment variable required")
		os.Exit(1)
	}

	ctx := context.Background()
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
	tc := oauth2.NewClient(ctx, ts)
	client := github.NewClient(tc)

	gen := templates.NewGenerator(client)
	result, err := gen.Apply(ctx, templateOrg, templateRepo, templateID, &templates.TemplateContext{
		OrgName:       templateOrg,
		RepoName:      templateRepo,
		DefaultBranch: "main",
	}, &templates.ApplyOptions{CreatePR: !templateDirectPush})

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if result.Success {
		if result.PRURL != "" {
			fmt.Printf("Created PR: %s\n", result.PRURL)
		} else {
			fmt.Printf("Applied template directly to %s\n", result.BranchName)
		}
	}
}

// Helper functions
var dependencyFiles = []string{
	"go.mod", "go.sum",
	"package.json", "package-lock.json", "yarn.lock",
	"requirements.txt", "Pipfile", "Pipfile.lock",
	"Cargo.toml", "Cargo.lock",
	"pom.xml", "build.gradle",
	"Gemfile", "Gemfile.lock",
	"composer.json",
}

func scanLocalDirectory(path string) (map[string]string, error) {
	files := make(map[string]string)
	for _, filename := range dependencyFiles {
		fullPath := filepath.Join(path, filename)
		data, err := os.ReadFile(fullPath)
		if err != nil {
			continue
		}
		files[filename] = string(data)
	}
	return files, nil
}

func fetchGitHubFiles(org, repo, token string) (map[string]string, error) {
	ctx := context.Background()
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
	tc := oauth2.NewClient(ctx, ts)
	client := github.NewClient(tc)

	files := make(map[string]string)
	for _, filename := range dependencyFiles {
		content, _, _, err := client.Repositories.GetContents(ctx, org, repo, filename, nil)
		if err != nil {
			continue
		}
		if content != nil {
			decoded, err := content.GetContent()
			if err != nil {
				continue
			}
			files[filename] = decoded
		}
	}
	return files, nil
}
