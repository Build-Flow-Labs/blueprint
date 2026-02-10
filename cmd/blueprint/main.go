package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/build-flow-labs/blueprint/sbom"
	"github.com/build-flow-labs/blueprint/templates"
	"github.com/build-flow-labs/blueprint/vulnscan"
	"github.com/google/go-github/v60/github"
	"golang.org/x/oauth2"
)

const version = "1.0.0"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "sbom":
		handleSBOM(os.Args[2:])
	case "vuln":
		handleVuln(os.Args[2:])
	case "template":
		handleTemplate(os.Args[2:])
	case "version":
		fmt.Printf("Blueprint v%s\n", version)
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`Blueprint - SBOM generation and vulnerability analysis toolkit

Usage:
  blueprint <command> [options]

Commands:
  sbom      Generate Software Bill of Materials
  vuln      Analyze vulnerability scan results
  template  Manage workflow templates
  version   Print version information
  help      Show this help message

Examples:
  blueprint sbom generate --path .
  blueprint sbom generate --org myorg --repo myrepo --format cyclonedx-json
  blueprint vuln analyze --input trivy.json --threshold no_critical_high
  blueprint template list
  blueprint template get security-scan`)
}

// SBOM command handling
func handleSBOM(args []string) {
	if len(args) < 1 || args[0] != "generate" {
		fmt.Println(`Usage: blueprint sbom generate [options]

Options:
  --path PATH          Local directory to scan for dependency files
  --org ORG            GitHub organization (requires GITHUB_TOKEN)
  --repo REPO          GitHub repository name
  --format FORMAT      Output format: cyclonedx-json (default), cyclonedx-xml, spdx-json
  --output FILE        Output file (default: stdout)`)
		return
	}

	// Parse flags
	var path, org, repo, format, output string
	format = "cyclonedx-json"

	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--path":
			if i+1 < len(args) {
				path = args[i+1]
				i++
			}
		case "--org", "-o":
			if i+1 < len(args) {
				org = args[i+1]
				i++
			}
		case "--repo", "-r":
			if i+1 < len(args) {
				repo = args[i+1]
				i++
			}
		case "--format", "-f":
			if i+1 < len(args) {
				format = args[i+1]
				i++
			}
		case "--output":
			if i+1 < len(args) {
				output = args[i+1]
				i++
			}
		}
	}

	// Parse format
	sbomFormat, err := sbom.ParseFormat(format)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	var files map[string]string

	if path != "" {
		// Local mode
		files, err = scanLocalDirectory(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error scanning directory: %v\n", err)
			os.Exit(1)
		}
		if org == "" {
			org = "local"
		}
		if repo == "" {
			repo = filepath.Base(path)
		}
	} else if org != "" && repo != "" {
		// GitHub mode
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

	// Generate SBOM
	generator := sbom.NewGenerator()
	result, err := generator.Generate(&sbom.GeneratorInput{
		OrgName:  org,
		RepoName: repo,
		Files:    files,
		Format:   sbomFormat,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating SBOM: %v\n", err)
		os.Exit(1)
	}

	// Output
	if output != "" {
		if err := os.WriteFile(output, []byte(result.Content), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing output: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "SBOM written to %s\n", output)
	} else {
		fmt.Println(result.Content)
	}

	// Print stats to stderr
	fmt.Fprintf(os.Stderr, "\nSBOM Stats:\n")
	fmt.Fprintf(os.Stderr, "  Total dependencies: %d\n", result.Stats.TotalDependencies)
	fmt.Fprintf(os.Stderr, "  Direct dependencies: %d\n", result.Stats.DirectDependencies)
	fmt.Fprintf(os.Stderr, "  With license: %d\n", result.Stats.WithLicense)
	fmt.Fprintf(os.Stderr, "  Ecosystems: %d\n", result.Stats.Ecosystems)
}

// Vulnerability command handling
func handleVuln(args []string) {
	if len(args) < 1 || args[0] != "analyze" {
		fmt.Println(`Usage: blueprint vuln analyze [options]

Options:
  --input FILE         Trivy JSON output file (required)
  --threshold LEVEL    Gate threshold: no_critical, no_critical_high (default),
                       no_critical_high_medium, no_vulnerabilities
  --ignore-unfixed     Ignore vulnerabilities without available fixes
  --json               Output as JSON`)
		return
	}

	var input, threshold string
	var ignoreUnfixed, jsonOutput bool
	threshold = "no_critical_high"

	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--input", "-i":
			if i+1 < len(args) {
				input = args[i+1]
				i++
			}
		case "--threshold", "-t":
			if i+1 < len(args) {
				threshold = args[i+1]
				i++
			}
		case "--ignore-unfixed":
			ignoreUnfixed = true
		case "--json":
			jsonOutput = true
		}
	}

	if input == "" {
		fmt.Fprintln(os.Stderr, "Error: --input required")
		os.Exit(1)
	}

	// Read input file
	data, err := os.ReadFile(input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading input: %v\n", err)
		os.Exit(1)
	}

	// Parse threshold
	gateThreshold := vulnscan.ParseGateThreshold(threshold)

	// Analyze
	analyzer := vulnscan.NewAnalyzer(gateThreshold)
	analyzer.IgnoreUnfixed = ignoreUnfixed

	analysis, err := analyzer.AnalyzeFromJSON(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error analyzing vulnerabilities: %v\n", err)
		os.Exit(1)
	}

	if jsonOutput {
		out, _ := json.MarshalIndent(analysis, "", "  ")
		fmt.Println(string(out))
	} else {
		fmt.Printf("Vulnerability Analysis\n")
		fmt.Printf("======================\n\n")
		fmt.Printf("Gate Threshold: %s\n", threshold)
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

	// Exit with error if gate failed
	if !analysis.PassesGate {
		os.Exit(1)
	}
}

// Template command handling
func handleTemplate(args []string) {
	if len(args) < 1 {
		fmt.Println(`Usage: blueprint template <subcommand>

Subcommands:
  list              List available workflow templates
  get <name>        Get template content
  apply             Apply template to a repository (requires GITHUB_TOKEN)`)
		return
	}

	registry := templates.NewRegistry()

	switch args[0] {
	case "list":
		tmplList := registry.List()
		fmt.Printf("Available Templates (%d):\n\n", len(tmplList))
		for _, t := range tmplList {
			fmt.Printf("  %s\n", t.ID)
			fmt.Printf("    %s\n", t.Description)
			fmt.Printf("    Category: %s\n", t.Category)
			fmt.Printf("    Frameworks: %s\n\n", strings.Join(t.Frameworks, ", "))
		}

	case "get":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "Error: template name required")
			os.Exit(1)
		}
		content, err := registry.Generate(args[1], &templates.TemplateContext{
			OrgName:       "example-org",
			RepoName:      "example-repo",
			DefaultBranch: "main",
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(content)

	case "apply":
		// Parse apply flags
		var org, repo, templateID string
		createPR := true

		for i := 1; i < len(args); i++ {
			switch args[i] {
			case "--org", "-o":
				if i+1 < len(args) {
					org = args[i+1]
					i++
				}
			case "--repo", "-r":
				if i+1 < len(args) {
					repo = args[i+1]
					i++
				}
			case "--template", "-t":
				if i+1 < len(args) {
					templateID = args[i+1]
					i++
				}
			case "--direct-push":
				createPR = false
			}
		}

		if org == "" || repo == "" || templateID == "" {
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
		result, err := gen.Apply(ctx, org, repo, templateID, &templates.TemplateContext{
			OrgName:       org,
			RepoName:      repo,
			DefaultBranch: "main",
		}, &templates.ApplyOptions{CreatePR: createPR})

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

	default:
		fmt.Fprintf(os.Stderr, "Unknown template subcommand: %s\n", args[0])
		os.Exit(1)
	}
}

// Helper functions

var dependencyFiles = []string{
	"go.mod",
	"go.sum",
	"package.json",
	"package-lock.json",
	"yarn.lock",
	"requirements.txt",
	"Pipfile",
	"Pipfile.lock",
	"Cargo.toml",
	"Cargo.lock",
	"pom.xml",
	"build.gradle",
	"Gemfile",
	"Gemfile.lock",
	"composer.json",
}

func scanLocalDirectory(path string) (map[string]string, error) {
	files := make(map[string]string)

	for _, filename := range dependencyFiles {
		fullPath := filepath.Join(path, filename)
		data, err := os.ReadFile(fullPath)
		if err != nil {
			continue // File doesn't exist, skip
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
			continue // File doesn't exist, skip
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
