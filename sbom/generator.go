package sbom

import (
	"fmt"
	"time"
)

// Format represents the SBOM output format.
type Format string

const (
	// FormatCycloneDXJSON is the CycloneDX 1.4 JSON format.
	FormatCycloneDXJSON Format = "cyclonedx-json"
	// FormatCycloneDXXML is the CycloneDX 1.4 XML format.
	FormatCycloneDXXML Format = "cyclonedx-xml"
	// FormatSPDXJSON is the SPDX 2.3 JSON format.
	FormatSPDXJSON Format = "spdx-json"
)

// ParseFormat converts a string to a Format type.
func ParseFormat(s string) (Format, error) {
	switch s {
	case "cyclonedx-json", "cyclonedx":
		return FormatCycloneDXJSON, nil
	case "cyclonedx-xml":
		return FormatCycloneDXXML, nil
	case "spdx-json", "spdx":
		return FormatSPDXJSON, nil
	default:
		return "", fmt.Errorf("unknown SBOM format: %s", s)
	}
}

// SBOMStats contains statistics about the generated SBOM.
type SBOMStats struct {
	TotalDependencies  int `json:"total_dependencies"`
	DirectDependencies int `json:"direct_dependencies"`
	WithLicense        int `json:"with_license"`
	WithoutLicense     int `json:"without_license"`
	Ecosystems         int `json:"ecosystems"`
}

// GeneratedSBOM contains the result of SBOM generation.
type GeneratedSBOM struct {
	Format       Format       `json:"format"`
	Content      string       `json:"content"`
	Dependencies []Dependency `json:"dependencies"`
	Stats        SBOMStats    `json:"stats"`
	GeneratedAt  time.Time    `json:"generated_at"`
	ToolName     string       `json:"tool_name"`
	ToolVersion  string       `json:"tool_version"`
}

// Generator handles SBOM generation from dependency files.
type Generator struct {
	ToolName    string
	ToolVersion string
}

// NewGenerator creates a new SBOM generator with default settings.
func NewGenerator() *Generator {
	return &Generator{
		ToolName:    "Blueprint",
		ToolVersion: "1.0.0",
	}
}

// GeneratorInput contains the input for SBOM generation.
type GeneratorInput struct {
	OrgName    string
	RepoName   string
	Files      map[string]string // filename -> content
	Format     Format
	CommitSHA  string
	BranchName string
}

// Generate creates an SBOM from the provided input files.
func (g *Generator) Generate(input *GeneratorInput) (*GeneratedSBOM, error) {
	// Collect all dependencies from all parseable files
	var allDeps []Dependency

	for filename, content := range input.Files {
		parser := GetParserForFile(filename)
		if parser == nil {
			continue
		}

		deps, err := parser.Parse(content)
		if err != nil {
			// Log but continue with other files
			continue
		}
		allDeps = append(allDeps, deps...)
	}

	// Calculate stats
	stats := calculateStats(allDeps)

	// Generate the SBOM in the requested format
	var content string
	var err error

	switch input.Format {
	case FormatCycloneDXJSON:
		content, err = generateCycloneDXJSON(input, allDeps, g)
	case FormatCycloneDXXML:
		content, err = generateCycloneDXXML(input, allDeps, g)
	case FormatSPDXJSON:
		content, err = generateSPDXJSON(input, allDeps, g)
	default:
		return nil, fmt.Errorf("unsupported format: %s", input.Format)
	}

	if err != nil {
		return nil, err
	}

	return &GeneratedSBOM{
		Format:       input.Format,
		Content:      content,
		Dependencies: allDeps,
		Stats:        stats,
		GeneratedAt:  time.Now().UTC(),
		ToolName:     g.ToolName,
		ToolVersion:  g.ToolVersion,
	}, nil
}

// calculateStats computes statistics about the dependencies.
func calculateStats(deps []Dependency) SBOMStats {
	stats := SBOMStats{
		TotalDependencies: len(deps),
	}

	ecosystems := make(map[string]bool)
	for _, dep := range deps {
		if dep.Direct {
			stats.DirectDependencies++
		}
		if dep.License != "" {
			stats.WithLicense++
		} else {
			stats.WithoutLicense++
		}
		ecosystems[dep.Type] = true
	}
	stats.Ecosystems = len(ecosystems)

	return stats
}

// GenerateFromSingleFile generates an SBOM from a single file.
func (g *Generator) GenerateFromSingleFile(filename, content string, format Format, orgName, repoName string) (*GeneratedSBOM, error) {
	return g.Generate(&GeneratorInput{
		OrgName:  orgName,
		RepoName: repoName,
		Files:    map[string]string{filename: content},
		Format:   format,
	})
}
