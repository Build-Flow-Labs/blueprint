// Package sbom provides Software Bill of Materials (SBOM) generation capabilities.
// It parses dependency manifests from various ecosystems and generates SBOMs in
// CycloneDX and SPDX formats.
package sbom

import (
	"bufio"
	"encoding/json"
	"regexp"
	"strings"
)

// Dependency represents a single software dependency with its metadata.
type Dependency struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	License string `json:"license,omitempty"`
	PURL    string `json:"purl,omitempty"`
	Type    string `json:"type"` // "go", "npm", "python", etc.
	Direct  bool   `json:"direct"`
}

// DependencyParser defines the interface for parsing dependency manifests.
type DependencyParser interface {
	// Parse extracts dependencies from the given file content.
	Parse(content string) ([]Dependency, error)
	// FilePatterns returns the file patterns this parser handles.
	FilePatterns() []string
	// EcosystemType returns the ecosystem name (e.g., "go", "npm", "python").
	EcosystemType() string
}

// GetParserForFile returns the appropriate parser for the given filename.
func GetParserForFile(filename string) DependencyParser {
	parsers := []DependencyParser{
		&GoModParser{},
		&PackageJSONParser{},
		&RequirementsTxtParser{},
	}

	for _, parser := range parsers {
		for _, pattern := range parser.FilePatterns() {
			if matchPattern(filename, pattern) {
				return parser
			}
		}
	}
	return nil
}

// matchPattern performs simple pattern matching for filenames.
func matchPattern(filename, pattern string) bool {
	// Handle exact matches
	if filename == pattern {
		return true
	}
	// Handle suffix matches (e.g., "go.mod" matches "foo/bar/go.mod")
	if strings.HasSuffix(filename, "/"+pattern) {
		return true
	}
	return false
}

// ----------------------------------------------------------------------------
// GoModParser - Parses Go module files
// ----------------------------------------------------------------------------

// GoModParser parses go.mod files for Go dependencies.
type GoModParser struct{}

// FilePatterns returns the file patterns for go.mod files.
func (p *GoModParser) FilePatterns() []string {
	return []string{"go.mod"}
}

// EcosystemType returns "go" for the Go ecosystem.
func (p *GoModParser) EcosystemType() string {
	return "go"
}

// Parse extracts dependencies from a go.mod file.
func (p *GoModParser) Parse(content string) ([]Dependency, error) {
	var deps []Dependency

	// Regex patterns for go.mod parsing
	moduleRegex := regexp.MustCompile(`^module\s+(\S+)`)
	requireRegex := regexp.MustCompile(`^\s*(\S+)\s+(v[\d.]+(?:-[\w.]+)?)`)
	indirectRegex := regexp.MustCompile(`//\s*indirect`)

	scanner := bufio.NewScanner(strings.NewReader(content))
	inRequireBlock := false

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		// Skip empty lines and comments
		if trimmed == "" || strings.HasPrefix(trimmed, "//") {
			continue
		}

		// Skip module declaration
		if moduleRegex.MatchString(trimmed) {
			continue
		}

		// Track require block
		if strings.HasPrefix(trimmed, "require (") || trimmed == "require(" {
			inRequireBlock = true
			continue
		}
		if trimmed == ")" && inRequireBlock {
			inRequireBlock = false
			continue
		}

		// Single-line require
		if strings.HasPrefix(trimmed, "require ") && !strings.Contains(trimmed, "(") {
			trimmed = strings.TrimPrefix(trimmed, "require ")
		}

		// Parse dependency line
		if inRequireBlock || strings.HasPrefix(line, "require ") {
			if matches := requireRegex.FindStringSubmatch(trimmed); matches != nil {
				name := matches[1]
				version := matches[2]
				isDirect := !indirectRegex.MatchString(line)

				deps = append(deps, Dependency{
					Name:    name,
					Version: version,
					Type:    "go",
					Direct:  isDirect,
					PURL:    buildGoPURL(name, version),
				})
			}
		}
	}

	return deps, scanner.Err()
}

// buildGoPURL constructs a Package URL for a Go module.
func buildGoPURL(name, version string) string {
	return "pkg:golang/" + strings.ReplaceAll(name, "/", "%2F") + "@" + version
}

// ----------------------------------------------------------------------------
// PackageJSONParser - Parses npm package.json files
// ----------------------------------------------------------------------------

// PackageJSONParser parses package.json files for npm dependencies.
type PackageJSONParser struct{}

// FilePatterns returns the file patterns for package.json files.
func (p *PackageJSONParser) FilePatterns() []string {
	return []string{"package.json"}
}

// EcosystemType returns "npm" for the npm ecosystem.
func (p *PackageJSONParser) EcosystemType() string {
	return "npm"
}

// packageJSON represents the structure of a package.json file.
type packageJSON struct {
	Name            string            `json:"name"`
	Version         string            `json:"version"`
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
	License         string            `json:"license"`
}

// Parse extracts dependencies from a package.json file.
func (p *PackageJSONParser) Parse(content string) ([]Dependency, error) {
	var pkg packageJSON
	if err := json.Unmarshal([]byte(content), &pkg); err != nil {
		return nil, err
	}

	var deps []Dependency

	// Parse production dependencies
	for name, version := range pkg.Dependencies {
		cleanVersion := cleanNpmVersion(version)
		deps = append(deps, Dependency{
			Name:    name,
			Version: cleanVersion,
			Type:    "npm",
			Direct:  true,
			PURL:    buildNpmPURL(name, cleanVersion),
		})
	}

	// Parse dev dependencies
	for name, version := range pkg.DevDependencies {
		cleanVersion := cleanNpmVersion(version)
		deps = append(deps, Dependency{
			Name:    name,
			Version: cleanVersion,
			Type:    "npm",
			Direct:  true,
			PURL:    buildNpmPURL(name, cleanVersion),
		})
	}

	return deps, nil
}

// cleanNpmVersion removes version range prefixes (^, ~, >=, etc.)
func cleanNpmVersion(version string) string {
	version = strings.TrimSpace(version)
	// Remove common prefixes
	for _, prefix := range []string{"^", "~", ">=", "<=", ">", "<", "="} {
		version = strings.TrimPrefix(version, prefix)
	}
	// Handle "x.x.x" range notation
	if strings.Contains(version, ".x") {
		version = strings.ReplaceAll(version, ".x", ".0")
	}
	return version
}

// buildNpmPURL constructs a Package URL for an npm package.
func buildNpmPURL(name, version string) string {
	// Handle scoped packages (@org/name)
	if strings.HasPrefix(name, "@") {
		parts := strings.SplitN(name, "/", 2)
		if len(parts) == 2 {
			return "pkg:npm/" + parts[0] + "/" + parts[1] + "@" + version
		}
	}
	return "pkg:npm/" + name + "@" + version
}

// ----------------------------------------------------------------------------
// RequirementsTxtParser - Parses Python requirements.txt files
// ----------------------------------------------------------------------------

// RequirementsTxtParser parses Python requirements.txt files.
type RequirementsTxtParser struct{}

// FilePatterns returns the file patterns for Python dependency files.
func (p *RequirementsTxtParser) FilePatterns() []string {
	return []string{"requirements.txt", "requirements-dev.txt", "requirements-test.txt"}
}

// EcosystemType returns "python" for the Python ecosystem.
func (p *RequirementsTxtParser) EcosystemType() string {
	return "python"
}

// Parse extracts dependencies from a requirements.txt file.
func (p *RequirementsTxtParser) Parse(content string) ([]Dependency, error) {
	var deps []Dependency

	// Regex for package==version or package>=version, etc.
	pkgRegex := regexp.MustCompile(`^([a-zA-Z0-9_-]+(?:\[[^\]]+\])?)\s*([=<>!~]+)?\s*([\d.]+(?:\.\*)?)?`)

	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		// Skip empty lines, comments, and special directives
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "-") {
			continue
		}

		// Skip lines with environment markers for now
		if strings.Contains(trimmed, ";") {
			trimmed = strings.Split(trimmed, ";")[0]
			trimmed = strings.TrimSpace(trimmed)
		}

		if matches := pkgRegex.FindStringSubmatch(trimmed); matches != nil {
			name := matches[1]
			version := ""
			if len(matches) > 3 && matches[3] != "" {
				version = matches[3]
			}

			// Clean extras from name (e.g., "package[extra]" -> "package")
			if idx := strings.Index(name, "["); idx != -1 {
				name = name[:idx]
			}

			deps = append(deps, Dependency{
				Name:    name,
				Version: version,
				Type:    "python",
				Direct:  true,
				PURL:    buildPyPIPURL(name, version),
			})
		}
	}

	return deps, scanner.Err()
}

// buildPyPIPURL constructs a Package URL for a Python package.
func buildPyPIPURL(name, version string) string {
	// Normalize package name (PEP 503)
	name = strings.ToLower(name)
	name = strings.ReplaceAll(name, "_", "-")

	if version != "" {
		return "pkg:pypi/" + name + "@" + version
	}
	return "pkg:pypi/" + name
}
