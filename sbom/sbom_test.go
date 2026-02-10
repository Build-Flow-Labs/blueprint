package sbom

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestGoModParser(t *testing.T) {
	content := `module github.com/example/myapp

go 1.21

require (
	github.com/gin-gonic/gin v1.9.1
	github.com/google/uuid v1.3.0
	golang.org/x/crypto v0.14.0 // indirect
)

require github.com/stretchr/testify v1.8.4
`

	parser := &GoModParser{}
	deps, err := parser.Parse(content)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if len(deps) != 4 {
		t.Errorf("Expected 4 dependencies, got %d", len(deps))
	}

	// Check first dependency
	found := false
	for _, dep := range deps {
		if dep.Name == "github.com/gin-gonic/gin" {
			found = true
			if dep.Version != "v1.9.1" {
				t.Errorf("Expected version v1.9.1, got %s", dep.Version)
			}
			if dep.Type != "go" {
				t.Errorf("Expected type 'go', got %s", dep.Type)
			}
			if !dep.Direct {
				t.Error("Expected gin to be a direct dependency")
			}
			if !strings.Contains(dep.PURL, "pkg:golang/") {
				t.Errorf("Expected PURL to contain pkg:golang/, got %s", dep.PURL)
			}
		}
		if dep.Name == "golang.org/x/crypto" {
			if dep.Direct {
				t.Error("Expected crypto to be an indirect dependency")
			}
		}
	}

	if !found {
		t.Error("Expected to find github.com/gin-gonic/gin dependency")
	}
}

func TestPackageJSONParser(t *testing.T) {
	content := `{
  "name": "my-app",
  "version": "1.0.0",
  "dependencies": {
    "express": "^4.18.2",
    "@types/node": "~20.0.0",
    "lodash": "4.17.21"
  },
  "devDependencies": {
    "jest": "^29.7.0"
  },
  "license": "MIT"
}`

	parser := &PackageJSONParser{}
	deps, err := parser.Parse(content)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if len(deps) != 4 {
		t.Errorf("Expected 4 dependencies, got %d", len(deps))
	}

	// Check dependencies
	expressFound := false
	typesFound := false
	for _, dep := range deps {
		if dep.Name == "express" {
			expressFound = true
			if dep.Version != "4.18.2" {
				t.Errorf("Expected version 4.18.2 (without ^), got %s", dep.Version)
			}
			if dep.Type != "npm" {
				t.Errorf("Expected type 'npm', got %s", dep.Type)
			}
		}
		if dep.Name == "@types/node" {
			typesFound = true
			if !strings.Contains(dep.PURL, "pkg:npm/@types/node") {
				t.Errorf("Expected scoped package PURL, got %s", dep.PURL)
			}
		}
	}

	if !expressFound {
		t.Error("Expected to find express dependency")
	}
	if !typesFound {
		t.Error("Expected to find @types/node dependency")
	}
}

func TestRequirementsTxtParser(t *testing.T) {
	content := `# Main dependencies
Django==4.2.0
requests>=2.31.0
flask[async]>=2.0.0

# Development
pytest==7.4.0

# Comments and empty lines are ignored

# With environment markers (simplified)
numpy==1.24.0; python_version >= "3.9"
`

	parser := &RequirementsTxtParser{}
	deps, err := parser.Parse(content)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if len(deps) != 5 {
		t.Errorf("Expected 5 dependencies, got %d", len(deps))
	}

	// Check Django
	djangoFound := false
	flaskFound := false
	for _, dep := range deps {
		if dep.Name == "Django" {
			djangoFound = true
			if dep.Version != "4.2.0" {
				t.Errorf("Expected version 4.2.0, got %s", dep.Version)
			}
			if dep.Type != "python" {
				t.Errorf("Expected type 'python', got %s", dep.Type)
			}
		}
		if dep.Name == "flask" {
			flaskFound = true
			// Extras should be stripped
			if strings.Contains(dep.Name, "[") {
				t.Error("Expected extras to be stripped from package name")
			}
		}
	}

	if !djangoFound {
		t.Error("Expected to find Django dependency")
	}
	if !flaskFound {
		t.Error("Expected to find flask dependency")
	}
}

func TestGetParserForFile(t *testing.T) {
	tests := []struct {
		filename     string
		expectedType string
	}{
		{"go.mod", "go"},
		{"/path/to/go.mod", "go"},
		{"package.json", "npm"},
		{"/app/package.json", "npm"},
		{"requirements.txt", "python"},
		{"requirements-dev.txt", "python"},
		{"unknown.txt", ""},
	}

	for _, test := range tests {
		parser := GetParserForFile(test.filename)
		if test.expectedType == "" {
			if parser != nil {
				t.Errorf("Expected no parser for %s, got %v", test.filename, parser)
			}
		} else {
			if parser == nil {
				t.Errorf("Expected parser for %s, got nil", test.filename)
			} else if parser.EcosystemType() != test.expectedType {
				t.Errorf("Expected %s parser for %s, got %s", test.expectedType, test.filename, parser.EcosystemType())
			}
		}
	}
}

func TestGeneratorCycloneDXJSON(t *testing.T) {
	generator := NewGenerator()

	input := &GeneratorInput{
		OrgName:  "TestOrg",
		RepoName: "test-repo",
		Files: map[string]string{
			"go.mod": `module github.com/test/app
go 1.21
require github.com/pkg/errors v0.9.1
`,
		},
		Format: FormatCycloneDXJSON,
	}

	result, err := generator.Generate(input)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	if result.Format != FormatCycloneDXJSON {
		t.Errorf("Expected format %s, got %s", FormatCycloneDXJSON, result.Format)
	}

	if len(result.Dependencies) != 1 {
		t.Errorf("Expected 1 dependency, got %d", len(result.Dependencies))
	}

	if result.Stats.TotalDependencies != 1 {
		t.Errorf("Expected TotalDependencies=1, got %d", result.Stats.TotalDependencies)
	}

	// Verify JSON structure
	var bom CDXBom
	if err := json.Unmarshal([]byte(result.Content), &bom); err != nil {
		t.Fatalf("Failed to parse CycloneDX JSON: %v", err)
	}

	if bom.BomFormat != "CycloneDX" {
		t.Errorf("Expected bomFormat 'CycloneDX', got %s", bom.BomFormat)
	}

	if bom.SpecVersion != "1.4" {
		t.Errorf("Expected specVersion '1.4', got %s", bom.SpecVersion)
	}

	if len(bom.Components) != 1 {
		t.Errorf("Expected 1 component, got %d", len(bom.Components))
	}
}

func TestGeneratorSPDXJSON(t *testing.T) {
	generator := NewGenerator()

	input := &GeneratorInput{
		OrgName:  "TestOrg",
		RepoName: "test-repo",
		Files: map[string]string{
			"package.json": `{
  "name": "test-app",
  "dependencies": {
    "express": "4.18.2"
  }
}`,
		},
		Format: FormatSPDXJSON,
	}

	result, err := generator.Generate(input)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	if result.Format != FormatSPDXJSON {
		t.Errorf("Expected format %s, got %s", FormatSPDXJSON, result.Format)
	}

	// Verify JSON structure
	var doc SPDXDocument
	if err := json.Unmarshal([]byte(result.Content), &doc); err != nil {
		t.Fatalf("Failed to parse SPDX JSON: %v", err)
	}

	if doc.SPDXVersion != "SPDX-2.3" {
		t.Errorf("Expected spdxVersion 'SPDX-2.3', got %s", doc.SPDXVersion)
	}

	if doc.DataLicense != "CC0-1.0" {
		t.Errorf("Expected dataLicense 'CC0-1.0', got %s", doc.DataLicense)
	}

	// Should have root package + 1 dependency
	if len(doc.Packages) != 2 {
		t.Errorf("Expected 2 packages (root + dependency), got %d", len(doc.Packages))
	}
}

func TestCalculateStats(t *testing.T) {
	deps := []Dependency{
		{Name: "pkg1", Type: "go", Direct: true, License: "MIT"},
		{Name: "pkg2", Type: "go", Direct: false, License: ""},
		{Name: "pkg3", Type: "npm", Direct: true, License: "Apache-2.0"},
	}

	stats := calculateStats(deps)

	if stats.TotalDependencies != 3 {
		t.Errorf("Expected TotalDependencies=3, got %d", stats.TotalDependencies)
	}

	if stats.DirectDependencies != 2 {
		t.Errorf("Expected DirectDependencies=2, got %d", stats.DirectDependencies)
	}

	if stats.WithLicense != 2 {
		t.Errorf("Expected WithLicense=2, got %d", stats.WithLicense)
	}

	if stats.WithoutLicense != 1 {
		t.Errorf("Expected WithoutLicense=1, got %d", stats.WithoutLicense)
	}

	if stats.Ecosystems != 2 {
		t.Errorf("Expected Ecosystems=2, got %d", stats.Ecosystems)
	}
}

func TestParseFormat(t *testing.T) {
	tests := []struct {
		input    string
		expected Format
		hasError bool
	}{
		{"cyclonedx-json", FormatCycloneDXJSON, false},
		{"cyclonedx", FormatCycloneDXJSON, false},
		{"cyclonedx-xml", FormatCycloneDXXML, false},
		{"spdx-json", FormatSPDXJSON, false},
		{"spdx", FormatSPDXJSON, false},
		{"unknown", "", true},
	}

	for _, test := range tests {
		format, err := ParseFormat(test.input)
		if test.hasError {
			if err == nil {
				t.Errorf("Expected error for %s, got nil", test.input)
			}
		} else {
			if err != nil {
				t.Errorf("Unexpected error for %s: %v", test.input, err)
			}
			if format != test.expected {
				t.Errorf("Expected %s for %s, got %s", test.expected, test.input, format)
			}
		}
	}
}
