package sbom

import (
	"reflect"
	"testing"
)

func TestMatchPattern(t *testing.T) {
	tests := []struct {
		filename string
		pattern  string
		expected bool
	}{
		{
			filename: "go.mod",
			pattern:  "go.mod",
			expected: true,
		},
		{
			filename: "/path/to/go.mod",
			pattern:  "go.mod",
			expected: true,
		},
		{
			filename: "package.json",
			pattern:  "package.json",
			expected: true,
		},
		{
			filename: "/app/package.json",
			pattern:  "package.json",
			expected: true,
		},
		{
			filename: "requirements.txt",
			pattern:  "requirements.txt",
			expected: true,
		},
		{
			filename: "requirements-dev.txt",
			pattern:  "requirements-dev.txt",
			expected: true,
		},
		{
			filename: "unknown.txt",
			pattern:  "go.mod",
			expected: false,
		},
		{
			filename: "unknown.txt",
			pattern:  "package.json",
			expected: false,
		},
		{
			filename: "unknown.txt",
			pattern:  "requirements.txt",
			expected: false,
		},
	}

	for _, test := range tests {
		t.Run(test.filename+"-"+test.pattern, func(t *testing.T) {
			result := matchPattern(test.filename, test.pattern)
			if result != test.expected {
				t.Errorf("For filename %s and pattern %s, expected %v, got %v", test.filename, test.pattern, test.expected, result)
			}
		})
	}
}

func TestGoModParser_FilePatterns(t *testing.T) {
	parser := &GoModParser{}
	expected := []string{"go.mod"}
	patterns := parser.FilePatterns()

	if !reflect.DeepEqual(patterns, expected) {
		t.Errorf("Expected file patterns %v, got %v", expected, patterns)
	}
}

func TestGoModParser_EcosystemType(t *testing.T) {
	parser := &GoModParser{}
	expected := "go"
	ecosystem := parser.EcosystemType()

	if ecosystem != expected {
		t.Errorf("Expected ecosystem type %s, got %s", expected, ecosystem)
	}
}

func TestPackageJSONParser_FilePatterns(t *testing.T) {
	parser := &PackageJSONParser{}
	expected := []string{"package.json"}
	patterns := parser.FilePatterns()

	if !reflect.DeepEqual(patterns, expected) {
		t.Errorf("Expected file patterns %v, got %v", expected, patterns)
	}
}

func TestPackageJSONParser_EcosystemType(t *testing.T) {
	parser := &PackageJSONParser{}
	expected := "npm"
	ecosystem := parser.EcosystemType()

	if ecosystem != expected {
		t.Errorf("Expected ecosystem type %s, got %s", expected, ecosystem)
	}
}

func TestRequirementsTxtParser_FilePatterns(t *testing.T) {
	parser := &RequirementsTxtParser{}
	expected := []string{"requirements.txt", "requirements-dev.txt", "requirements-test.txt"}
	patterns := parser.FilePatterns()

	if !reflect.DeepEqual(patterns, expected) {
		t.Errorf("Expected file patterns %v, got %v", expected, patterns)
	}
}

func TestRequirementsTxtParser_EcosystemType(t *testing.T) {
	parser := &RequirementsTxtParser{}
	expected := "python"
	ecosystem := parser.EcosystemType()

	if ecosystem != expected {
		t.Errorf("Expected ecosystem type %s, got %s", expected, ecosystem)
	}
}

func TestCleanNpmVersion(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"^4.18.2", "4.18.2"},
		{"~20.0.0", "20.0.0"},
		{">=2.31.0", "2.31.0"},
		{"<=7.4.0", "7.4.0"},
		{">1.24.0", "1.24.0"},
		{"<1.24.0", "1.24.0"},
		{"=1.24.0", "1.24.0"},
		{"4.17.21", "4.17.21"},
		{"  4.17.21  ", "4.17.21"},
		{"1.x.x", "1.0.0"},
		{"1.2.x", "1.2.0"},
		{"1.2.3", "1.2.3"},
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			result := cleanNpmVersion(test.input)
			if result != test.expected {
				t.Errorf("Expected %s, got %s", test.expected, result)
			}
		})
	}
}

func TestBuildNpmPURL(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected string
	}{
		{"express", "4.18.2", "pkg:npm/express@4.18.2"},
		{"@types/node", "20.0.0", "pkg:npm/@types/node@20.0.0"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := buildNpmPURL(test.name, test.version)
			if result != test.expected {
				t.Errorf("Expected %s, got %s", test.expected, result)
			}
		})
	}
}

func TestBuildGoPURL(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected string
	}{
		{"github.com/gin-gonic/gin", "v1.9.1", "pkg:golang/github.com%2Fgin-gonic%2Fgin@v1.9.1"},
		{"golang.org/x/crypto", "v0.14.0", "pkg:golang/golang.org%2Fx%2Fcrypto@v0.14.0"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := buildGoPURL(test.name, test.version)
			if result != test.expected {
				t.Errorf("Expected %s, got %s", test.expected, result)
			}
		})
	}
}

func TestBuildPyPIPURL(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected string
	}{
		{"Django", "4.2.0", "pkg:pypi/django@4.2.0"},
		{"requests", "2.31.0", "pkg:pypi/requests@2.31.0"},
		{"Flask", "", "pkg:pypi/flask"},
		{"my_package", "1.0.0", "pkg:pypi/my-package@1.0.0"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := buildPyPIPURL(test.name, test.version)
			if result != test.expected {
				t.Errorf("Expected %s, got %s", test.expected, result)
			}
		})
	}
}