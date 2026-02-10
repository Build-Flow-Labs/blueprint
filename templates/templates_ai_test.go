package templates

import (
	"strings"
	"testing"
)

func TestRegistry_loadBuiltinTemplates(t *testing.T) {
	r := NewRegistry()

	tests := []struct {
		id          string
		name        string
		description string
		category    string
		tags        []string
		frameworks  []string
		variables   []TemplateVar
	}{
		{
			id:          "sbom",
			name:        "SBOM Generation",
			description: "Generate Software Bill of Materials on every release using Syft",
			category:    "supply-chain",
			tags:        []string{"sbom", "cyclonedx", "spdx", "supply-chain"},
			frameworks:  []string{"NIST 800-53", "FedRAMP", "SOC2"},
			variables: []TemplateVar{
				{Name: "format", Description: "SBOM format (cyclonedx-json, spdx-json)", Default: "cyclonedx-json", Required: false},
				{Name: "upload_artifact", Description: "Upload SBOM as release asset", Default: "true", Required: false},
			},
		},
		{
			id:          "security-scan",
			name:        "Security Scanning",
			description: "Run Trivy vulnerability scanner on push and PR",
			category:    "security",
			tags:        []string{"trivy", "vulnerability", "cve", "security"},
			frameworks:  []string{"NIST 800-53", "PCI-DSS", "SOC2", "HIPAA"},
			variables: []TemplateVar{
				{Name: "severity", Description: "Minimum severity to fail (CRITICAL,HIGH,MEDIUM,LOW)", Default: "CRITICAL,HIGH", Required: false},
				{Name: "ignore_unfixed", Description: "Ignore vulnerabilities without fixes", Default: "true", Required: false},
			},
		},
		{
			id:          "dependency-review",
			name:        "Dependency Review",
			description: "Review dependency changes in pull requests for vulnerabilities",
			category:    "security",
			tags:        []string{"dependencies", "license", "vulnerability"},
			frameworks:  []string{"SOC2", "PCI-DSS"},
			variables: []TemplateVar{
				{Name: "fail_on_severity", Description: "Fail on vulnerability severity", Default: "high", Required: false},
				{Name: "deny_licenses", Description: "Denied license types (comma-separated)", Default: "GPL-3.0,AGPL-3.0", Required: false},
			},
		},
		{
			id:          "signed-commits",
			name:        "Signed Commits Check",
			description: "Verify all commits in a PR are signed with GPG or SSH keys",
			category:    "governance",
			tags:        []string{"signing", "gpg", "ssh", "commits"},
			frameworks:  []string{"SOX", "FedRAMP", "NIST 800-53"},
			variables:   []TemplateVar{},
		},
		{
			id:          "buildguard-scan",
			name:        "BuildGuard Compliance Scan",
			description: "Run BuildGuard compliance checks on push and PR",
			category:    "compliance",
			tags:        []string{"compliance", "governance", "audit"},
			frameworks:  []string{"SOC2", "SOX", "NIST 800-53", "PCI-DSS", "HIPAA", "FedRAMP"},
			variables: []TemplateVar{
				{Name: "fail_on_violation", Description: "Fail workflow on policy violations", Default: "true", Required: false},
				{Name: "min_severity", Description: "Minimum severity to report", Default: "medium", Required: false},
			},
		},
		{
			id:          "oidc-aws-deploy",
			name:        "AWS OIDC Deployment",
			description: "Deploy to AWS using OIDC authentication (no long-lived credentials)",
			category:    "deployment",
			tags:        []string{"aws", "oidc", "deploy", "ecr", "ecs"},
			frameworks:  []string{"NIST 800-53", "FedRAMP", "SOC2"},
			variables: []TemplateVar{
				{Name: "aws_region", Description: "AWS region for deployment", Default: "us-east-1", Required: true},
				{Name: "role_arn", Description: "IAM role ARN to assume", Default: "", Required: true},
				{Name: "ecr_repository", Description: "ECR repository name", Default: "", Required: false},
			},
		},
		{
			id:          "dockerfile-go",
			name:        "Hardened Go Dockerfile",
			description: "CIS-compliant Dockerfile for Go applications using distroless",
			category:    "docker",
			tags:        []string{"go", "golang", "dockerfile", "distroless", "cis"},
			frameworks:  []string{"CIS Controls v8.1", "NIST 800-53"},
			variables: []TemplateVar{
				{Name: "GoVersion", Description: "Go version", Default: "1.22", Required: false},
				{Name: "MainPackage", Description: "Main package path", Default: "./cmd/app", Required: false},
			},
		},
		{
			id:          "dockerfile-node",
			name:        "Hardened Node.js Dockerfile",
			description: "CIS-compliant Dockerfile for Node.js applications",
			category:    "docker",
			tags:        []string{"node", "nodejs", "dockerfile", "alpine", "cis"},
			frameworks:  []string{"CIS Controls v8.1", "NIST 800-53"},
			variables: []TemplateVar{
				{Name: "NodeVersion", Description: "Node.js version", Default: "20", Required: false},
				{Name: "Port", Description: "Application port", Default: "3000", Required: false},
				{Name: "EntryPoint", Description: "Entry point file", Default: "index.js", Required: false},
				{Name: "BuildCommand", Description: "Build command (optional)", Default: "", Required: false},
				{Name: "BuildOutput", Description: "Build output directory", Default: "dist", Required: false},
			},
		},
		{
			id:          "dockerfile-python",
			name:        "Hardened Python Dockerfile",
			description: "CIS-compliant Dockerfile for Python applications",
			category:    "docker",
			tags:        []string{"python", "dockerfile", "slim", "cis"},
			frameworks:  []string{"CIS Controls v8.1", "NIST 800-53"},
			variables: []TemplateVar{
				{Name: "PythonVersion", Description: "Python version", Default: "3.12", Required: false},
				{Name: "Port", Description: "Application port", Default: "8000", Required: false},
				{Name: "EntryPoint", Description: "Entry point file", Default: "app.py", Required: false},
			},
		},
		{
			id:          "dockerfile-java",
			name:        "Hardened Java Dockerfile",
			description: "CIS-compliant Dockerfile for Java applications using Eclipse Temurin",
			category:    "docker",
			tags:        []string{"java", "dockerfile", "temurin", "spring", "cis"},
			frameworks:  []string{"CIS Controls v8.1", "NIST 800-53"},
			variables: []TemplateVar{
				{Name: "JavaVersion", Description: "Java version", Default: "21", Required: false},
				{Name: "Port", Description: "Application port", Default: "8080", Required: false},
				{Name: "BuildTool", Description: "Build tool (maven or gradle)", Default: "maven", Required: false},
				{Name: "JarName", Description: "JAR file name", Default: "app.jar", Required: false},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			tmpl, err := r.Get(tt.id)
			if err != nil {
				t.Fatalf("Get(%q) returned unexpected error: %v", tt.id, err)
			}

			if tmpl.ID != tt.id {
				t.Errorf("Template ID mismatch: got %q, want %q", tmpl.ID, tt.id)
			}
			if tmpl.Name != tt.name {
				t.Errorf("Template Name mismatch: got %q, want %q", tmpl.Name, tt.name)
			}
			if tmpl.Description != tt.description {
				t.Errorf("Template Description mismatch: got %q, want %q", tmpl.Description, tt.description)
			}
			if tmpl.Category != tt.category {
				t.Errorf("Template Category mismatch: got %q, want %q", tmpl.Category, tt.category)
			}

			if len(tmpl.Tags) != len(tt.tags) {
				t.Errorf("Template Tags length mismatch: got %d, want %d", len(tmpl.Tags), len(tt.tags))
			}
			for i, tag := range tmpl.Tags {
				if tag != tt.tags[i] {
					t.Errorf("Template Tag mismatch at index %d: got %q, want %q", i, tag, tt.tags[i])
				}
			}

			if len(tmpl.Frameworks) != len(tt.frameworks) {
				t.Errorf("Template Frameworks length mismatch: got %d, want %d", len(tmpl.Frameworks), len(tt.frameworks))
			}
			for i, framework := range tmpl.Frameworks {
				if framework != tt.frameworks[i] {
					t.Errorf("Template Framework mismatch at index %d: got %q, want %q", i, framework, tt.frameworks[i])
				}
			}

			if len(tmpl.Variables) != len(tt.variables) {
				t.Errorf("Template Variables length mismatch: got %d, want %d", len(tmpl.Variables), len(tt.variables))
			}
			for i, variable := range tmpl.Variables {
				if variable.Name != tt.variables[i].Name {
					t.Errorf("Template Variable Name mismatch at index %d: got %q, want %q", i, variable.Name, tt.variables[i].Name)
				}
				if variable.Description != tt.variables[i].Description {
					t.Errorf("Template Variable Description mismatch at index %d: got %q, want %q", i, variable.Description, tt.variables[i].Description)
				}
				if variable.Default != tt.variables[i].Default {
					t.Errorf("Template Variable Default mismatch at index %d: got %q, want %q", i, variable.Default, tt.variables[i].Default)
				}
				if variable.Required != tt.variables[i].Required {
					t.Errorf("Template Variable Required mismatch at index %d: got %v, want %v", i, variable.Required, tt.variables[i].Required)
				}
			}
		})
	}
}

func TestRegistry_loadTemplateContent(t *testing.T) {
	r := NewRegistry()
	r.loadTemplateContent()

	tests := []struct {
		id      string
		wantErr bool
	}{
		{"sbom", false},
		{"security-scan", false},
		{"dependency-review", false},
		{"signed-commits", false},
		{"buildguard-scan", false},
		{"oidc-aws-deploy", false},
		{"dockerfile-go", false},
		{"dockerfile-node", false},
		{"dockerfile-python", false},
		{"dockerfile-java", false},
	}

	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			tmpl, err := r.Get(tt.id)
			if err != nil {
				t.Fatalf("Get(%q) returned unexpected error: %v", tt.id, err)
			}

			if tmpl.content == "" && !tt.wantErr {
				t.Errorf("Template %q content is empty, want non-empty", tt.id)
			}

			if tmpl.Category == "docker" {
				if !strings.Contains(tmpl.content, "FROM") {
					t.Errorf("Docker template %q missing FROM instruction", tt.id)
				}
			} else {
				if !strings.Contains(tmpl.content, "name:") {
					t.Errorf("Workflow template %q missing name", tt.id)
				}
			}
		})
	}
}