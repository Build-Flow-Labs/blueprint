package templates

import (
	"bytes"
	"embed"
	"fmt"
	"text/template"
)

//go:embed workflows/*.yaml
var workflowFS embed.FS

//go:embed dockerfiles/*.dockerfile
var dockerfileFS embed.FS

// WorkflowTemplate represents a GitHub Actions workflow template
type WorkflowTemplate struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Category    string        `json:"category"`
	Tags        []string      `json:"tags"`
	Frameworks  []string      `json:"frameworks"`
	Variables   []TemplateVar `json:"variables"`
	content     string        // raw template content
}

// TemplateVar defines a variable that can be customized in a template
type TemplateVar struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Default     string `json:"default"`
	Required    bool   `json:"required"`
}

// TemplateContext provides values for template rendering
type TemplateContext struct {
	OrgName       string
	RepoName      string
	DefaultBranch string
	Custom        map[string]string
}

// Registry holds all available workflow templates
type Registry struct {
	templates map[string]*WorkflowTemplate
}

// NewRegistry creates a new template registry with built-in templates
func NewRegistry() *Registry {
	r := &Registry{
		templates: make(map[string]*WorkflowTemplate),
	}
	r.loadBuiltinTemplates()
	return r
}

func (r *Registry) loadBuiltinTemplates() {
	// SBOM generation workflow
	r.register(&WorkflowTemplate{
		ID:          "sbom",
		Name:        "SBOM Generation",
		Description: "Generate Software Bill of Materials on every release using Syft",
		Category:    "supply-chain",
		Tags:        []string{"sbom", "cyclonedx", "spdx", "supply-chain"},
		Frameworks:  []string{"NIST 800-53", "FedRAMP", "SOC2"},
		Variables: []TemplateVar{
			{Name: "format", Description: "SBOM format (cyclonedx-json, spdx-json)", Default: "cyclonedx-json", Required: false},
			{Name: "upload_artifact", Description: "Upload SBOM as release asset", Default: "true", Required: false},
		},
	})

	// Security scanning workflow
	r.register(&WorkflowTemplate{
		ID:          "security-scan",
		Name:        "Security Scanning",
		Description: "Run Trivy vulnerability scanner on push and PR",
		Category:    "security",
		Tags:        []string{"trivy", "vulnerability", "cve", "security"},
		Frameworks:  []string{"NIST 800-53", "PCI-DSS", "SOC2", "HIPAA"},
		Variables: []TemplateVar{
			{Name: "severity", Description: "Minimum severity to fail (CRITICAL,HIGH,MEDIUM,LOW)", Default: "CRITICAL,HIGH", Required: false},
			{Name: "ignore_unfixed", Description: "Ignore vulnerabilities without fixes", Default: "true", Required: false},
		},
	})

	// Dependency review workflow
	r.register(&WorkflowTemplate{
		ID:          "dependency-review",
		Name:        "Dependency Review",
		Description: "Review dependency changes in pull requests for vulnerabilities",
		Category:    "security",
		Tags:        []string{"dependencies", "license", "vulnerability"},
		Frameworks:  []string{"SOC2", "PCI-DSS"},
		Variables: []TemplateVar{
			{Name: "fail_on_severity", Description: "Fail on vulnerability severity", Default: "high", Required: false},
			{Name: "deny_licenses", Description: "Denied license types (comma-separated)", Default: "GPL-3.0,AGPL-3.0", Required: false},
		},
	})

	// Signed commits enforcement
	r.register(&WorkflowTemplate{
		ID:          "signed-commits",
		Name:        "Signed Commits Check",
		Description: "Verify all commits in a PR are signed with GPG or SSH keys",
		Category:    "governance",
		Tags:        []string{"signing", "gpg", "ssh", "commits"},
		Frameworks:  []string{"SOX", "FedRAMP", "NIST 800-53"},
		Variables:   []TemplateVar{},
	})

	// BuildGuard compliance scan
	r.register(&WorkflowTemplate{
		ID:          "buildguard-scan",
		Name:        "BuildGuard Compliance Scan",
		Description: "Run BuildGuard compliance checks on push and PR",
		Category:    "compliance",
		Tags:        []string{"compliance", "governance", "audit"},
		Frameworks:  []string{"SOC2", "SOX", "NIST 800-53", "PCI-DSS", "HIPAA", "FedRAMP"},
		Variables: []TemplateVar{
			{Name: "fail_on_violation", Description: "Fail workflow on policy violations", Default: "true", Required: false},
			{Name: "min_severity", Description: "Minimum severity to report", Default: "medium", Required: false},
		},
	})

	// OIDC AWS deployment
	r.register(&WorkflowTemplate{
		ID:          "oidc-aws-deploy",
		Name:        "AWS OIDC Deployment",
		Description: "Deploy to AWS using OIDC authentication (no long-lived credentials)",
		Category:    "deployment",
		Tags:        []string{"aws", "oidc", "deploy", "ecr", "ecs"},
		Frameworks:  []string{"NIST 800-53", "FedRAMP", "SOC2"},
		Variables: []TemplateVar{
			{Name: "aws_region", Description: "AWS region for deployment", Default: "us-east-1", Required: true},
			{Name: "role_arn", Description: "IAM role ARN to assume", Default: "", Required: true},
			{Name: "ecr_repository", Description: "ECR repository name", Default: "", Required: false},
		},
	})

	// Hardened Dockerfile templates
	r.register(&WorkflowTemplate{
		ID:          "dockerfile-go",
		Name:        "Hardened Go Dockerfile",
		Description: "CIS-compliant Dockerfile for Go applications using distroless",
		Category:    "docker",
		Tags:        []string{"go", "golang", "dockerfile", "distroless", "cis"},
		Frameworks:  []string{"CIS Controls v8.1", "NIST 800-53"},
		Variables: []TemplateVar{
			{Name: "GoVersion", Description: "Go version", Default: "1.22", Required: false},
			{Name: "MainPackage", Description: "Main package path", Default: "./cmd/app", Required: false},
		},
	})

	r.register(&WorkflowTemplate{
		ID:          "dockerfile-node",
		Name:        "Hardened Node.js Dockerfile",
		Description: "CIS-compliant Dockerfile for Node.js applications",
		Category:    "docker",
		Tags:        []string{"node", "nodejs", "dockerfile", "alpine", "cis"},
		Frameworks:  []string{"CIS Controls v8.1", "NIST 800-53"},
		Variables: []TemplateVar{
			{Name: "NodeVersion", Description: "Node.js version", Default: "20", Required: false},
			{Name: "Port", Description: "Application port", Default: "3000", Required: false},
			{Name: "EntryPoint", Description: "Entry point file", Default: "index.js", Required: false},
			{Name: "BuildCommand", Description: "Build command (optional)", Default: "", Required: false},
			{Name: "BuildOutput", Description: "Build output directory", Default: "dist", Required: false},
		},
	})

	r.register(&WorkflowTemplate{
		ID:          "dockerfile-python",
		Name:        "Hardened Python Dockerfile",
		Description: "CIS-compliant Dockerfile for Python applications",
		Category:    "docker",
		Tags:        []string{"python", "dockerfile", "slim", "cis"},
		Frameworks:  []string{"CIS Controls v8.1", "NIST 800-53"},
		Variables: []TemplateVar{
			{Name: "PythonVersion", Description: "Python version", Default: "3.12", Required: false},
			{Name: "Port", Description: "Application port", Default: "8000", Required: false},
			{Name: "EntryPoint", Description: "Entry point file", Default: "app.py", Required: false},
		},
	})

	r.register(&WorkflowTemplate{
		ID:          "dockerfile-java",
		Name:        "Hardened Java Dockerfile",
		Description: "CIS-compliant Dockerfile for Java applications using Eclipse Temurin",
		Category:    "docker",
		Tags:        []string{"java", "dockerfile", "temurin", "spring", "cis"},
		Frameworks:  []string{"CIS Controls v8.1", "NIST 800-53"},
		Variables: []TemplateVar{
			{Name: "JavaVersion", Description: "Java version", Default: "21", Required: false},
			{Name: "Port", Description: "Application port", Default: "8080", Required: false},
			{Name: "BuildTool", Description: "Build tool (maven or gradle)", Default: "maven", Required: false},
			{Name: "JarName", Description: "JAR file name", Default: "app.jar", Required: false},
		},
	})

	// Load template content from embedded files
	r.loadTemplateContent()
}

func (r *Registry) register(t *WorkflowTemplate) {
	r.templates[t.ID] = t
}

func (r *Registry) loadTemplateContent() {
	for id, tmpl := range r.templates {
		var content []byte
		var err error

		// Try loading from appropriate directory based on category
		if tmpl.Category == "docker" {
			// Remove "dockerfile-" prefix for file lookup
			filename := id
			if len(id) > 11 && id[:11] == "dockerfile-" {
				filename = id[11:] + "-hardened"
			}
			content, err = dockerfileFS.ReadFile(fmt.Sprintf("dockerfiles/%s.dockerfile", filename))
		} else {
			content, err = workflowFS.ReadFile(fmt.Sprintf("workflows/%s.yaml", id))
		}

		if err != nil {
			// Template file not found, will be created
			continue
		}
		tmpl.content = string(content)
	}
}

// List returns all available templates
func (r *Registry) List() []*WorkflowTemplate {
	result := make([]*WorkflowTemplate, 0, len(r.templates))
	for _, t := range r.templates {
		result = append(result, t)
	}
	return result
}

// Get returns a template by ID
func (r *Registry) Get(id string) (*WorkflowTemplate, error) {
	t, ok := r.templates[id]
	if !ok {
		return nil, fmt.Errorf("template not found: %s", id)
	}
	return t, nil
}

// ListByCategory returns templates filtered by category
func (r *Registry) ListByCategory(category string) []*WorkflowTemplate {
	result := make([]*WorkflowTemplate, 0)
	for _, t := range r.templates {
		if t.Category == category {
			result = append(result, t)
		}
	}
	return result
}

// ListByFramework returns templates that map to a compliance framework
func (r *Registry) ListByFramework(framework string) []*WorkflowTemplate {
	result := make([]*WorkflowTemplate, 0)
	for _, t := range r.templates {
		for _, f := range t.Frameworks {
			if f == framework {
				result = append(result, t)
				break
			}
		}
	}
	return result
}

// Generate renders a template with the provided context
func (r *Registry) Generate(id string, ctx *TemplateContext) (string, error) {
	tmpl, err := r.Get(id)
	if err != nil {
		return "", err
	}

	if tmpl.content == "" {
		return "", fmt.Errorf("template content not loaded for: %s", id)
	}

	// Build template data that includes both standard fields and custom variables
	data := make(map[string]interface{})
	data["OrgName"] = ctx.OrgName
	data["RepoName"] = ctx.RepoName
	data["DefaultBranch"] = ctx.DefaultBranch

	// Keep Custom map for backward compatibility with .Custom.field syntax
	data["Custom"] = ctx.Custom

	// Also merge custom variables at top level for simple access
	for k, v := range ctx.Custom {
		data[k] = v
	}

	// Add default values from template variables if not provided
	for _, v := range tmpl.Variables {
		if _, exists := data[v.Name]; !exists && v.Default != "" {
			data[v.Name] = v.Default
		}
	}

	// Parse and execute template
	t, err := template.New(id).Parse(tmpl.content)
	if err != nil {
		return "", fmt.Errorf("failed to parse template: %w", err)
	}

	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to execute template: %w", err)
	}

	return buf.String(), nil
}

// GetCategories returns all unique categories
func (r *Registry) GetCategories() []string {
	categorySet := make(map[string]bool)
	for _, t := range r.templates {
		categorySet[t.Category] = true
	}
	result := make([]string, 0, len(categorySet))
	for c := range categorySet {
		result = append(result, c)
	}
	return result
}
