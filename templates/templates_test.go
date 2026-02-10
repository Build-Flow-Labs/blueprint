package templates

import (
	"strings"
	"testing"
)

func TestNewRegistry(t *testing.T) {
	r := NewRegistry()

	if r == nil {
		t.Fatal("NewRegistry returned nil")
	}

	templates := r.List()
	if len(templates) == 0 {
		t.Error("Registry should have built-in templates")
	}
}

func TestRegistryGet(t *testing.T) {
	r := NewRegistry()

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
		{"nonexistent", true},
	}

	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			tmpl, err := r.Get(tt.id)
			if tt.wantErr {
				if err == nil {
					t.Errorf("Get(%q) should return error", tt.id)
				}
			} else {
				if err != nil {
					t.Errorf("Get(%q) returned unexpected error: %v", tt.id, err)
				}
				if tmpl == nil {
					t.Errorf("Get(%q) returned nil template", tt.id)
				}
			}
		})
	}
}

func TestTemplateMetadata(t *testing.T) {
	r := NewRegistry()

	sbom, err := r.Get("sbom")
	if err != nil {
		t.Fatalf("Failed to get sbom template: %v", err)
	}

	if sbom.Name == "" {
		t.Error("Template should have a name")
	}
	if sbom.Description == "" {
		t.Error("Template should have a description")
	}
	if sbom.Category == "" {
		t.Error("Template should have a category")
	}
	if len(sbom.Frameworks) == 0 {
		t.Error("Template should have framework mappings")
	}
}

func TestListByCategory(t *testing.T) {
	r := NewRegistry()

	securityTemplates := r.ListByCategory("security")
	if len(securityTemplates) == 0 {
		t.Error("Should have security category templates")
	}

	for _, tmpl := range securityTemplates {
		if tmpl.Category != "security" {
			t.Errorf("Template %s has wrong category: %s", tmpl.ID, tmpl.Category)
		}
	}
}

func TestListByFramework(t *testing.T) {
	r := NewRegistry()

	soc2Templates := r.ListByFramework("SOC2")
	if len(soc2Templates) == 0 {
		t.Error("Should have SOC2 framework templates")
	}

	for _, tmpl := range soc2Templates {
		found := false
		for _, f := range tmpl.Frameworks {
			if f == "SOC2" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Template %s doesn't have SOC2 framework", tmpl.ID)
		}
	}
}

func TestGetCategories(t *testing.T) {
	r := NewRegistry()

	categories := r.GetCategories()
	if len(categories) == 0 {
		t.Error("Should have categories")
	}

	expectedCategories := []string{"supply-chain", "security", "governance", "compliance", "deployment"}
	for _, expected := range expectedCategories {
		found := false
		for _, c := range categories {
			if c == expected {
				found = true
				break
			}
		}
		if !found {
			t.Logf("Category %s not found in: %v", expected, categories)
		}
	}
}

func TestGenerate(t *testing.T) {
	r := NewRegistry()

	ctx := &TemplateContext{
		OrgName:       "TestOrg",
		RepoName:      "test-repo",
		DefaultBranch: "main",
		Custom:        map[string]string{"format": "spdx-json"},
	}

	content, err := r.Generate("sbom", ctx)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	if content == "" {
		t.Error("Generated content should not be empty")
	}

	// Check that template variables were substituted
	if !strings.Contains(content, "spdx-json") {
		t.Error("Custom format variable should be substituted")
	}
}

func TestGenerateWithDefaults(t *testing.T) {
	r := NewRegistry()

	ctx := &TemplateContext{
		OrgName:  "TestOrg",
		RepoName: "test-repo",
		Custom:   map[string]string{},
	}

	content, err := r.Generate("security-scan", ctx)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// Should use default severity
	if !strings.Contains(content, "CRITICAL,HIGH") {
		t.Error("Should use default severity value")
	}
}

func TestGenerateNonexistentTemplate(t *testing.T) {
	r := NewRegistry()

	ctx := &TemplateContext{}
	_, err := r.Generate("nonexistent", ctx)
	if err == nil {
		t.Error("Generate should return error for nonexistent template")
	}
}

func TestAllWorkflowTemplatesHaveContent(t *testing.T) {
	r := NewRegistry()

	for _, tmpl := range r.List() {
		// Skip docker templates - they have different structure
		if tmpl.Category == "docker" {
			continue
		}

		ctx := &TemplateContext{
			OrgName:       "TestOrg",
			DefaultBranch: "main",
			Custom:        map[string]string{},
		}

		content, err := r.Generate(tmpl.ID, ctx)
		if err != nil {
			t.Errorf("Template %s failed to generate: %v", tmpl.ID, err)
			continue
		}

		if content == "" {
			t.Errorf("Template %s generated empty content", tmpl.ID)
		}

		// Basic YAML validation - should have 'name:' and 'on:'
		if !strings.Contains(content, "name:") {
			t.Errorf("Template %s missing workflow name", tmpl.ID)
		}
		if !strings.Contains(content, "on:") {
			t.Errorf("Template %s missing trigger definition", tmpl.ID)
		}
		if !strings.Contains(content, "jobs:") {
			t.Errorf("Template %s missing jobs definition", tmpl.ID)
		}
	}
}

func TestDockerTemplatesHaveContent(t *testing.T) {
	r := NewRegistry()

	dockerTemplates := r.ListByCategory("docker")
	if len(dockerTemplates) == 0 {
		t.Skip("No docker templates found")
	}

	for _, tmpl := range dockerTemplates {
		// Docker templates use Custom map for variables
		ctx := &TemplateContext{
			OrgName:       "TestOrg",
			DefaultBranch: "main",
			Custom: map[string]string{
				"GoVersion":     "1.22",
				"MainPackage":   "./cmd/app",
				"NodeVersion":   "20",
				"Port":          "3000",
				"EntryPoint":    "index.js",
				"BuildCommand":  "",
				"BuildOutput":   "dist",
				"PythonVersion": "3.12",
				"JavaVersion":   "21",
				"BuildTool":     "maven",
				"JarName":       "app.jar",
			},
		}

		content, err := r.Generate(tmpl.ID, ctx)
		if err != nil {
			t.Errorf("Docker template %s failed to generate: %v", tmpl.ID, err)
			continue
		}

		if content == "" {
			t.Errorf("Docker template %s generated empty content", tmpl.ID)
		}

		// Validate docker-specific content
		if !strings.Contains(content, "FROM") {
			t.Errorf("Docker template %s missing FROM instruction", tmpl.ID)
		}
		if !strings.Contains(content, "USER") {
			t.Errorf("Docker template %s missing USER instruction (CIS 4.1)", tmpl.ID)
		}
		if !strings.Contains(content, "HEALTHCHECK") {
			t.Errorf("Docker template %s missing HEALTHCHECK instruction (CIS 4.5)", tmpl.ID)
		}
	}
}
