package filter

import (
	"os"
	"path/filepath"
	"testing"
)

// helper to build a Config inline for tests.
func makeConfig(defaultAction string, rules []Rule) *Config {
	return &Config{
		Version: "1.0",
		Filtering: FilterConfig{
			DefaultAction: defaultAction,
			Rules:         rules,
		},
	}
}

func TestDefaultActionExclude(t *testing.T) {
	cfg := makeConfig("exclude", nil)
	included, reason := Evaluate(cfg, map[string]string{"foo": "bar"})
	if included {
		t.Fatalf("expected exclude, got include: %s", reason)
	}
}

func TestDefaultActionInclude(t *testing.T) {
	cfg := makeConfig("include", nil)
	included, reason := Evaluate(cfg, map[string]string{"foo": "bar"})
	if !included {
		t.Fatalf("expected include, got exclude: %s", reason)
	}
}

func TestSingleValueMatch(t *testing.T) {
	cfg := makeConfig("exclude", []Rule{
		{Property: "pbom-enabled", Value: "true", Action: "include"},
	})
	included, reason := Evaluate(cfg, map[string]string{"pbom-enabled": "true"})
	if !included {
		t.Fatalf("expected include, got exclude: %s", reason)
	}
}

func TestSingleValueNoMatch(t *testing.T) {
	cfg := makeConfig("exclude", []Rule{
		{Property: "pbom-enabled", Value: "true", Action: "include"},
	})
	included, reason := Evaluate(cfg, map[string]string{"pbom-enabled": "false"})
	if included {
		t.Fatalf("expected exclude, got include: %s", reason)
	}
}

func TestMultiValueMatch(t *testing.T) {
	cfg := makeConfig("exclude", []Rule{
		{Property: "tier", Values: []string{"production", "staging"}, Action: "include"},
	})

	for _, val := range []string{"production", "staging"} {
		included, reason := Evaluate(cfg, map[string]string{"tier": val})
		if !included {
			t.Fatalf("expected include for tier=%s, got exclude: %s", val, reason)
		}
	}
}

func TestMultiValueNoMatch(t *testing.T) {
	cfg := makeConfig("exclude", []Rule{
		{Property: "tier", Values: []string{"production", "staging"}, Action: "include"},
	})
	included, reason := Evaluate(cfg, map[string]string{"tier": "development"})
	if included {
		t.Fatalf("expected exclude, got include: %s", reason)
	}
}

func TestFirstMatchWins(t *testing.T) {
	cfg := makeConfig("exclude", []Rule{
		{Property: "lifecycle", Value: "deprecated", Action: "exclude"},
		{Property: "pbom-enabled", Value: "true", Action: "include"},
	})
	// Both properties set; the first matching rule (exclude) should win.
	props := map[string]string{
		"lifecycle":    "deprecated",
		"pbom-enabled": "true",
	}
	included, reason := Evaluate(cfg, props)
	if included {
		t.Fatalf("expected exclude (first match wins), got include: %s", reason)
	}
}

func TestExcludeRuleOverride(t *testing.T) {
	cfg := makeConfig("include", []Rule{
		{Property: "lifecycle", Value: "deprecated", Action: "exclude"},
	})
	included, reason := Evaluate(cfg, map[string]string{"lifecycle": "deprecated"})
	if included {
		t.Fatalf("expected exclude via rule, got include: %s", reason)
	}
}

func TestEmptyProperties(t *testing.T) {
	cfg := makeConfig("exclude", []Rule{
		{Property: "pbom-enabled", Value: "true", Action: "include"},
	})
	included, reason := Evaluate(cfg, map[string]string{})
	if included {
		t.Fatalf("expected exclude (empty properties), got include: %s", reason)
	}
}

func TestMissingProperty(t *testing.T) {
	cfg := makeConfig("exclude", []Rule{
		{Property: "pbom-enabled", Value: "true", Action: "include"},
	})
	included, reason := Evaluate(cfg, map[string]string{"other-prop": "whatever"})
	if included {
		t.Fatalf("expected exclude (property not present), got include: %s", reason)
	}
}

func TestNilProperties(t *testing.T) {
	cfg := makeConfig("include", nil)
	included, reason := Evaluate(cfg, nil)
	if !included {
		t.Fatalf("expected include (nil properties, default include), got exclude: %s", reason)
	}
}

// --- LoadConfig / validation tests ---

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "pbom-config.yml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadConfigValid(t *testing.T) {
	yaml := `
version: "1.0"
filtering:
  default_action: exclude
  rules:
    - property: "pbom-enabled"
      value: "true"
      action: include
    - property: "tier"
      values:
        - "production"
        - "staging"
      action: include
`
	path := writeTemp(t, yaml)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Version != "1.0" {
		t.Fatalf("expected version 1.0, got %s", cfg.Version)
	}
	if len(cfg.Filtering.Rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(cfg.Filtering.Rules))
	}
}

func TestLoadConfigMissingVersion(t *testing.T) {
	yaml := `
filtering:
  default_action: exclude
  rules: []
`
	path := writeTemp(t, yaml)
	_, err := LoadConfig(path)
	if err == nil {
		t.Fatal("expected error for missing version")
	}
}

func TestLoadConfigBadDefaultAction(t *testing.T) {
	yaml := `
version: "1.0"
filtering:
  default_action: maybe
  rules: []
`
	path := writeTemp(t, yaml)
	_, err := LoadConfig(path)
	if err == nil {
		t.Fatal("expected error for invalid default_action")
	}
}

func TestLoadConfigRuleMissingProperty(t *testing.T) {
	yaml := `
version: "1.0"
filtering:
  default_action: exclude
  rules:
    - value: "true"
      action: include
`
	path := writeTemp(t, yaml)
	_, err := LoadConfig(path)
	if err == nil {
		t.Fatal("expected error for rule missing property")
	}
}

func TestLoadConfigRuleMissingValue(t *testing.T) {
	yaml := `
version: "1.0"
filtering:
  default_action: exclude
  rules:
    - property: "foo"
      action: include
`
	path := writeTemp(t, yaml)
	_, err := LoadConfig(path)
	if err == nil {
		t.Fatal("expected error for rule missing value/values")
	}
}

func TestLoadConfigRuleBadAction(t *testing.T) {
	yaml := `
version: "1.0"
filtering:
  default_action: exclude
  rules:
    - property: "foo"
      value: "bar"
      action: maybe
`
	path := writeTemp(t, yaml)
	_, err := LoadConfig(path)
	if err == nil {
		t.Fatal("expected error for invalid rule action")
	}
}

func TestLoadConfigFileNotFound(t *testing.T) {
	_, err := LoadConfig("/nonexistent/path/config.yml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}
