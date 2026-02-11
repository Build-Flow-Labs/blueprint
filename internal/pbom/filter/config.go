package filter

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config is the top-level structure of pbom-config.yml.
type Config struct {
	Version   string       `yaml:"version"`
	Filtering FilterConfig `yaml:"filtering"`
}

// FilterConfig holds the filtering rules and default action.
type FilterConfig struct {
	DefaultAction string `yaml:"default_action"`
	Rules         []Rule `yaml:"rules"`
}

// Rule defines a single filter rule that matches a GitHub custom property.
type Rule struct {
	Property string   `yaml:"property"`
	Value    string   `yaml:"value,omitempty"`
	Values   []string `yaml:"values,omitempty"`
	Action   string   `yaml:"action"`
}

// LoadConfig reads and validates a pbom-config.yml file.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config YAML: %w", err)
	}

	if err := validateConfig(&cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

func validateConfig(cfg *Config) error {
	if cfg.Version == "" {
		return fmt.Errorf("config missing required field: version")
	}

	action := cfg.Filtering.DefaultAction
	if action != "include" && action != "exclude" {
		return fmt.Errorf("invalid default_action %q: must be \"include\" or \"exclude\"", action)
	}

	for i, r := range cfg.Filtering.Rules {
		if r.Property == "" {
			return fmt.Errorf("rule %d: missing required field: property", i)
		}
		if r.Value == "" && len(r.Values) == 0 {
			return fmt.Errorf("rule %d: must specify value or values", i)
		}
		if r.Action != "include" && r.Action != "exclude" {
			return fmt.Errorf("rule %d: invalid action %q: must be \"include\" or \"exclude\"", i, r.Action)
		}
	}

	return nil
}
