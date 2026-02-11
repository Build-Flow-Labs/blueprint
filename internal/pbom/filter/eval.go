package filter

import "fmt"

// Evaluate checks whether a repo should be included based on its custom
// properties and the filtering rules in the config. Returns (true, reason)
// for include, (false, reason) for exclude. Rules are evaluated top-to-bottom;
// first match wins. If no rules match, default_action applies.
func Evaluate(cfg *Config, properties map[string]string) (bool, string) {
	for _, rule := range cfg.Filtering.Rules {
		propVal, exists := properties[rule.Property]
		if !exists {
			continue
		}

		if matches(rule, propVal) {
			included := rule.Action == "include"
			reason := fmt.Sprintf("matched rule: property %q = %q → %s", rule.Property, propVal, rule.Action)
			return included, reason
		}
	}

	included := cfg.Filtering.DefaultAction == "include"
	reason := fmt.Sprintf("no rules matched → default_action %q", cfg.Filtering.DefaultAction)
	return included, reason
}

// matches checks if a property value satisfies a rule's value or values list.
func matches(rule Rule, propVal string) bool {
	if rule.Value != "" && propVal == rule.Value {
		return true
	}
	for _, v := range rule.Values {
		if propVal == v {
			return true
		}
	}
	return false
}
