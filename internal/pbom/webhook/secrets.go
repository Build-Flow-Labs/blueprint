package webhook

import (
	"regexp"
	"sort"
)

// secretsPattern matches ${{ secrets.SECRET_NAME }} references in workflow YAML.
var secretsPattern = regexp.MustCompile(`\$\{\{\s*secrets\.([A-Za-z_][A-Za-z0-9_]*)\s*\}\}`)

// ExtractSecretsFromWorkflow parses workflow YAML content and returns
// a deduplicated, sorted list of secret names referenced.
// GITHUB_TOKEN is excluded since it's always implicitly available.
func ExtractSecretsFromWorkflow(workflowYAML []byte) []string {
	matches := secretsPattern.FindAllSubmatch(workflowYAML, -1)
	seen := make(map[string]bool)
	var secrets []string

	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		name := string(match[1])
		if name == "GITHUB_TOKEN" {
			continue
		}
		if !seen[name] {
			seen[name] = true
			secrets = append(secrets, name)
		}
	}

	sort.Strings(secrets)
	return secrets
}
