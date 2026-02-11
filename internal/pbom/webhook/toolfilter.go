package webhook

// languageTools maps GitHub language names to the build tools they use.
var languageTools = map[string][]string{
	"Go":         {"go", "docker"},
	"Python":     {"python", "docker"},
	"JavaScript": {"node", "npm", "docker"},
	"TypeScript": {"node", "npm", "docker"},
	"Java":       {"java", "gradle", "mvn", "docker"},
	"Kotlin":     {"java", "gradle", "mvn", "docker"},
	"Scala":      {"java", "gradle", "mvn", "docker"},
	"Rust":       {"rustc", "cargo", "docker"},
	"C#":         {"dotnet", "docker"},
	"F#":         {"dotnet", "docker"},
	"Dockerfile": {"docker"},
	"HCL":        {"helm", "docker"},
	"Shell":      {"docker"},
}

// universalTools are always relevant regardless of language.
var universalTools = []string{"docker"}

// FilterToolVersions reduces a tool version map to only tools relevant
// to the repo's detected languages. Returns the original map unfiltered
// if languages is empty or no recognized languages are found.
func FilterToolVersions(toolVersions map[string]string, languages map[string]int64) map[string]string {
	if len(languages) == 0 || len(toolVersions) == 0 {
		return toolVersions
	}

	relevant := make(map[string]bool)
	for _, tool := range universalTools {
		relevant[tool] = true
	}

	matched := false
	for lang := range languages {
		if tools, ok := languageTools[lang]; ok {
			matched = true
			for _, tool := range tools {
				relevant[tool] = true
			}
		}
	}

	// If no languages matched our map, return unfiltered to avoid data loss
	if !matched {
		return toolVersions
	}

	filtered := make(map[string]string)
	for tool, version := range toolVersions {
		if relevant[tool] {
			filtered[tool] = version
		}
	}
	return filtered
}
