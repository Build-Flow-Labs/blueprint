// Package detect probes the runner environment for installed build tools
// and returns their versions. Designed to run quickly on GHA runners —
// tools that aren't found are silently skipped.
package detect

import (
	"os/exec"
	"strings"
)

// probe defines a tool to detect: the binary name and the args that print
// a parseable version string.
type probe struct {
	Name string
	Bin  string
	Args []string
	// Parse extracts the version from stdout. If nil, the full
	// trimmed output is used.
	Parse func(string) string
}

var probes = []probe{
	{Name: "go", Bin: "go", Args: []string{"version"}, Parse: parseGo},
	{Name: "node", Bin: "node", Args: []string{"--version"}, Parse: trimV},
	{Name: "python", Bin: "python3", Args: []string{"--version"}, Parse: lastField},
	{Name: "java", Bin: "java", Args: []string{"-version"}, Parse: parseJava},
	{Name: "docker", Bin: "docker", Args: []string{"version", "--format", "{{.Client.Version}}"}},
	{Name: "kubectl", Bin: "kubectl", Args: []string{"version", "--client", "--short"}, Parse: lastField},
	{Name: "helm", Bin: "helm", Args: []string{"version", "--short"}, Parse: trimV},
	{Name: "ko", Bin: "ko", Args: []string{"version"}},
	{Name: "cargo", Bin: "cargo", Args: []string{"--version"}, Parse: lastField},
	{Name: "rustc", Bin: "rustc", Args: []string{"--version"}, Parse: secondField},
	{Name: "dotnet", Bin: "dotnet", Args: []string{"--version"}},
	{Name: "gradle", Bin: "gradle", Args: []string{"--version"}, Parse: parseGradle},
	{Name: "mvn", Bin: "mvn", Args: []string{"--version"}, Parse: parseMaven},
	{Name: "npm", Bin: "npm", Args: []string{"--version"}},
}

// ToolVersions probes the PATH for known build tools and returns a map
// of tool name → version string. Only tools that are found and return
// a parseable version are included. This is designed to be fast — each
// probe is a single exec with a short implicit timeout.
func ToolVersions() map[string]string {
	result := make(map[string]string)

	for _, p := range probes {
		if _, err := exec.LookPath(p.Bin); err != nil {
			continue
		}

		out, err := exec.Command(p.Bin, p.Args...).CombinedOutput()
		if err != nil {
			continue
		}

		version := strings.TrimSpace(string(out))
		if p.Parse != nil {
			version = p.Parse(version)
		}

		if version != "" {
			result[p.Name] = version
		}
	}

	return result
}

// parseGo: "go version go1.22.4 linux/amd64" → "1.22.4"
func parseGo(s string) string {
	for _, field := range strings.Fields(s) {
		if strings.HasPrefix(field, "go") && len(field) > 2 && field[2] >= '0' && field[2] <= '9' {
			return field[2:]
		}
	}
	return s
}

// trimV: "v20.11.0" → "20.11.0"
func trimV(s string) string {
	return strings.TrimPrefix(strings.TrimSpace(s), "v")
}

// lastField: "Python 3.12.1" → "3.12.1"
func lastField(s string) string {
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return s
	}
	return fields[len(fields)-1]
}

// secondField: "rustc 1.77.0 (aedd..." → "1.77.0"
func secondField(s string) string {
	fields := strings.Fields(s)
	if len(fields) < 2 {
		return s
	}
	return fields[1]
}

// parseJava: first line of java -version is like:
// openjdk version "21.0.1" 2023-10-17
func parseJava(s string) string {
	line := strings.Split(s, "\n")[0]
	if i := strings.Index(line, "\""); i >= 0 {
		if j := strings.Index(line[i+1:], "\""); j >= 0 {
			return line[i+1 : i+1+j]
		}
	}
	return lastField(line)
}

// parseGradle: multi-line output, look for "Gradle X.Y.Z"
func parseGradle(s string) string {
	for _, line := range strings.Split(s, "\n") {
		if strings.HasPrefix(line, "Gradle ") {
			return strings.TrimPrefix(line, "Gradle ")
		}
	}
	return ""
}

// parseMaven: first line like "Apache Maven 3.9.6 (...)"
func parseMaven(s string) string {
	line := strings.Split(s, "\n")[0]
	fields := strings.Fields(line)
	for i, f := range fields {
		if f == "Maven" && i+1 < len(fields) {
			return fields[i+1]
		}
	}
	return ""
}
