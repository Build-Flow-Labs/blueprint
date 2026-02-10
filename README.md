# Blueprint

SBOM generation and vulnerability analysis toolkit for software supply chain security.

## Features

- **SBOM Generation**: Generate Software Bill of Materials in CycloneDX and SPDX formats
- **Vulnerability Analysis**: Analyze Trivy scan results with configurable gate thresholds
- **Workflow Templates**: Pre-built GitHub Actions workflows for security automation
- **Go Library**: Import packages directly into your Go applications

## Installation

### CLI

```bash
go install github.com/build-flow-labs/blueprint/cmd/blueprint@latest
```

### Go Library

```bash
go get github.com/build-flow-labs/blueprint
```

## CLI Usage

### SBOM Generation

Generate from local directory:
```bash
blueprint sbom generate --path . --format cyclonedx-json --output sbom.json
```

Generate from GitHub repository:
```bash
export GITHUB_TOKEN=ghp_xxx
blueprint sbom generate --org myorg --repo myrepo --format spdx-json
```

### Vulnerability Analysis

Analyze Trivy scan results:
```bash
# First, run Trivy
trivy fs --format json --output trivy.json .

# Then analyze with Blueprint
blueprint vuln analyze --input trivy.json --threshold no_critical_high
```

Gate thresholds:
- `no_critical` - Fail if any CRITICAL vulnerabilities
- `no_critical_high` - Fail if any CRITICAL or HIGH vulnerabilities (default)
- `no_critical_high_medium` - Fail if any CRITICAL, HIGH, or MEDIUM vulnerabilities
- `no_vulnerabilities` - Fail if any vulnerabilities exist

### Workflow Templates

List available templates:
```bash
blueprint template list
```

Get template content:
```bash
blueprint template get security-scan
```

Apply template to a repository:
```bash
export GITHUB_TOKEN=ghp_xxx
blueprint template apply --org myorg --repo myrepo --template security-scan
```

## GitHub Action

### SBOM Generation

```yaml
- uses: build-flow-labs/blueprint@v1
  with:
    command: sbom
    format: cyclonedx-json
    path: .
    output: sbom.json

- name: Upload SBOM
  uses: actions/upload-artifact@v4
  with:
    name: sbom
    path: sbom.json
```

### Vulnerability Gating

```yaml
- name: Run Trivy
  uses: aquasecurity/trivy-action@master
  with:
    scan-type: fs
    format: json
    output: trivy.json

- uses: build-flow-labs/blueprint@v1
  with:
    command: vuln
    trivy-results: trivy.json
    threshold: no_critical_high
```

## Go Library Usage

### SBOM Generation

```go
import "github.com/build-flow-labs/blueprint/sbom"

generator := sbom.NewGenerator()
result, err := generator.Generate(&sbom.GeneratorInput{
    OrgName:  "myorg",
    RepoName: "myrepo",
    Files: map[string]string{
        "go.mod": goModContent,
    },
    Format: sbom.FormatCycloneDXJSON,
})
```

### Vulnerability Analysis

```go
import "github.com/build-flow-labs/blueprint/vulnscan"

analyzer := vulnscan.NewAnalyzer(vulnscan.GateNoCriticalHigh)
analysis, err := analyzer.AnalyzeFromJSON(trivyOutput)

if !analysis.PassesGate {
    log.Fatalf("Security gate failed: %s", analysis.GateMessage)
}
```

## Supported Formats

### SBOM Output
- CycloneDX 1.4 JSON
- CycloneDX 1.4 XML
- SPDX 2.3 JSON

### Dependency Files
- Go: `go.mod`, `go.sum`
- npm: `package.json`, `package-lock.json`, `yarn.lock`
- Python: `requirements.txt`, `Pipfile`, `Pipfile.lock`
- Rust: `Cargo.toml`, `Cargo.lock`
- Java: `pom.xml`, `build.gradle`
- Ruby: `Gemfile`, `Gemfile.lock`
- PHP: `composer.json`

## License

MIT
