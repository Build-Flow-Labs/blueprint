# Blueprint Roadmap

## Priority: Features from buildflowlabs.com

### PBOM (Pipeline Bill of Materials)
- [ ] Automated capture of build environment metadata
- [ ] CI runner version tracking
- [ ] Build script recording
- [ ] Environment variables capture (sanitized)
- [ ] Toolchain metadata collection

### Secret Scanning
- [ ] Pre-commit hooks for blocking sensitive keys
- [ ] Secret pattern detection library
- [ ] Integration with git hooks

### Code Linting & Pre-commit
- [ ] Pre-commit configuration templates
- [ ] Automated formatting enforcement
- [ ] Language-specific linter configurations

### Additional OIDC Providers
- [ ] Azure OIDC deployment template
- [ ] GCP OIDC deployment template

### Additional Vulnerability Scanners
- [ ] Snyk integration (currently Trivy only)
- [ ] Scanner abstraction layer for pluggable backends

### Signing & Provenance
- [ ] Sigstore/Cosign integration
- [ ] Build artifact signing
- [ ] SLSA provenance generation

### Secrets Management
- [ ] HashiCorp Vault integration
- [ ] Secrets injection templates

### CI/CD Enhancements
- [ ] Automated versioning workflows
- [ ] Changelog generation
- [ ] Self-hosted runner golden images

### Infrastructure
- [ ] Ephemeral preview environment templates
- [ ] Terraform/OpenTofu IaC templates
- [ ] Developer Portal / Service Catalog setup

---

## Future Enhancements

### Additional Package Ecosystems
- [ ] .NET/NuGet (`*.csproj`, `packages.config`, `*.nuspec`)
- [ ] Swift/CocoaPods (`Package.swift`, `Podfile`, `Podfile.lock`)
- [ ] Dart/Flutter (`pubspec.yaml`, `pubspec.lock`)

### SBOM Features
- [ ] SBOM comparison/diff between versions
- [ ] SBOM merging for monorepos
- [ ] Dependency graph visualization

### Vulnerability Management
- [ ] VEX (Vulnerability Exploitability eXchange) support
- [ ] Custom vulnerability ignore rules
- [ ] EPSS (Exploit Prediction Scoring System) integration

### Compliance & Licensing
- [ ] License compliance checking and policy enforcement
- [ ] License compatibility analysis
- [ ] SPDX license expression parsing

### Testing & CI
- [ ] Integration tests for CLI commands
- [ ] End-to-end tests for GitHub Action
- [ ] CI workflow for the project itself

### Documentation
- [ ] API documentation for Go library
- [ ] Example integrations and tutorials
