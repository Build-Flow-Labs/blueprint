# Blueprint Roadmap

> Blueprint is the **bootstrap layer** of Build Flow Labs — a federal-aligned, pre-configured starter kit for secure software delivery.

## Build Flow Labs Ecosystem

```
┌─────────────────────────────────────────────────────────────┐
│                      BuildGuard                              │
│   Policy enforcement (23 policies, 8 compliance frameworks) │
│   OPA/Rego • Auto-remediation • Dashboard • Notifications   │
└─────────────────────────────────────────────────────────────┘
                              │ enforces
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                         PBOM                                 │
│   Evidence collection (cryptographic build lineage)         │
│   Tracks HOW artifacts were built • 4-axis health scoring   │
└─────────────────────────────────────────────────────────────┘
                              │ captures
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                       Blueprint                              │
│   Bootstrap templates & generation tools                     │
│   SBOM • Hardened Dockerfiles • CI/CD templates • PBOM      │
└─────────────────────────────────────────────────────────────┘
```

**Relationship:**
- **BuildGuard** = Policy enforcement ("what must happen")
- **PBOM** = Evidence capture ("proof it happened")
- **Blueprint** = Starter kit ("how to set it up")

---

## Current State (v1.0.0)

### Implemented
- [x] **SBOM Generation** — CycloneDX 1.4 (JSON/XML) and SPDX 2.3 (JSON)
- [x] **Dependency Parsing** — Go, npm, Python, Rust, Java, Ruby, PHP
- [x] **Vulnerability Analysis** — Trivy integration with configurable gate thresholds
- [x] **CLI** — `blueprint sbom generate`, `vuln analyze`, `template list/get/apply`
- [x] **GitHub Action** — Full action.yml for CI/CD integration
- [x] **Workflow Templates** — security-scan, dependency-review, sbom, signed-commits, buildguard-scan, oidc-aws-deploy
- [x] **Hardened Dockerfiles** — Go, Node, Python, Java (CIS-aligned)

### PBOM (Separate Project — Ready to Integrate)
Located at `../PBOM/` — fully functional, tested on BuildGuard-Test-Lab org (30 repos).

**Already built:**
- [x] CLI — generate, validate, inspect, score, filter, init, webhook
- [x] GitHub webhook listener for `workflow_run.completed` events
- [x] 4-axis health scoring (Tool Currency, Secret Hygiene, Provenance, Vulnerability)
- [x] Web dashboard (htmx, dark theme)
- [x] Org onboarding wizard (`pbom init`)
- [x] Required Workflow template for zero-touch collection

**PBOM remaining work:**
- [ ] ORAS registry integration (OCI referrer artifacts)
- [ ] Pipeline change notifications / diff engine
- [ ] Production readiness (Dockerfile, docker-compose)

---

## Phase 1: PBOM Integration (Next)

Merge PBOM into Blueprint as the evidence/lineage module.

### Option A: Unified CLI
```bash
blueprint sbom generate ...      # What's inside (existing)
blueprint pbom generate ...      # How it was built (from PBOM project)
blueprint pbom score ...
blueprint pbom webhook ...
```

### Option B: Shared Go Module
- Extract `github.com/build-flow-labs/pbom/pkg/schema` as shared types
- Blueprint imports PBOM for lineage tracking
- Both CLIs remain separate but interoperable

### Integration Tasks
- [ ] Decide on CLI structure (unified vs separate)
- [ ] Move/import PBOM packages into Blueprint
- [ ] Unified GitHub Action supporting both SBOM and PBOM
- [ ] Combined dashboard showing SBOM + PBOM data
- [ ] Update documentation

---

## Phase 2: Signing & Provenance

Complete the chain-of-custody with cryptographic attestations.

- [ ] **Sigstore/Cosign integration** — Sign SBOMs and PBOMs
- [ ] **SLSA provenance generation** — Level 2/3 attestations
- [ ] **Artifact signing workflow** — Template for container/binary signing
- [ ] **Verification commands** — `blueprint verify <artifact>`

---

## Phase 3: Extended Security Features

### Secret Scanning
- [ ] Pre-commit hooks for blocking sensitive keys
- [ ] Secret pattern detection library (regex + entropy)
- [ ] Git hooks integration template

### Additional Vulnerability Scanners
- [ ] Snyk integration
- [ ] Scanner abstraction layer for pluggable backends
- [ ] Unified vulnerability report format

### Additional OIDC Providers
- [ ] Azure OIDC deployment template
- [ ] GCP OIDC deployment template

---

## Phase 4: Infrastructure Templates

### Secrets Management
- [ ] HashiCorp Vault integration templates
- [ ] Secrets injection workflow

### CI/CD Enhancements
- [ ] Automated versioning workflows (semver)
- [ ] Changelog generation
- [ ] Self-hosted runner golden images

### Infrastructure as Code
- [ ] Ephemeral preview environment templates
- [ ] Terraform/OpenTofu modules
- [ ] Developer Portal / Service Catalog setup

---

## Future Enhancements

### Additional Package Ecosystems
- [ ] .NET/NuGet (`*.csproj`, `packages.config`)
- [ ] Swift/CocoaPods (`Package.swift`, `Podfile`)
- [ ] Dart/Flutter (`pubspec.yaml`)

### SBOM Features
- [ ] SBOM comparison/diff between versions
- [ ] SBOM merging for monorepos
- [ ] Dependency graph visualization

### Compliance & Licensing
- [ ] License compliance checking
- [ ] VEX (Vulnerability Exploitability eXchange) support
- [ ] EPSS integration

### Testing & Docs
- [ ] Integration tests for CLI
- [ ] End-to-end tests for GitHub Action
- [ ] API documentation for Go library

---

## Resources

### PBOM
- https://www.ox.security/blog/the-anatomy-of-a-pbom/
- https://www.ox.security/blog/pbom-vs-sbom/
- https://pbom.dev/

### Standards
- CycloneDX: https://cyclonedx.org/
- SPDX: https://spdx.dev/
- SLSA: https://slsa.dev/
- Sigstore: https://sigstore.dev/
