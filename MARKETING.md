# Blueprint Marketing Strategy

## Product Positioning

**Blueprint** is the **bootstrap layer** of Build Flow Labs — a proprietary, federal-aligned starter kit for secure software delivery.

### Product Hierarchy

```
BuildGuard (Policy Enforcement)      ← Premium SaaS
    ↓
Blueprint (Bootstrap + Evidence)     ← Paid Tool
    • SBOM generation
    • PBOM tracking
    • Hardened templates
    • Health scoring
```

---

## PBOM Market Position

### Competitive Landscape (as of Feb 2026)

| Player | PBOM Status |
|--------|-------------|
| OX Security | Coined term, proprietary SaaS, **no public spec** |
| Apiiro | Blogs about it, calls it XBOM, **no public spec** |
| pbom.dev | Community site, **no schema or tooling** |
| CycloneDX | Has OBOM (runtime), **not PBOM (build pipeline)** |
| **Build Flow Labs** | **First working implementation + schema** |

### Strategic Advantage

We have the **only working PBOM implementation**:
- JSON Schema v1.0.0
- 4-axis health scoring model
- CLI + webhook + dashboard
- Tested on real org (BuildGuard-Test-Lab, 30 repos)

**This is proprietary IP. Do not open-source.**

---

## Standardization Strategy

### Phase 1: Market Position First (Now)
- Keep schema, scoring, and tooling **proprietary**
- Build paying customer base
- Become the de facto PBOM tool through adoption
- "Blueprint PBOM" becomes synonymous with "PBOM"

### Phase 2: Industry Credibility (Later, 12-24 months)
- Once market leader, consider donating schema to CycloneDX/OWASP
- Position as "the battle-tested PBOM standard"
- Keep implementation (scoring, dashboard, enrichment) proprietary
- Competitors can implement schema, but Blueprint remains the reference

### Precedents
- **HashiCorp**: Terraform was proprietary for years before OpenTofu pressure
- **Docker**: Defined container format, then donated to OCI
- **Kubernetes**: Google open-sourced after proving the model internally

**Rule**: Define the standard by winning the market first. Formalize later.

---

## Messaging

### Tagline Options
- "From commit to compliance"
- "Know what's inside. Know how it got there."
- "SBOM + PBOM. Complete supply chain visibility."

### Key Differentiators
1. **First real PBOM** — Others talk about it, we ship it
2. **4-axis health scoring** — Not just data, but actionable grades
3. **Zero-touch collection** — Org webhooks, no developer friction
4. **Federal-aligned** — SLSA, FedRAMP, NIST 800-161 ready

### Target Buyers
| Persona | Pain Point | Blueprint Value |
|---------|------------|-----------------|
| Platform Engineer | "Our pipelines are a black box" | PBOM visibility |
| Security Lead | "We can't prove build integrity" | Health scores + provenance |
| Compliance Officer | "FedRAMP audits are painful" | Evidence collection |
| CISO | "Supply chain attacks scare me" | Complete lineage tracking |

---

## Pricing Considerations

### Blueprint (Paid)
- Per-org or per-repo pricing
- Tiers based on features:
  - **Starter**: SBOM + basic PBOM
  - **Pro**: Health scoring + dashboard + webhook
  - **Enterprise**: BuildGuard integration + SSO + support SLAs

### BuildGuard (Premium SaaS)
- Per-org pricing
- Policy enforcement + auto-remediation
- Includes Blueprint features

---

## Go-to-Market

### Phase 1: Developer Awareness
- Technical blog posts on PBOM concept
- Conference talks (KubeCon, DevSecCon)
- GitHub presence (but not the IP)

### Phase 2: Enterprise Sales
- Target FedRAMP-bound companies
- Partner with compliance consultants
- Case studies from early adopters

### Phase 3: Platform Partnerships
- GitHub Marketplace listing
- GitLab integration
- Cloud provider partnerships (AWS, Azure, GCP)
