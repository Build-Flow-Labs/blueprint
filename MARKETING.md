# Blueprint Marketing Strategy

## Relationship with buildflowlabs.com

**Build Flow Labs** is the company. **Blueprint** and **BuildGuard** are the products.

### Brand Architecture

```
Build Flow Labs (Company)
├── buildflowlabs.com        ← Company website, thought leadership
├── BuildGuard               ← Flagship SaaS product (policy enforcement)
└── Blueprint                ← Developer toolkit (SBOM + PBOM generation)
```

### Website Strategy

| Domain | Purpose |
|--------|---------|
| buildflowlabs.com | Company site, advisory services, blog, contact |
| buildflowlabs.com/buildguard | BuildGuard product pages, pricing, demo requests |
| buildflowlabs.com/blueprint | Blueprint product pages, docs, download |

### Content Strategy

**buildflowlabs.com** should:
- Establish thought leadership on supply chain security
- Publish PBOM educational content (we coined the implementation)
- Drive leads to both products
- Showcase advisory tiers (Foundational Sprint → High-Trust Enterprise)

**Blueprint-specific content**:
- Technical docs and CLI reference (behind login/license)
- Integration guides (GitHub Actions, GitLab CI)
- PBOM concepts explained (not the schema itself)

### Revenue Relationship

```
Blueprint (Entry Point)          →    BuildGuard (Upsell)
─────────────────────────────────      ────────────────────────
Self-serve, per-repo pricing           Enterprise, per-org pricing
Generates SBOMs + PBOMs                Enforces policies on them
"Generate evidence"                    "Prove compliance"
```

Blueprint can be sold standalone, but the full value comes with BuildGuard integration.

---

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

## IP Protection Strategy

### Fully Proprietary
- **No open source** — Blueprint and PBOM are commercial products
- Schema, scoring algorithms, and tooling remain closed source
- Source code in private repositories only
- Customers get binaries/SaaS access, not source

### What We Protect
| Asset | Protection Level |
|-------|------------------|
| PBOM JSON Schema | Proprietary, not published |
| 4-axis scoring algorithm | Proprietary, core IP |
| Health score weights/thresholds | Proprietary |
| Webhook enrichment pipeline | Proprietary |
| Dashboard and UI | Proprietary |
| CLI source code | Proprietary |

### Standardization (Future, Optional)
- **Only consider** if/when we have dominant market position
- Would only publish schema, never implementation
- Decision to be made later — no commitment now
- Default position: keep everything proprietary

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
- Technical blog posts on PBOM concept (educate, don't reveal implementation)
- Conference talks (KubeCon, DevSecCon)
- Demo videos and webinars

### Phase 2: Enterprise Sales
- Target FedRAMP-bound companies
- Partner with compliance consultants
- Case studies from early adopters

### Phase 3: Platform Partnerships
- GitHub Marketplace listing
- GitLab integration
- Cloud provider partnerships (AWS, Azure, GCP)
