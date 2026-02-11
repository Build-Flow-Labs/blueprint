// Package schema defines the Pipeline Bill of Materials (PBOM) data model.
//
// A PBOM tracks how an artifact reached production — the build, the source,
// the security posture, and the promotion path — as opposed to an SBOM which
// tracks what is inside the artifact.
package schema

import "time"

const Version = "1.0.0"

// PBOM is the root document.
type PBOM struct {
	PBOMVersion string       `json:"pbom_version"`
	ID          string       `json:"id"`
	Timestamp   time.Time    `json:"timestamp"`
	Source      Source       `json:"source"`
	Build       Build        `json:"build"`
	Artifacts   []Artifact   `json:"artifacts,omitempty"`
	HealthScore *HealthScore `json:"health_score,omitempty"`
	Promotion   *Promotion   `json:"promotion,omitempty"`
}

// Source represents Phase A: the exact source code state.
type Source struct {
	Repository string `json:"repository"`
	CommitSHA  string `json:"commit_sha"`
	Branch     string `json:"branch,omitempty"`
	Ref        string `json:"ref,omitempty"`
	Author     string `json:"author,omitempty"`
}

// Build represents Phase A: the GitHub Actions execution context.
type Build struct {
	WorkflowRunID   string            `json:"workflow_run_id"`
	WorkflowName    string            `json:"workflow_name"`
	WorkflowFile    string            `json:"workflow_file,omitempty"`
	Trigger         string            `json:"trigger,omitempty"`
	Actor           string            `json:"actor"`
	Runner          *Runner           `json:"runner,omitempty"`
	ToolVersions    map[string]string `json:"tool_versions,omitempty"`
	SecretsAccessed []string          `json:"secrets_accessed,omitempty"`
	StartedAt       *time.Time        `json:"started_at,omitempty"`
	CompletedAt     *time.Time        `json:"completed_at,omitempty"`
	Status          string            `json:"status"`
}

// Runner describes the GitHub Actions runner environment.
type Runner struct {
	OS         string `json:"os,omitempty"`
	Arch       string `json:"arch,omitempty"`
	Name       string `json:"name,omitempty"`
	SelfHosted bool   `json:"self_hosted,omitempty"`
}

// Artifact represents Phase B: a produced artifact and its security posture.
type Artifact struct {
	Name            string          `json:"name"`
	Type            string          `json:"type"`
	Digest          string          `json:"digest"`
	URI             string          `json:"uri,omitempty"`
	Tags            []string        `json:"tags,omitempty"`
	Provenance      *Provenance     `json:"provenance,omitempty"`
	Vulnerabilities *Vulnerabilities `json:"vulnerabilities,omitempty"`
}

// Provenance holds SLSA attestation metadata.
type Provenance struct {
	SLSALevel      int    `json:"slsa_level,omitempty"`
	BuilderID      string `json:"builder_id,omitempty"`
	AttestationURI string `json:"attestation_uri,omitempty"`
}

// Vulnerabilities is a point-in-time snapshot of CVE counts at build time.
type Vulnerabilities struct {
	Scanner   string     `json:"scanner,omitempty"`
	ScannedAt *time.Time `json:"scanned_at,omitempty"`
	Critical  int        `json:"critical"`
	High      int        `json:"high"`
	Medium    int        `json:"medium"`
	Low       int        `json:"low"`
}

// HealthScore is a 4-axis pipeline health assessment.
type HealthScore struct {
	Grade          string      `json:"grade"`
	Score          int         `json:"score"`
	ToolCurrency   AxisScore   `json:"tool_currency"`
	SecretHygiene  AxisScore   `json:"secret_hygiene"`
	Provenance     AxisScore   `json:"provenance"`
	Vulnerability  AxisScore   `json:"vulnerability"`
}

// AxisScore is a single scoring axis with a letter grade and numeric score.
type AxisScore struct {
	Grade   string   `json:"grade"`
	Score   int      `json:"score"`
	Findings []string `json:"findings,omitempty"`
}

// Promotion represents Phase C: Kargo promotion data (deferred).
type Promotion struct {
	FreightID           string              `json:"freight_id,omitempty"`
	Stage               string              `json:"stage,omitempty"`
	PromotedBy          string              `json:"promoted_by,omitempty"`
	PromotedAt          *time.Time          `json:"promoted_at,omitempty"`
	EnvironmentSnapshot []CoDeployedService `json:"environment_snapshot,omitempty"`
}

// CoDeployedService describes another service present in the target
// environment at the time of promotion.
type CoDeployedService struct {
	Name    string `json:"name"`
	Digest  string `json:"digest,omitempty"`
	Version string `json:"version,omitempty"`
}
