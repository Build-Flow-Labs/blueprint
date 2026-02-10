// Package vulnscan provides vulnerability scanning and analysis capabilities.
// It parses Trivy scan results and provides gating logic for deployment pipelines.
package vulnscan

import (
	"encoding/json"
	"strings"
)

// Severity levels for vulnerabilities
const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
	SeverityLow      = "LOW"
	SeverityUnknown  = "UNKNOWN"
)

// Vulnerability represents a single vulnerability finding.
type Vulnerability struct {
	VulnerabilityID  string   `json:"VulnerabilityID"`
	PkgName          string   `json:"PkgName"`
	InstalledVersion string   `json:"InstalledVersion"`
	FixedVersion     string   `json:"FixedVersion,omitempty"`
	Severity         string   `json:"Severity"`
	Title            string   `json:"Title,omitempty"`
	Description      string   `json:"Description,omitempty"`
	References       []string `json:"References,omitempty"`
	CVSS             *CVSS    `json:"CVSS,omitempty"`
	PublishedDate    string   `json:"PublishedDate,omitempty"`
	LastModifiedDate string   `json:"LastModifiedDate,omitempty"`
}

// CVSS contains CVSS scoring information.
type CVSS struct {
	V2Score  float64 `json:"V2Score,omitempty"`
	V3Score  float64 `json:"V3Score,omitempty"`
	V2Vector string  `json:"V2Vector,omitempty"`
	V3Vector string  `json:"V3Vector,omitempty"`
}

// TrivyTarget represents a scanned target (e.g., a container image layer or file).
type TrivyTarget struct {
	Target          string          `json:"Target"`
	Class           string          `json:"Class,omitempty"`
	Type            string          `json:"Type,omitempty"`
	Vulnerabilities []Vulnerability `json:"Vulnerabilities,omitempty"`
}

// TrivyResult represents the complete Trivy scan output.
type TrivyResult struct {
	SchemaVersion int           `json:"SchemaVersion,omitempty"`
	ArtifactName  string        `json:"ArtifactName,omitempty"`
	ArtifactType  string        `json:"ArtifactType,omitempty"`
	Metadata      *TrivyMeta    `json:"Metadata,omitempty"`
	Results       []TrivyTarget `json:"Results,omitempty"`
}

// TrivyMeta contains metadata about the scanned artifact.
type TrivyMeta struct {
	OS          *OSInfo         `json:"OS,omitempty"`
	ImageID     string          `json:"ImageID,omitempty"`
	DiffIDs     []string        `json:"DiffIDs,omitempty"`
	RepoTags    []string        `json:"RepoTags,omitempty"`
	RepoDigests []string        `json:"RepoDigests,omitempty"`
	ImageConfig json.RawMessage `json:"ImageConfig,omitempty"`
}

// OSInfo contains OS information from the scan.
type OSInfo struct {
	Family string `json:"Family"`
	Name   string `json:"Name"`
}

// ParseTrivyJSON parses Trivy JSON output into a structured result.
func ParseTrivyJSON(data []byte) (*TrivyResult, error) {
	var result TrivyResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetAllVulnerabilities returns all vulnerabilities from all targets.
func (r *TrivyResult) GetAllVulnerabilities() []Vulnerability {
	var all []Vulnerability
	for _, target := range r.Results {
		all = append(all, target.Vulnerabilities...)
	}
	return all
}

// FilterBySeverity returns vulnerabilities matching the given severities.
func (r *TrivyResult) FilterBySeverity(severities ...string) []Vulnerability {
	sevMap := make(map[string]bool)
	for _, s := range severities {
		sevMap[strings.ToUpper(s)] = true
	}

	var filtered []Vulnerability
	for _, v := range r.GetAllVulnerabilities() {
		if sevMap[strings.ToUpper(v.Severity)] {
			filtered = append(filtered, v)
		}
	}
	return filtered
}

// HasFixedVersion returns true if the vulnerability has a known fix.
func (v *Vulnerability) HasFixedVersion() bool {
	return v.FixedVersion != "" && v.FixedVersion != "none"
}

// NormalizeSeverity converts various severity formats to standard form.
func NormalizeSeverity(severity string) string {
	switch strings.ToUpper(strings.TrimSpace(severity)) {
	case "CRITICAL", "CRIT":
		return SeverityCritical
	case "HIGH":
		return SeverityHigh
	case "MEDIUM", "MODERATE", "MED":
		return SeverityMedium
	case "LOW":
		return SeverityLow
	default:
		return SeverityUnknown
	}
}

// SeverityRank returns a numeric rank for severity comparison.
// Higher rank means more severe.
func SeverityRank(severity string) int {
	switch NormalizeSeverity(severity) {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 0
	}
}
