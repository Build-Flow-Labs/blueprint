package vulnscan

import (
	"strings"
)

// GateThreshold defines the vulnerability threshold for gating.
type GateThreshold string

const (
	// GateNoCritical fails if any CRITICAL vulnerabilities are found.
	GateNoCritical GateThreshold = "no_critical"
	// GateNoCriticalHigh fails if any CRITICAL or HIGH vulnerabilities are found.
	GateNoCriticalHigh GateThreshold = "no_critical_high"
	// GateNoCriticalHighMedium fails if any CRITICAL, HIGH, or MEDIUM vulnerabilities are found.
	GateNoCriticalHighMedium GateThreshold = "no_critical_high_medium"
	// GateNoVulnerabilities fails if any vulnerabilities are found.
	GateNoVulnerabilities GateThreshold = "no_vulnerabilities"
)

// VulnSummary contains counts of vulnerabilities by severity.
type VulnSummary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Unknown  int `json:"unknown"`
	Total    int `json:"total"`
}

// VulnAnalysis contains the analysis results and gate decision.
type VulnAnalysis struct {
	Summary       VulnSummary   `json:"summary"`
	PassesGate    bool          `json:"passes_gate"`
	GateThreshold GateThreshold `json:"gate_threshold"`
	GateMessage   string        `json:"gate_message"`
	TopFindings   []VulnFinding `json:"top_findings,omitempty"`
}

// VulnFinding represents a vulnerability finding in a simplified format.
type VulnFinding struct {
	ID          string `json:"id"`
	Package     string `json:"package"`
	Version     string `json:"version"`
	FixVersion  string `json:"fix_version,omitempty"`
	Severity    string `json:"severity"`
	Title       string `json:"title,omitempty"`
	HasFix      bool   `json:"has_fix"`
}

// Analyzer processes vulnerability scan results.
type Analyzer struct {
	Threshold     GateThreshold
	IgnoreUnfixed bool
}

// NewAnalyzer creates a new vulnerability analyzer with the specified threshold.
func NewAnalyzer(threshold GateThreshold) *Analyzer {
	return &Analyzer{
		Threshold:     threshold,
		IgnoreUnfixed: false,
	}
}

// Analyze processes a Trivy result and returns the analysis.
func (a *Analyzer) Analyze(result *TrivyResult) *VulnAnalysis {
	vulns := result.GetAllVulnerabilities()

	// Filter unfixed if configured
	if a.IgnoreUnfixed {
		var filtered []Vulnerability
		for _, v := range vulns {
			if v.HasFixedVersion() {
				filtered = append(filtered, v)
			}
		}
		vulns = filtered
	}

	// Calculate summary
	summary := a.calculateSummary(vulns)

	// Check gate
	passesGate, message := a.checkGate(summary)

	// Get top findings (up to 10)
	topFindings := a.getTopFindings(vulns, 10)

	return &VulnAnalysis{
		Summary:       summary,
		PassesGate:    passesGate,
		GateThreshold: a.Threshold,
		GateMessage:   message,
		TopFindings:   topFindings,
	}
}

// AnalyzeFromJSON parses JSON and returns the analysis.
func (a *Analyzer) AnalyzeFromJSON(data []byte) (*VulnAnalysis, error) {
	result, err := ParseTrivyJSON(data)
	if err != nil {
		return nil, err
	}
	return a.Analyze(result), nil
}

// calculateSummary counts vulnerabilities by severity.
func (a *Analyzer) calculateSummary(vulns []Vulnerability) VulnSummary {
	var summary VulnSummary
	summary.Total = len(vulns)

	for _, v := range vulns {
		switch NormalizeSeverity(v.Severity) {
		case SeverityCritical:
			summary.Critical++
		case SeverityHigh:
			summary.High++
		case SeverityMedium:
			summary.Medium++
		case SeverityLow:
			summary.Low++
		default:
			summary.Unknown++
		}
	}

	return summary
}

// checkGate determines if the scan passes the configured threshold.
func (a *Analyzer) checkGate(summary VulnSummary) (bool, string) {
	switch a.Threshold {
	case GateNoCritical:
		if summary.Critical > 0 {
			return false, "Gate failed: " + formatCount(summary.Critical, "critical") + " vulnerability(ies) found"
		}
		return true, "Gate passed: no critical vulnerabilities"

	case GateNoCriticalHigh:
		if summary.Critical > 0 || summary.High > 0 {
			counts := []string{}
			if summary.Critical > 0 {
				counts = append(counts, formatCount(summary.Critical, "critical"))
			}
			if summary.High > 0 {
				counts = append(counts, formatCount(summary.High, "high"))
			}
			return false, "Gate failed: " + strings.Join(counts, " and ") + " vulnerability(ies) found"
		}
		return true, "Gate passed: no critical or high vulnerabilities"

	case GateNoCriticalHighMedium:
		if summary.Critical > 0 || summary.High > 0 || summary.Medium > 0 {
			counts := []string{}
			if summary.Critical > 0 {
				counts = append(counts, formatCount(summary.Critical, "critical"))
			}
			if summary.High > 0 {
				counts = append(counts, formatCount(summary.High, "high"))
			}
			if summary.Medium > 0 {
				counts = append(counts, formatCount(summary.Medium, "medium"))
			}
			return false, "Gate failed: " + strings.Join(counts, ", ") + " vulnerability(ies) found"
		}
		return true, "Gate passed: no critical, high, or medium vulnerabilities"

	case GateNoVulnerabilities:
		if summary.Total > 0 {
			return false, "Gate failed: " + formatCount(summary.Total, "") + " vulnerability(ies) found"
		}
		return true, "Gate passed: no vulnerabilities"

	default:
		// Default to no_critical_high
		if summary.Critical > 0 || summary.High > 0 {
			return false, "Gate failed: critical or high vulnerabilities found"
		}
		return true, "Gate passed"
	}
}

// getTopFindings returns the most severe findings.
func (a *Analyzer) getTopFindings(vulns []Vulnerability, limit int) []VulnFinding {
	// Sort by severity (critical first)
	sorted := make([]Vulnerability, len(vulns))
	copy(sorted, vulns)

	// Simple bubble sort by severity rank (descending)
	for i := 0; i < len(sorted)-1; i++ {
		for j := 0; j < len(sorted)-i-1; j++ {
			if SeverityRank(sorted[j].Severity) < SeverityRank(sorted[j+1].Severity) {
				sorted[j], sorted[j+1] = sorted[j+1], sorted[j]
			}
		}
	}

	// Take top N
	if len(sorted) > limit {
		sorted = sorted[:limit]
	}

	findings := make([]VulnFinding, 0, len(sorted))
	for _, v := range sorted {
		findings = append(findings, VulnFinding{
			ID:         v.VulnerabilityID,
			Package:    v.PkgName,
			Version:    v.InstalledVersion,
			FixVersion: v.FixedVersion,
			Severity:   NormalizeSeverity(v.Severity),
			Title:      v.Title,
			HasFix:     v.HasFixedVersion(),
		})
	}

	return findings
}

// formatCount returns a formatted count string.
func formatCount(count int, severity string) string {
	if severity != "" {
		return strings.ToLower(severity) + "(" + string(rune('0'+count%10)) + ")"
	}
	return string(rune('0' + count%10))
}

// ParseGateThreshold converts a string to a GateThreshold.
func ParseGateThreshold(s string) GateThreshold {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "no_critical", "critical":
		return GateNoCritical
	case "no_critical_high", "critical_high", "high":
		return GateNoCriticalHigh
	case "no_critical_high_medium", "medium":
		return GateNoCriticalHighMedium
	case "no_vulnerabilities", "none", "all":
		return GateNoVulnerabilities
	default:
		return GateNoCriticalHigh
	}
}
