package vulnscan

import (
	"testing"
)

var sampleTrivyOutput = []byte(`{
  "SchemaVersion": 2,
  "ArtifactName": "myapp:latest",
  "ArtifactType": "container_image",
  "Results": [
    {
      "Target": "myapp:latest (alpine 3.18.4)",
      "Class": "os-pkgs",
      "Type": "alpine",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2023-12345",
          "PkgName": "libcrypto3",
          "InstalledVersion": "3.1.2-r0",
          "FixedVersion": "3.1.3-r0",
          "Severity": "CRITICAL",
          "Title": "OpenSSL: Buffer overflow vulnerability"
        },
        {
          "VulnerabilityID": "CVE-2023-67890",
          "PkgName": "libssl3",
          "InstalledVersion": "3.1.2-r0",
          "FixedVersion": "3.1.3-r0",
          "Severity": "HIGH",
          "Title": "OpenSSL: TLS handshake vulnerability"
        },
        {
          "VulnerabilityID": "CVE-2023-11111",
          "PkgName": "zlib",
          "InstalledVersion": "1.2.13-r0",
          "Severity": "MEDIUM",
          "Title": "zlib: Memory corruption on malformed input"
        },
        {
          "VulnerabilityID": "CVE-2023-22222",
          "PkgName": "busybox",
          "InstalledVersion": "1.36.1-r2",
          "FixedVersion": "1.36.1-r3",
          "Severity": "LOW",
          "Title": "busybox: Minor information disclosure"
        }
      ]
    }
  ]
}`)

func TestParseTrivyJSON(t *testing.T) {
	result, err := ParseTrivyJSON(sampleTrivyOutput)
	if err != nil {
		t.Fatalf("Failed to parse Trivy JSON: %v", err)
	}

	if result.ArtifactName != "myapp:latest" {
		t.Errorf("Expected ArtifactName 'myapp:latest', got '%s'", result.ArtifactName)
	}

	if len(result.Results) != 1 {
		t.Errorf("Expected 1 result, got %d", len(result.Results))
	}

	vulns := result.GetAllVulnerabilities()
	if len(vulns) != 4 {
		t.Errorf("Expected 4 vulnerabilities, got %d", len(vulns))
	}
}

func TestFilterBySeverity(t *testing.T) {
	result, _ := ParseTrivyJSON(sampleTrivyOutput)

	critical := result.FilterBySeverity("CRITICAL")
	if len(critical) != 1 {
		t.Errorf("Expected 1 critical vulnerability, got %d", len(critical))
	}

	criticalHigh := result.FilterBySeverity("CRITICAL", "HIGH")
	if len(criticalHigh) != 2 {
		t.Errorf("Expected 2 critical/high vulnerabilities, got %d", len(criticalHigh))
	}
}

func TestAnalyzerSummary(t *testing.T) {
	result, _ := ParseTrivyJSON(sampleTrivyOutput)
	analyzer := NewAnalyzer(GateNoCriticalHigh)
	analysis := analyzer.Analyze(result)

	if analysis.Summary.Critical != 1 {
		t.Errorf("Expected 1 critical, got %d", analysis.Summary.Critical)
	}
	if analysis.Summary.High != 1 {
		t.Errorf("Expected 1 high, got %d", analysis.Summary.High)
	}
	if analysis.Summary.Medium != 1 {
		t.Errorf("Expected 1 medium, got %d", analysis.Summary.Medium)
	}
	if analysis.Summary.Low != 1 {
		t.Errorf("Expected 1 low, got %d", analysis.Summary.Low)
	}
	if analysis.Summary.Total != 4 {
		t.Errorf("Expected 4 total, got %d", analysis.Summary.Total)
	}
}

func TestGateNoCritical(t *testing.T) {
	result, _ := ParseTrivyJSON(sampleTrivyOutput)
	analyzer := NewAnalyzer(GateNoCritical)
	analysis := analyzer.Analyze(result)

	if analysis.PassesGate {
		t.Error("Expected gate to fail with critical vulnerability")
	}
	if analysis.GateThreshold != GateNoCritical {
		t.Errorf("Expected threshold 'no_critical', got '%s'", analysis.GateThreshold)
	}
}

func TestGateNoCriticalHigh(t *testing.T) {
	result, _ := ParseTrivyJSON(sampleTrivyOutput)
	analyzer := NewAnalyzer(GateNoCriticalHigh)
	analysis := analyzer.Analyze(result)

	if analysis.PassesGate {
		t.Error("Expected gate to fail with critical and high vulnerabilities")
	}
}

func TestGatePassesWithNoVulns(t *testing.T) {
	emptyResult := &TrivyResult{
		Results: []TrivyTarget{
			{
				Target:          "clean:latest",
				Vulnerabilities: []Vulnerability{},
			},
		},
	}

	analyzer := NewAnalyzer(GateNoCriticalHigh)
	analysis := analyzer.Analyze(emptyResult)

	if !analysis.PassesGate {
		t.Error("Expected gate to pass with no vulnerabilities")
	}
}

func TestIgnoreUnfixed(t *testing.T) {
	result, _ := ParseTrivyJSON(sampleTrivyOutput)
	analyzer := NewAnalyzer(GateNoCriticalHighMedium)
	analyzer.IgnoreUnfixed = true
	analysis := analyzer.Analyze(result)

	// Medium vuln has no fixed version, so should be excluded
	// Only 3 vulns should be counted
	if analysis.Summary.Medium != 0 {
		t.Errorf("Expected 0 medium (unfixed ignored), got %d", analysis.Summary.Medium)
	}
	if analysis.Summary.Total != 3 {
		t.Errorf("Expected 3 total (ignoring unfixed), got %d", analysis.Summary.Total)
	}
}

func TestTopFindings(t *testing.T) {
	result, _ := ParseTrivyJSON(sampleTrivyOutput)
	analyzer := NewAnalyzer(GateNoCriticalHigh)
	analysis := analyzer.Analyze(result)

	if len(analysis.TopFindings) != 4 {
		t.Errorf("Expected 4 top findings, got %d", len(analysis.TopFindings))
	}

	// First should be critical
	if analysis.TopFindings[0].Severity != SeverityCritical {
		t.Errorf("Expected first finding to be CRITICAL, got %s", analysis.TopFindings[0].Severity)
	}

	// Second should be high
	if analysis.TopFindings[1].Severity != SeverityHigh {
		t.Errorf("Expected second finding to be HIGH, got %s", analysis.TopFindings[1].Severity)
	}
}

func TestNormalizeSeverity(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"CRITICAL", SeverityCritical},
		{"critical", SeverityCritical},
		{"CRIT", SeverityCritical},
		{"HIGH", SeverityHigh},
		{"high", SeverityHigh},
		{"MEDIUM", SeverityMedium},
		{"MODERATE", SeverityMedium},
		{"LOW", SeverityLow},
		{"unknown", SeverityUnknown},
		{"", SeverityUnknown},
	}

	for _, test := range tests {
		result := NormalizeSeverity(test.input)
		if result != test.expected {
			t.Errorf("NormalizeSeverity(%s) = %s, expected %s", test.input, result, test.expected)
		}
	}
}

func TestParseGateThreshold(t *testing.T) {
	tests := []struct {
		input    string
		expected GateThreshold
	}{
		{"no_critical", GateNoCritical},
		{"critical", GateNoCritical},
		{"no_critical_high", GateNoCriticalHigh},
		{"high", GateNoCriticalHigh},
		{"medium", GateNoCriticalHighMedium},
		{"none", GateNoVulnerabilities},
		{"all", GateNoVulnerabilities},
		{"invalid", GateNoCriticalHigh}, // default
	}

	for _, test := range tests {
		result := ParseGateThreshold(test.input)
		if result != test.expected {
			t.Errorf("ParseGateThreshold(%s) = %s, expected %s", test.input, result, test.expected)
		}
	}
}

func TestHasFixedVersion(t *testing.T) {
	result, _ := ParseTrivyJSON(sampleTrivyOutput)
	vulns := result.GetAllVulnerabilities()

	// CVE-2023-12345 has a fix
	if !vulns[0].HasFixedVersion() {
		t.Error("Expected CVE-2023-12345 to have a fixed version")
	}

	// CVE-2023-11111 (medium/zlib) has no fix
	if vulns[2].HasFixedVersion() {
		t.Error("Expected CVE-2023-11111 to not have a fixed version")
	}
}
