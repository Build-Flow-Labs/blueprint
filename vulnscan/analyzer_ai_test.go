package vulnscan

import (
	"reflect"
	"testing"
)

func TestNewAnalyzer(t *testing.T) {
	threshold := GateNoCriticalHigh
	analyzer := NewAnalyzer(threshold)

	if analyzer == nil {
		t.Fatal("NewAnalyzer returned nil")
	}

	if analyzer.Threshold != threshold {
		t.Errorf("Expected threshold %s, got %s", threshold, analyzer.Threshold)
	}

	if analyzer.IgnoreUnfixed != false {
		t.Errorf("Expected IgnoreUnfixed to be false, got %v", analyzer.IgnoreUnfixed)
	}
}

func TestAnalyzer_AnalyzeFromJSON(t *testing.T) {
	analyzer := NewAnalyzer(GateNoCriticalHigh)

	t.Run("valid JSON", func(t *testing.T) {
		analysis, err := analyzer.AnalyzeFromJSON(sampleTrivyOutput)
		if err != nil {
			t.Fatalf("AnalyzeFromJSON failed: %v", err)
		}

		if analysis == nil {
			t.Fatal("AnalyzeFromJSON returned nil analysis")
		}

		if analysis.Summary.Total != 4 {
			t.Errorf("Expected 4 total vulnerabilities, got %d", analysis.Summary.Total)
		}
	})

	t.Run("invalid JSON", func(t *testing.T) {
		_, err := analyzer.AnalyzeFromJSON([]byte("invalid json"))
		if err == nil {
			t.Error("AnalyzeFromJSON should have returned an error for invalid JSON")
		}
	})
}

func TestAnalyzer_calculateSummary(t *testing.T) {
	analyzer := NewAnalyzer(GateNoCriticalHigh)

	t.Run("empty vulnerabilities", func(t *testing.T) {
		summary := analyzer.calculateSummary([]Vulnerability{})
		expected := VulnSummary{Total: 0}
		if !reflect.DeepEqual(summary, expected) {
			t.Errorf("Expected summary %+v, got %+v", expected, summary)
		}
	})

	t.Run("with vulnerabilities", func(t *testing.T) {
		result, _ := ParseTrivyJSON(sampleTrivyOutput)
		vulns := result.GetAllVulnerabilities()
		summary := analyzer.calculateSummary(vulns)
		expected := VulnSummary{
			Critical: 1,
			High:     1,
			Medium:   1,
			Low:      1,
			Unknown:  0,
			Total:    4,
		}
		if !reflect.DeepEqual(summary, expected) {
			t.Errorf("Expected summary %+v, got %+v", expected, summary)
		}
	})
}

func TestAnalyzer_checkGate(t *testing.T) {
	tests := []struct {
		name          string
		threshold     GateThreshold
		summary       VulnSummary
		expectedPass  bool
		expectedMessage string
	}{
		{
			name:          "GateNoCritical pass",
			threshold:     GateNoCritical,
			summary:       VulnSummary{High: 1},
			expectedPass:  true,
			expectedMessage: "Gate passed: no critical vulnerabilities",
		},
		{
			name:          "GateNoCritical fail",
			threshold:     GateNoCritical,
			summary:       VulnSummary{Critical: 1},
			expectedPass:  false,
			expectedMessage: "Gate failed: critical(1) vulnerability(ies) found",
		},
		{
			name:          "GateNoCriticalHigh pass",
			threshold:     GateNoCriticalHigh,
			summary:       VulnSummary{Medium: 1},
			expectedPass:  true,
			expectedMessage: "Gate passed: no critical or high vulnerabilities",
		},
		{
			name:          "GateNoCriticalHigh fail critical",
			threshold:     GateNoCriticalHigh,
			summary:       VulnSummary{Critical: 1},
			expectedPass:  false,
			expectedMessage: "Gate failed: critical(1) vulnerability(ies) found",
		},
		{
			name:          "GateNoCriticalHigh fail high",
			threshold:     GateNoCriticalHigh,
			summary:       VulnSummary{High: 1},
			expectedPass:  false,
			expectedMessage: "Gate failed: high(1) vulnerability(ies) found",
		},
		{
			name:          "GateNoCriticalHigh fail both",
			threshold:     GateNoCriticalHigh,
			summary:       VulnSummary{Critical: 1, High: 1},
			expectedPass:  false,
			expectedMessage: "Gate failed: critical(1) and high(1) vulnerability(ies) found",
		},
		{
			name:          "GateNoCriticalHighMedium pass",
			threshold:     GateNoCriticalHighMedium,
			summary:       VulnSummary{Low: 1},
			expectedPass:  true,
			expectedMessage: "Gate passed: no critical, high, or medium vulnerabilities",
		},
		{
			name:          "GateNoCriticalHighMedium fail critical",
			threshold:     GateNoCriticalHighMedium,
			summary:       VulnSummary{Critical: 1},
			expectedPass:  false,
			expectedMessage: "Gate failed: critical(1) vulnerability(ies) found",
		},
		{
			name:          "GateNoCriticalHighMedium fail high",
			threshold:     GateNoCriticalHighMedium,
			summary:       VulnSummary{High: 1},
			expectedPass:  false,
			expectedMessage: "Gate failed: high(1) vulnerability(ies) found",
		},
		{
			name:          "GateNoCriticalHighMedium fail medium",
			threshold:     GateNoCriticalHighMedium,
			summary:       VulnSummary{Medium: 1},
			expectedPass:  false,
			expectedMessage: "Gate failed: medium(1) vulnerability(ies) found",
		},
		{
			name:          "GateNoCriticalHighMedium fail all",
			threshold:     GateNoCriticalHighMedium,
			summary:       VulnSummary{Critical: 1, High: 1, Medium: 1},
			expectedPass:  false,
			expectedMessage: "Gate failed: critical(1), high(1), medium(1) vulnerability(ies) found",
		},
		{
			name:          "GateNoVulnerabilities pass",
			threshold:     GateNoVulnerabilities,
			summary:       VulnSummary{},
			expectedPass:  true,
			expectedMessage: "Gate passed: no vulnerabilities",
		},
		{
			name:          "GateNoVulnerabilities fail",
			threshold:     GateNoVulnerabilities,
			summary:       VulnSummary{Total: 1},
			expectedPass:  false,
			expectedMessage: "Gate failed: 1 vulnerability(ies) found",
		},
		{
			name:          "Default gate pass",
			threshold:     "invalid",
			summary:       VulnSummary{Medium: 1},
			expectedPass:  true,
			expectedMessage: "Gate passed",
		},
		{
			name:          "Default gate fail",
			threshold:     "invalid",
			summary:       VulnSummary{Critical: 1},
			expectedPass:  false,
			expectedMessage: "Gate failed: critical or high vulnerabilities found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			analyzer := &Analyzer{Threshold: tt.threshold}
			pass, message := analyzer.checkGate(tt.summary)
			if pass != tt.expectedPass {
				t.Errorf("Expected pass %v, got %v", tt.expectedPass, pass)
			}
			if message != tt.expectedMessage {
				t.Errorf("Expected message '%s', got '%s'", tt.expectedMessage, message)
			}
		})
	}
}

func TestAnalyzer_getTopFindings(t *testing.T) {
	analyzer := NewAnalyzer(GateNoCriticalHigh)

	// Create some mock vulnerabilities with different severities
	vulns := []Vulnerability{
		{VulnerabilityID: "V1", Severity: "LOW", PkgName: "pkg1", InstalledVersion: "1.0"},
		{VulnerabilityID: "V2", Severity: "MEDIUM", PkgName: "pkg2", InstalledVersion: "2.0"},
		{VulnerabilityID: "V3", Severity: "HIGH", PkgName: "pkg3", InstalledVersion: "3.0"},
		{VulnerabilityID: "V4", Severity: "CRITICAL", PkgName: "pkg4", InstalledVersion: "4.0"},
		{VulnerabilityID: "V5", Severity: "UNKNOWN", PkgName: "pkg5", InstalledVersion: "5.0"},
	}

	t.Run("limit less than number of vulns", func(t *testing.T) {
		limit := 3
		findings := analyzer.getTopFindings(vulns, limit)

		if len(findings) != limit {
			t.Errorf("Expected %d findings, got %d", limit, len(findings))
		}

		// Check order (critical, high, medium)
		if findings[0].ID != "V4" || findings[1].ID != "V3" || findings[2].ID != "V2" {
			t.Errorf("Findings not sorted correctly: %+v", findings)
		}
	})

	t.Run("limit greater than number of vulns", func(t *testing.T) {
		limit := 10
		findings := analyzer.getTopFindings(vulns, limit)

		if len(findings) != len(vulns) {
			t.Errorf("Expected %d findings, got %d", len(vulns), len(findings))
		}

		// Check order (critical, high, medium, low, unknown)
		if findings[0].ID != "V4" || findings[1].ID != "V3" || findings[2].ID != "V2" || findings[3].ID != "V1" || findings[4].ID != "V5" {
			t.Errorf("Findings not sorted correctly: %+v", findings)
		}
	})

	t.Run("empty vulns", func(t *testing.T) {
		limit := 5
		findings := analyzer.getTopFindings([]Vulnerability{}, limit)

		if len(findings) != 0 {
			t.Errorf("Expected 0 findings, got %d", len(findings))
		}
	})
}

func TestFormatCount(t *testing.T) {
	tests := []struct {
		count    int
		severity string
		expected string
	}{
		{1, "critical", "critical(1)"},
		{5, "high", "high(5)"},
		{0, "medium", "medium(0)"},
		{9, "", "9"},
		{15, "low", "low(5)"},
	}

	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			result := formatCount(tt.count, tt.severity)
			if result != tt.expected {
				t.Errorf("formatCount(%d, %s) = %s, expected %s", tt.count, tt.severity, result, tt.expected)
			}
		})
	}
}