package score

import (
	"testing"

	"github.com/build-flow-labs/blueprint/pbom/schema"
)

func TestScoreComposite(t *testing.T) {
	tests := []struct {
		name      string
		pbom      schema.PBOM
		wantGrade string
		wantMin   int
		wantMax   int
	}{
		{
			name: "perfect build with provenance",
			pbom: schema.PBOM{
				Build: schema.Build{
					ToolVersions: map[string]string{
						"go": "1.23.0",
					},
					Status: "success",
				},
				Artifacts: []schema.Artifact{
					{
						Name:   "app",
						Type:   "container-image",
						Digest: "sha256:abc123",
						URI:    "ghcr.io/org/app@sha256:abc123",
						Provenance: &schema.Provenance{
							SLSALevel: 3,
						},
						Vulnerabilities: &schema.Vulnerabilities{
							Scanner:  "trivy",
							Critical: 0,
							High:     0,
							Medium:   0,
							Low:      2,
						},
					},
				},
			},
			wantGrade: "A",
			wantMin:   90,
			wantMax:   100,
		},
		{
			name: "minimal build no artifacts",
			pbom: schema.PBOM{
				Build: schema.Build{
					Status: "success",
				},
			},
			wantGrade: "F",
			wantMin:   50,
			wantMax:   60,
		},
		{
			name: "failed build with critical vulns",
			pbom: schema.PBOM{
				Build: schema.Build{
					ToolVersions: map[string]string{
						"go": "1.19.0",
					},
					SecretsAccessed: []string{"DEPLOY_TOKEN", "REGISTRY_PASSWORD"},
					Status:          "failure",
				},
				Artifacts: []schema.Artifact{
					{
						Name:   "app",
						Type:   "container-image",
						Digest: "sha256:abc123",
						Vulnerabilities: &schema.Vulnerabilities{
							Critical: 3,
							High:     5,
						},
					},
				},
			},
			wantGrade: "F",
			wantMin:   40,
			wantMax:   50,
		},
		{
			name: "good build with some secrets",
			pbom: schema.PBOM{
				Build: schema.Build{
					ToolVersions: map[string]string{
						"go":     "1.23.0",
						"docker": "28.0.0",
					},
					SecretsAccessed: []string{"COSIGN_KEY", "SLACK_WEBHOOK_URL"},
					Status:          "success",
				},
				Artifacts: []schema.Artifact{
					{
						Name:   "app",
						Type:   "container-image",
						Digest: "sha256:abc123",
						URI:    "ghcr.io/org/app@sha256:abc123",
					},
				},
			},
			wantGrade: "C",
			wantMin:   60,
			wantMax:   80,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hs := Score(&tt.pbom)
			if hs.Grade != tt.wantGrade {
				t.Errorf("Grade = %q, want %q (score=%d)", hs.Grade, tt.wantGrade, hs.Score)
			}
			if hs.Score < tt.wantMin || hs.Score > tt.wantMax {
				t.Errorf("Score = %d, want [%d, %d]", hs.Score, tt.wantMin, tt.wantMax)
			}
		})
	}
}

func TestScoreToolCurrency(t *testing.T) {
	tests := []struct {
		name      string
		versions  map[string]string
		wantGrade string
	}{
		{
			name:      "no versions",
			versions:  nil,
			wantGrade: "D",
		},
		{
			name:      "current go",
			versions:  map[string]string{"go": "1.23.0"},
			wantGrade: "A",
		},
		{
			name:      "slightly behind",
			versions:  map[string]string{"go": "1.22.0"},
			wantGrade: "A",
		},
		{
			name: "multiple tools behind",
			versions: map[string]string{
				"go":   "1.19.0",
				"node": "16.0.0",
			},
			wantGrade: "C",
		},
		{
			name:      "unrecognized tool only",
			versions:  map[string]string{"custom-tool": "1.0.0"},
			wantGrade: "C",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pbom := &schema.PBOM{
				Build: schema.Build{ToolVersions: tt.versions},
			}
			result := scoreToolCurrency(pbom)
			if result.Grade != tt.wantGrade {
				t.Errorf("Grade = %q, want %q (score=%d, findings=%v)", result.Grade, tt.wantGrade, result.Score, result.Findings)
			}
		})
	}
}

func TestScoreSecretHygiene(t *testing.T) {
	tests := []struct {
		name      string
		secrets   []string
		status    string
		wantGrade string
	}{
		{
			name:      "no secrets",
			secrets:   nil,
			status:    "success",
			wantGrade: "A",
		},
		{
			name:      "signing only",
			secrets:   []string{"COSIGN_KEY"},
			status:    "success",
			wantGrade: "A",
		},
		{
			name:      "low risk only",
			secrets:   []string{"SLACK_WEBHOOK_URL"},
			status:    "success",
			wantGrade: "A",
		},
		{
			name:      "high risk",
			secrets:   []string{"DEPLOY_TOKEN", "REGISTRY_PASSWORD"},
			status:    "success",
			wantGrade: "C",
		},
		{
			name:      "high risk in failing build",
			secrets:   []string{"DEPLOY_TOKEN"},
			status:    "failure",
			wantGrade: "C",
		},
		{
			name:      "signing mitigates high risk",
			secrets:   []string{"COSIGN_KEY", "DEPLOY_TOKEN"},
			status:    "success",
			wantGrade: "A",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pbom := &schema.PBOM{
				Build: schema.Build{
					SecretsAccessed: tt.secrets,
					Status:          tt.status,
				},
			}
			result := scoreSecretHygiene(pbom)
			if result.Grade != tt.wantGrade {
				t.Errorf("Grade = %q, want %q (score=%d, findings=%v)", result.Grade, tt.wantGrade, result.Score, result.Findings)
			}
		})
	}
}

func TestScoreProvenance(t *testing.T) {
	tests := []struct {
		name      string
		artifacts []schema.Artifact
		status    string
		wantGrade string
	}{
		{
			name:      "no artifacts success",
			artifacts: nil,
			status:    "success",
			wantGrade: "F",
		},
		{
			name:      "no artifacts failure",
			artifacts: nil,
			status:    "failure",
			wantGrade: "F",
		},
		{
			name: "digest and URI",
			artifacts: []schema.Artifact{
				{Name: "app", Digest: "sha256:abc", URI: "ghcr.io/org/app"},
			},
			status:    "success",
			wantGrade: "D",
		},
		{
			name: "slsa level 3",
			artifacts: []schema.Artifact{
				{
					Name: "app", Digest: "sha256:abc", URI: "ghcr.io/org/app",
					Provenance: &schema.Provenance{SLSALevel: 3},
				},
			},
			status:    "success",
			wantGrade: "A",
		},
		{
			name: "slsa level 1",
			artifacts: []schema.Artifact{
				{
					Name: "app", Digest: "sha256:abc",
					Provenance: &schema.Provenance{SLSALevel: 1},
				},
			},
			status:    "success",
			wantGrade: "C",
		},
		{
			name: "no digest",
			artifacts: []schema.Artifact{
				{Name: "app", Type: "binary"},
			},
			status:    "success",
			wantGrade: "F",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pbom := &schema.PBOM{
				Artifacts: tt.artifacts,
				Build:     schema.Build{Status: tt.status},
			}
			result := scoreProvenance(pbom)
			if result.Grade != tt.wantGrade {
				t.Errorf("Grade = %q, want %q (score=%d, findings=%v)", result.Grade, tt.wantGrade, result.Score, result.Findings)
			}
		})
	}
}

func TestScoreVulnerability(t *testing.T) {
	tests := []struct {
		name      string
		artifacts []schema.Artifact
		status    string
		wantGrade string
	}{
		{
			name:      "no artifacts",
			artifacts: nil,
			status:    "success",
			wantGrade: "D",
		},
		{
			name: "no scan data",
			artifacts: []schema.Artifact{
				{Name: "app", Digest: "sha256:abc"},
			},
			status:    "success",
			wantGrade: "D",
		},
		{
			name: "clean scan",
			artifacts: []schema.Artifact{
				{
					Name: "app", Digest: "sha256:abc",
					Vulnerabilities: &schema.Vulnerabilities{
						Scanner: "trivy", Critical: 0, High: 0, Medium: 0, Low: 5,
					},
				},
			},
			status:    "success",
			wantGrade: "A",
		},
		{
			name: "critical vulns",
			artifacts: []schema.Artifact{
				{
					Name: "app", Digest: "sha256:abc",
					Vulnerabilities: &schema.Vulnerabilities{
						Scanner: "trivy", Critical: 2, High: 3,
					},
				},
			},
			status:    "success",
			wantGrade: "F",
		},
		{
			name: "medium vulns only",
			artifacts: []schema.Artifact{
				{
					Name: "app", Digest: "sha256:abc",
					Vulnerabilities: &schema.Vulnerabilities{
						Scanner: "trivy", Medium: 5,
					},
				},
			},
			status:    "success",
			wantGrade: "B",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pbom := &schema.PBOM{
				Artifacts: tt.artifacts,
				Build:     schema.Build{Status: tt.status},
			}
			result := scoreVulnerability(pbom)
			if result.Grade != tt.wantGrade {
				t.Errorf("Grade = %q, want %q (score=%d, findings=%v)", result.Grade, tt.wantGrade, result.Score, result.Findings)
			}
		})
	}
}

func TestNumericToGrade(t *testing.T) {
	tests := []struct {
		score int
		want  string
	}{
		{100, "A"},
		{95, "A"},
		{90, "A"},
		{89, "B"},
		{80, "B"},
		{79, "C"},
		{70, "C"},
		{69, "D"},
		{60, "D"},
		{59, "F"},
		{0, "F"},
	}

	for _, tt := range tests {
		got := numericToGrade(tt.score)
		if got != tt.want {
			t.Errorf("numericToGrade(%d) = %q, want %q", tt.score, got, tt.want)
		}
	}
}
