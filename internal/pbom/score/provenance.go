package score

import (
	"github.com/build-flow-labs/blueprint/pbom/schema"
)

// scoreProvenance grades how verifiable the build artifacts are.
//
// Scoring:
//   - No artifacts at all: 30 (no verifiable output)
//   - Artifacts without digests: 40
//   - Artifacts with digests but no provenance: 60
//   - Artifacts with provenance (SLSA Level 1): 75
//   - Artifacts with provenance (SLSA Level 2): 85
//   - Artifacts with provenance (SLSA Level 3+): 95-100
//   - Build status "failure": -10 (unreliable provenance)
func scoreProvenance(pbom *schema.PBOM) schema.AxisScore {
	if len(pbom.Artifacts) == 0 {
		findings := []string{"no artifacts produced"}
		// Still give some credit if build succeeded — artifacts might exist but not tracked
		if pbom.Build.Status == "success" {
			return schema.AxisScore{
				Grade:    "F",
				Score:    30,
				Findings: findings,
			}
		}
		return schema.AxisScore{
			Grade:    "F",
			Score:    20,
			Findings: append(findings, "build did not succeed"),
		}
	}

	points := 0
	var findings []string

	// Check artifact quality
	hasDigest := false
	hasProvenance := false
	maxSLSA := 0

	for _, a := range pbom.Artifacts {
		if a.Digest != "" {
			hasDigest = true
		} else {
			findings = append(findings, a.Name+": missing digest")
		}

		if a.Provenance != nil {
			hasProvenance = true
			if a.Provenance.SLSALevel > maxSLSA {
				maxSLSA = a.Provenance.SLSALevel
			}
		}
	}

	switch {
	case hasProvenance && maxSLSA >= 3:
		points = 95 + maxSLSA // 95 for L3, 96+ for L4
		if points > 100 {
			points = 100
		}
	case hasProvenance && maxSLSA == 2:
		points = 85
	case hasProvenance && maxSLSA >= 1:
		points = 75
	case hasProvenance:
		points = 70
		findings = append(findings, "provenance present but no SLSA level set")
	case hasDigest:
		points = 60
		findings = append(findings, "artifacts have digests but no provenance attestation")
	default:
		points = 40
		findings = append(findings, "artifacts present but missing digests")
	}

	// URI presence is a bonus signal (artifact is addressable)
	allHaveURI := true
	for _, a := range pbom.Artifacts {
		if a.URI == "" {
			allHaveURI = false
			break
		}
	}
	if allHaveURI && points < 100 {
		points += 5
		if points > 100 {
			points = 100
		}
	}

	// Build failure penalty
	if pbom.Build.Status == "failure" {
		points -= 10
		findings = append(findings, "build failed — provenance is unreliable")
	}

	if points < 0 {
		points = 0
	}

	return schema.AxisScore{
		Grade:    numericToGrade(points),
		Score:    points,
		Findings: findings,
	}
}
