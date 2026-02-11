// Package score implements pipeline health scoring for PBOM documents.
//
// Each PBOM is scored on 4 axes: tool currency, secret hygiene, provenance,
// and vulnerability. Axes produce letter grades (A-F) and numeric scores (0-100).
// The composite grade is a weighted average.
package score

import (
	"github.com/build-flow-labs/blueprint/pbom/schema"
)

// Weights for each axis in the composite score.
const (
	WeightToolCurrency  = 0.20
	WeightSecretHygiene = 0.20
	WeightProvenance    = 0.30
	WeightVulnerability = 0.30
)

// Score evaluates a PBOM and returns a HealthScore.
func Score(pbom *schema.PBOM) *schema.HealthScore {
	tc := scoreToolCurrency(pbom)
	sh := scoreSecretHygiene(pbom)
	pv := scoreProvenance(pbom)
	vl := scoreVulnerability(pbom)

	composite := int(
		float64(tc.Score)*WeightToolCurrency +
			float64(sh.Score)*WeightSecretHygiene +
			float64(pv.Score)*WeightProvenance +
			float64(vl.Score)*WeightVulnerability +
			0.5, // round
	)

	return &schema.HealthScore{
		Grade:         numericToGrade(composite),
		Score:         composite,
		ToolCurrency:  tc,
		SecretHygiene: sh,
		Provenance:    pv,
		Vulnerability: vl,
	}
}

// numericToGrade converts a 0-100 score to a letter grade.
func numericToGrade(score int) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 80:
		return "B"
	case score >= 70:
		return "C"
	case score >= 60:
		return "D"
	default:
		return "F"
	}
}
