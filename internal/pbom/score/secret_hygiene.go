package score

import (
	"fmt"
	"strings"

	"github.com/build-flow-labs/blueprint/pbom/schema"
)

// Secret risk categories. Higher risk secrets reduce the score more.
var highRiskSecrets = map[string]bool{
	"DEPLOY_TOKEN":       true,
	"REGISTRY_PASSWORD":  true,
	"AWS_SECRET_ACCESS_KEY": true,
	"GCP_SA_KEY":         true,
	"KUBECONFIG":         true,
	"SSH_PRIVATE_KEY":    true,
	"NPM_TOKEN":         true,
	"PYPI_TOKEN":        true,
}

var signingSecrets = map[string]bool{
	"COSIGN_KEY":         true,
	"COSIGN_PASSWORD":    true,
	"SIGNING_KEY":        true,
	"GPG_PRIVATE_KEY":    true,
}

// scoreSecretHygiene grades secret usage patterns.
//
// Scoring:
//   - No secrets accessed: 100 (clean build)
//   - Only signing secrets (COSIGN_KEY etc): 95 (good practice)
//   - Notification secrets (SLACK_WEBHOOK_URL etc): -5 each (low risk)
//   - High-risk secrets (DEPLOY_TOKEN, REGISTRY_PASSWORD): -15 each
//   - Signing + high-risk together: partial offset (+10) — signing mitigates risk
//   - Build failed AND has secrets: -10 additional (secrets exposed in failing build)
func scoreSecretHygiene(pbom *schema.PBOM) schema.AxisScore {
	secrets := pbom.Build.SecretsAccessed
	if len(secrets) == 0 {
		return schema.AxisScore{
			Grade:    "A",
			Score:    100,
			Findings: nil,
		}
	}

	points := 100
	var findings []string
	hasSigning := false
	hasHighRisk := false

	for _, s := range secrets {
		upper := strings.ToUpper(s)

		if signingSecrets[upper] {
			hasSigning = true
			points -= 5
			findings = append(findings, fmt.Sprintf("%s: signing secret (good practice)", s))
			continue
		}

		if highRiskSecrets[upper] {
			hasHighRisk = true
			points -= 15
			findings = append(findings, fmt.Sprintf("%s: high-risk credential", s))
			continue
		}

		// Low-risk / notification secrets
		points -= 5
		findings = append(findings, fmt.Sprintf("%s: low-risk secret", s))
	}

	// Signing + high-risk together: signing mitigates some risk
	if hasSigning && hasHighRisk {
		points += 10
		findings = append(findings, "signing secret present — partial risk mitigation")
	}

	// Secrets in a failing build is worse
	if pbom.Build.Status == "failure" && len(secrets) > 0 {
		points -= 10
		findings = append(findings, "secrets accessed in a failing build")
	}

	if points < 0 {
		points = 0
	}
	if points > 100 {
		points = 100
	}

	return schema.AxisScore{
		Grade:    numericToGrade(points),
		Score:    points,
		Findings: findings,
	}
}
