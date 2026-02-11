package webhook

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	gh "github.com/build-flow-labs/blueprint/internal/pbom/github"
	"github.com/build-flow-labs/blueprint/pbom/schema"
)

// inTotoStatement is the minimal in-toto statement we need to parse.
type inTotoStatement struct {
	PredicateType string          `json:"predicateType"`
	Predicate     json.RawMessage `json:"predicate"`
}

// slsaPredicate has the fields we need from the SLSA provenance predicate.
type slsaPredicate struct {
	BuildDefinition struct {
		BuildType string `json:"buildType"`
	} `json:"buildDefinition"`
	RunDetails struct {
		Builder struct {
			ID string `json:"id"`
		} `json:"builder"`
	} `json:"runDetails"`
}

// ExtractProvenance queries the GitHub attestations API for an artifact digest
// and returns provenance metadata if an attestation is found.
func ExtractProvenance(ctx context.Context, client *gh.Client, owner, repo, digest string, logger *slog.Logger) *schema.Provenance {
	if digest == "" {
		return nil
	}

	resp, err := client.GetAttestations(ctx, owner, repo, digest)
	if err != nil {
		logger.Debug("no attestations found", "digest", truncDigest(digest), "error", err)
		return nil
	}

	if len(resp.Attestations) == 0 {
		return nil
	}

	att := resp.Attestations[0]

	prov := &schema.Provenance{
		AttestationURI: fmt.Sprintf("https://github.com/%s/%s/attestations", owner, repo),
	}

	// Parse the DSSE envelope to extract builder ID
	if att.Bundle.DSSEEnvelope != nil && att.Bundle.DSSEEnvelope.Payload != "" {
		builderID := extractBuilderID(att.Bundle.DSSEEnvelope.Payload)
		if builderID != "" {
			prov.BuilderID = builderID
		}
	}

	prov.SLSALevel = InferSLSALevel(prov.BuilderID)

	return prov
}

// extractBuilderID decodes the DSSE payload and extracts the builder ID
// from the in-toto statement's SLSA predicate.
func extractBuilderID(b64Payload string) string {
	payload, err := base64.StdEncoding.DecodeString(b64Payload)
	if err != nil {
		// Try URL-safe base64
		payload, err = base64.URLEncoding.DecodeString(b64Payload)
		if err != nil {
			return ""
		}
	}

	var stmt inTotoStatement
	if err := json.Unmarshal(payload, &stmt); err != nil {
		return ""
	}

	var pred slsaPredicate
	if err := json.Unmarshal(stmt.Predicate, &pred); err != nil {
		return ""
	}

	return pred.RunDetails.Builder.ID
}

// InferSLSALevel determines the SLSA level from the builder ID.
func InferSLSALevel(builderID string) int {
	switch {
	case strings.Contains(builderID, "attest-build-provenance"):
		return 3
	case strings.Contains(builderID, "github.com"):
		return 1
	case builderID != "":
		return 1
	default:
		return 0
	}
}

func truncDigest(d string) string {
	if len(d) > 19 {
		return d[:19] + "..."
	}
	return d
}
