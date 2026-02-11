package webhook

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"

	gh "github.com/build-flow-labs/blueprint/internal/pbom/github"
	"github.com/build-flow-labs/blueprint/pbom/schema"
)

// FindCollectorRun searches for a completed PBOM Collector workflow run
// triggered by the same commit SHA.
func FindCollectorRun(ctx context.Context, client *gh.Client, owner, repo, headSHA string) (*gh.WorkflowRun, error) {
	runs, err := client.ListRunsByCommit(ctx, owner, repo, headSHA)
	if err != nil {
		return nil, fmt.Errorf("listing runs for commit %s: %w", headSHA, err)
	}

	for i := range runs {
		if runs[i].Name == "PBOM Collector" && runs[i].Conclusion == "success" {
			return &runs[i], nil
		}
	}

	return nil, fmt.Errorf("no completed PBOM Collector run found for commit %s", headSHA)
}

// DownloadSkeletonPBOM downloads the PBOM artifact from a collector run,
// extracts the pbom.json from the ZIP, and unmarshals it.
func DownloadSkeletonPBOM(ctx context.Context, client *gh.Client, owner, repo string, collectorRunID int64) (*schema.PBOM, error) {
	artifacts, err := client.GetArtifacts(ctx, owner, repo, collectorRunID)
	if err != nil {
		return nil, fmt.Errorf("getting collector artifacts: %w", err)
	}

	// Find the pbom-{run_id} artifact
	var pbomArtifact *gh.Artifact
	prefix := fmt.Sprintf("pbom-%d", collectorRunID)
	for i := range artifacts {
		if artifacts[i].Name == prefix {
			pbomArtifact = &artifacts[i]
			break
		}
	}
	if pbomArtifact == nil {
		return nil, fmt.Errorf("no artifact named %q found in collector run %d", prefix, collectorRunID)
	}

	// Download and extract
	zipData, err := client.DownloadArtifact(ctx, pbomArtifact.ArchiveDownloadURL)
	if err != nil {
		return nil, fmt.Errorf("downloading PBOM artifact: %w", err)
	}

	return extractPBOMFromZip(zipData)
}

func extractPBOMFromZip(zipData []byte) (*schema.PBOM, error) {
	reader, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
	if err != nil {
		return nil, fmt.Errorf("opening artifact zip: %w", err)
	}

	for _, f := range reader.File {
		if strings.HasSuffix(f.Name, ".json") {
			rc, err := f.Open()
			if err != nil {
				return nil, fmt.Errorf("opening %s: %w", f.Name, err)
			}
			defer rc.Close()

			var pbom schema.PBOM
			if err := json.NewDecoder(rc).Decode(&pbom); err != nil {
				return nil, fmt.Errorf("parsing PBOM JSON: %w", err)
			}
			return &pbom, nil
		}
	}

	return nil, fmt.Errorf("no JSON file found in PBOM artifact zip")
}
