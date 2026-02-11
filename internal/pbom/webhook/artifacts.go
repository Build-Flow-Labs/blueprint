package webhook

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	gh "github.com/build-flow-labs/blueprint/internal/pbom/github"
	"github.com/build-flow-labs/blueprint/pbom/schema"
)

// DockerMetadata is the JSON structure written by CI workflows as a
// docker-metadata-{run_id} artifact.
type DockerMetadata struct {
	Image  string `json:"image"`
	Digest string `json:"digest"`
	Tags   string `json:"tags"`
}

// ExtractDockerArtifacts finds docker-metadata-* artifacts from a workflow run,
// downloads them, and returns schema.Artifact entries.
func ExtractDockerArtifacts(ctx context.Context, client *gh.Client, owner, repo string, runID int64, logger *slog.Logger) []schema.Artifact {
	artifacts, err := client.GetArtifacts(ctx, owner, repo, runID)
	if err != nil {
		logger.Warn("failed to get artifacts", "error", err)
		return nil
	}

	var result []schema.Artifact
	for _, art := range artifacts {
		if !strings.HasPrefix(art.Name, "docker-metadata-") {
			continue
		}

		meta, err := downloadAndParseDockerMetadata(ctx, client, art.ArchiveDownloadURL)
		if err != nil {
			logger.Warn("failed to parse docker metadata artifact", "name", art.Name, "error", err)
			continue
		}

		tags := parseTags(meta.Tags)

		// Construct the full URI with digest
		uri := meta.Image
		if meta.Digest != "" {
			uri = meta.Image + "@" + meta.Digest
		}

		result = append(result, schema.Artifact{
			Name:   repoBaseName(repo),
			Type:   "container-image",
			Digest: meta.Digest,
			URI:    uri,
			Tags:   tags,
		})
	}

	return result
}

func downloadAndParseDockerMetadata(ctx context.Context, client *gh.Client, downloadURL string) (*DockerMetadata, error) {
	zipData, err := client.DownloadArtifact(ctx, downloadURL)
	if err != nil {
		return nil, fmt.Errorf("downloading artifact: %w", err)
	}

	reader, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
	if err != nil {
		return nil, fmt.Errorf("opening zip: %w", err)
	}

	for _, f := range reader.File {
		if strings.HasSuffix(f.Name, ".json") {
			rc, err := f.Open()
			if err != nil {
				return nil, fmt.Errorf("opening %s: %w", f.Name, err)
			}
			defer rc.Close()

			var meta DockerMetadata
			if err := json.NewDecoder(rc).Decode(&meta); err != nil {
				return nil, fmt.Errorf("parsing %s: %w", f.Name, err)
			}
			return &meta, nil
		}
	}

	return nil, fmt.Errorf("no JSON file found in artifact zip")
}

func parseTags(tagStr string) []string {
	if tagStr == "" {
		return nil
	}
	var tags []string
	for _, line := range strings.Split(tagStr, "\n") {
		t := strings.TrimSpace(line)
		if t != "" {
			tags = append(tags, t)
		}
	}
	return tags
}

func repoBaseName(repo string) string {
	parts := strings.Split(repo, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return repo
}
