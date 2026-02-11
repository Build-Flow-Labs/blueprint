package webhook

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	gh "github.com/build-flow-labs/blueprint/internal/pbom/github"
	"github.com/build-flow-labs/blueprint/internal/pbom/score"
	"github.com/build-flow-labs/blueprint/pbom/schema"
)

// Enricher performs PBOM enrichment from GitHub API data.
type Enricher struct {
	ghClient   *gh.Client
	storageDir string
	logger     *slog.Logger
	onStore    func() // called after successful PBOM storage (e.g., dashboard refresh)
}

// NewEnricher creates an Enricher.
func NewEnricher(ghClient *gh.Client, storageDir string, logger *slog.Logger) *Enricher {
	return &Enricher{
		ghClient:   ghClient,
		storageDir: storageDir,
		logger:     logger,
	}
}

// Enrich is the main enrichment pipeline for a completed workflow run.
func (e *Enricher) Enrich(parentCtx context.Context, event WebhookEvent) {
	// Use a fresh context with timeout (the HTTP request context may already be done)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	owner := event.Repository.Owner.Login
	repo := event.Repository.Name
	runID := event.WorkflowRun.ID
	headSHA := event.WorkflowRun.HeadSHA

	log := e.logger.With(
		"repo", event.Repository.FullName,
		"run_id", runID,
		"sha", headSHA[:min(8, len(headSHA))],
	)

	// Step 1: Find the companion PBOM Collector run (with retry for race condition)
	pbom, err := e.findSkeletonWithRetry(ctx, owner, repo, headSHA, log)
	if err != nil {
		log.Warn("could not find skeleton PBOM, creating from scratch", "error", err)
		pbom = e.buildFallbackPBOM(event)
	}

	// Step 2: Get jobs from the developer's CI run
	jobs, err := e.ghClient.GetJobs(ctx, owner, repo, runID)
	if err != nil {
		log.Error("failed to get jobs", "error", err)
	} else {
		// Enrich runner
		if runner := ExtractRunner(jobs); runner != nil {
			pbom.Build.Runner = runner
			log.Info("enriched runner", "os", runner.OS, "arch", runner.Arch, "self_hosted", runner.SelfHosted)
		}

		// Enrich timestamps
		started, completed := ExtractTimestamps(jobs)
		if started != nil {
			pbom.Build.StartedAt = started
		}
		if completed != nil {
			pbom.Build.CompletedAt = completed
		}
	}

	// Step 3: Update build status and metadata from the developer CI (not the collector)
	pbom.Build.Status = event.WorkflowRun.Conclusion
	pbom.Build.WorkflowName = event.WorkflowRun.Name
	pbom.Build.WorkflowFile = event.WorkflowRun.Path

	// Step 4: Extract secrets from workflow YAML
	workflowPath := event.WorkflowRun.Path
	if workflowPath != "" {
		yamlContent, err := e.ghClient.GetWorkflowContent(ctx, owner, repo, workflowPath, headSHA)
		if err != nil {
			log.Warn("failed to fetch workflow YAML", "path", workflowPath, "error", err)
		} else {
			secrets := ExtractSecretsFromWorkflow(yamlContent)
			if len(secrets) > 0 {
				pbom.Build.SecretsAccessed = secrets
				log.Info("enriched secrets", "count", len(secrets), "secrets", strings.Join(secrets, ","))
			}
		}
	}

	// Step 5: Extract Docker artifacts from the developer's CI run
	dockerArtifacts := ExtractDockerArtifacts(ctx, e.ghClient, owner, repo, runID, log)
	if len(dockerArtifacts) > 0 {
		pbom.Artifacts = append(pbom.Artifacts, dockerArtifacts...)
		log.Info("enriched artifacts", "count", len(dockerArtifacts))
	}

	// Step 5.1: Extract vulnerability data from Trivy scan
	if len(pbom.Artifacts) > 0 {
		vulns := ExtractVulnerabilities(ctx, e.ghClient, owner, repo, runID, log)
		if vulns != nil {
			pbom.Artifacts[0].Vulnerabilities = vulns
			log.Info("enriched vulnerabilities",
				"critical", vulns.Critical,
				"high", vulns.High,
				"medium", vulns.Medium,
				"low", vulns.Low,
			)
		}
	}

	// Step 5.2: Extract provenance attestations for each artifact
	for i := range pbom.Artifacts {
		if pbom.Artifacts[i].Digest == "" {
			continue
		}
		prov := ExtractProvenance(ctx, e.ghClient, owner, repo, pbom.Artifacts[i].Digest, log)
		if prov != nil {
			pbom.Artifacts[i].Provenance = prov
			log.Info("enriched provenance",
				"artifact", pbom.Artifacts[i].Name,
				"slsa_level", prov.SLSALevel,
				"builder", prov.BuilderID,
			)
		}
	}

	// Step 5.5: Filter tool versions to repo-relevant tools
	languages, err := e.ghClient.GetRepoLanguages(ctx, owner, repo)
	if err != nil {
		log.Warn("failed to get repo languages, keeping all tool versions", "error", err)
	} else {
		before := len(pbom.Build.ToolVersions)
		pbom.Build.ToolVersions = FilterToolVersions(pbom.Build.ToolVersions, languages)
		log.Info("filtered tool versions",
			"before", before,
			"after", len(pbom.Build.ToolVersions),
		)
	}

	// Step 6: Score pipeline health
	pbom.HealthScore = score.Score(pbom)
	log.Info("scored pipeline health",
		"grade", pbom.HealthScore.Grade,
		"score", pbom.HealthScore.Score,
	)

	// Step 7: Store the enriched PBOM
	path, err := Store(e.storageDir, pbom, owner, repo, runID)
	if err != nil {
		log.Error("failed to store enriched PBOM", "error", err)
		return
	}

	log.Info("enriched PBOM stored",
		"path", path,
		"artifacts", len(pbom.Artifacts),
		"secrets", len(pbom.Build.SecretsAccessed),
	)

	// Notify dashboard to refresh its index
	if e.onStore != nil {
		e.onStore()
	}
}

// findSkeletonWithRetry attempts to find and download the skeleton PBOM,
// retrying if the collector run hasn't completed yet.
func (e *Enricher) findSkeletonWithRetry(ctx context.Context, owner, repo, headSHA string, log *slog.Logger) (*schema.PBOM, error) {
	delays := []time.Duration{0, 10 * time.Second, 30 * time.Second, 60 * time.Second}

	for attempt, delay := range delays {
		if delay > 0 {
			log.Info("waiting for PBOM Collector to complete", "attempt", attempt+1, "delay", delay)
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}

		collectorRun, err := FindCollectorRun(ctx, e.ghClient, owner, repo, headSHA)
		if err != nil {
			if attempt < len(delays)-1 {
				continue
			}
			return nil, fmt.Errorf("after %d attempts: %w", len(delays), err)
		}

		pbom, err := DownloadSkeletonPBOM(ctx, e.ghClient, owner, repo, collectorRun.ID)
		if err != nil {
			return nil, fmt.Errorf("downloading skeleton: %w", err)
		}

		return pbom, nil
	}

	return nil, fmt.Errorf("exhausted retries")
}

// buildFallbackPBOM creates a minimal PBOM from the webhook event when no skeleton is available.
func (e *Enricher) buildFallbackPBOM(event WebhookEvent) *schema.PBOM {
	now := time.Now().UTC()
	return &schema.PBOM{
		PBOMVersion: schema.Version,
		ID:          fmt.Sprintf("fallback-%d", event.WorkflowRun.ID),
		Timestamp:   now,
		Source: schema.Source{
			Repository: event.Repository.FullName,
			CommitSHA:  event.WorkflowRun.HeadSHA,
			Branch:     event.WorkflowRun.HeadBranch,
			Author:     event.WorkflowRun.Actor.Login,
		},
		Build: schema.Build{
			WorkflowRunID: fmt.Sprintf("%d", event.WorkflowRun.ID),
			WorkflowName:  event.WorkflowRun.Name,
			WorkflowFile:  event.WorkflowRun.Path,
			Trigger:       event.WorkflowRun.Event,
			Actor:         event.WorkflowRun.Actor.Login,
			Status:        event.WorkflowRun.Conclusion,
			StartedAt:     &now,
		},
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
