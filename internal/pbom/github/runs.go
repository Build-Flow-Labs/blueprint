package github

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
)

// GetWorkflowRun fetches a single workflow run by ID.
func (c *Client) GetWorkflowRun(ctx context.Context, owner, repo string, runID int64) (*WorkflowRun, error) {
	path := fmt.Sprintf("/repos/%s/%s/actions/runs/%d", owner, repo, runID)
	data, err := c.get(ctx, path)
	if err != nil {
		return nil, err
	}
	var run WorkflowRun
	if err := json.Unmarshal(data, &run); err != nil {
		return nil, fmt.Errorf("parsing workflow run: %w", err)
	}
	return &run, nil
}

// ListRunsByCommit lists workflow runs for a specific commit SHA.
func (c *Client) ListRunsByCommit(ctx context.Context, owner, repo, sha string) ([]WorkflowRun, error) {
	path := fmt.Sprintf("/repos/%s/%s/actions/runs?head_sha=%s", owner, repo, url.QueryEscape(sha))
	data, err := c.get(ctx, path)
	if err != nil {
		return nil, err
	}
	var resp WorkflowRunsResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parsing workflow runs: %w", err)
	}
	return resp.WorkflowRuns, nil
}

// GetJobs fetches all jobs for a workflow run.
func (c *Client) GetJobs(ctx context.Context, owner, repo string, runID int64) ([]Job, error) {
	path := fmt.Sprintf("/repos/%s/%s/actions/runs/%d/jobs", owner, repo, runID)
	data, err := c.get(ctx, path)
	if err != nil {
		return nil, err
	}
	var resp JobsResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parsing jobs: %w", err)
	}
	return resp.Jobs, nil
}

// GetArtifacts fetches all artifacts for a workflow run.
func (c *Client) GetArtifacts(ctx context.Context, owner, repo string, runID int64) ([]Artifact, error) {
	path := fmt.Sprintf("/repos/%s/%s/actions/runs/%d/artifacts", owner, repo, runID)
	data, err := c.get(ctx, path)
	if err != nil {
		return nil, err
	}
	var resp ArtifactsResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parsing artifacts: %w", err)
	}
	return resp.Artifacts, nil
}

// DownloadArtifact downloads a workflow artifact ZIP by its archive URL.
func (c *Client) DownloadArtifact(ctx context.Context, downloadURL string) ([]byte, error) {
	return c.download(ctx, downloadURL)
}

// GetRepoLanguages returns the language breakdown for a repository.
func (c *Client) GetRepoLanguages(ctx context.Context, owner, repo string) (LanguagesResponse, error) {
	path := fmt.Sprintf("/repos/%s/%s/languages", owner, repo)
	data, err := c.get(ctx, path)
	if err != nil {
		return nil, err
	}
	var langs LanguagesResponse
	if err := json.Unmarshal(data, &langs); err != nil {
		return nil, fmt.Errorf("parsing languages: %w", err)
	}
	return langs, nil
}

// GetAttestations fetches SLSA provenance attestations for an artifact digest.
func (c *Client) GetAttestations(ctx context.Context, owner, repo, digest string) (*AttestationsResponse, error) {
	path := fmt.Sprintf("/repos/%s/%s/attestations/%s", owner, repo, url.PathEscape(digest))
	data, err := c.get(ctx, path)
	if err != nil {
		return nil, err
	}
	var resp AttestationsResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parsing attestations: %w", err)
	}
	return &resp, nil
}

// GetWorkflowContent fetches a workflow YAML file's content from the repo.
// Returns the decoded file bytes (base64-decoded from the Contents API).
func (c *Client) GetWorkflowContent(ctx context.Context, owner, repo, path, ref string) ([]byte, error) {
	apiPath := fmt.Sprintf("/repos/%s/%s/contents/%s?ref=%s", owner, repo, url.PathEscape(path), url.QueryEscape(ref))
	data, err := c.get(ctx, apiPath)
	if err != nil {
		return nil, err
	}
	var fc FileContent
	if err := json.Unmarshal(data, &fc); err != nil {
		return nil, fmt.Errorf("parsing file content: %w", err)
	}
	decoded, err := base64.StdEncoding.DecodeString(fc.Content)
	if err != nil {
		return nil, fmt.Errorf("decoding base64 content: %w", err)
	}
	return decoded, nil
}
