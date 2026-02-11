package dashboard

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/build-flow-labs/blueprint/pbom/schema"
)

func writePBOM(t *testing.T, dir, filename string, pbom *schema.PBOM) {
	t.Helper()
	data, err := json.MarshalIndent(pbom, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, filename), data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func samplePBOM(repo, branch, status, grade string, score int, ts time.Time) *schema.PBOM {
	p := &schema.PBOM{
		PBOMVersion: "1.0.0",
		ID:          "test-id",
		Timestamp:   ts,
		Source: schema.Source{
			Repository: repo,
			CommitSHA:  "abc1234567890def1234567890abc1234567890de",
			Branch:     branch,
			Author:     "testuser",
		},
		Build: schema.Build{
			WorkflowRunID: "12345",
			WorkflowName:  "CI",
			Actor:         "testuser",
			Status:        status,
		},
		Artifacts: []schema.Artifact{
			{Name: "app", Type: "container-image", Digest: "sha256:abcdef"},
		},
	}
	if grade != "" {
		p.HealthScore = &schema.HealthScore{
			Grade: grade,
			Score: score,
		}
	}
	return p
}

func TestLoadAndList(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().UTC()

	writePBOM(t, dir, "acme_api_100.pbom.json",
		samplePBOM("acme/api", "main", "success", "A", 95, now))
	writePBOM(t, dir, "acme_web_200.pbom.json",
		samplePBOM("acme/web", "main", "failure", "C", 72, now.Add(-time.Hour)))
	writePBOM(t, dir, "acme_api_300.pbom.json",
		samplePBOM("acme/api", "feature", "success", "B", 85, now.Add(-30*time.Minute)))

	idx := NewIndex(dir)
	if err := idx.Load(); err != nil {
		t.Fatal(err)
	}

	if idx.Count() != 3 {
		t.Errorf("expected 3 entries, got %d", idx.Count())
	}

	// List all, default sort by timestamp ascending
	all := idx.List(ListOptions{})
	if len(all) != 3 {
		t.Errorf("expected 3 entries, got %d", len(all))
	}

	// Filter by repo substring
	apiOnly := idx.List(ListOptions{Repo: "api"})
	if len(apiOnly) != 2 {
		t.Errorf("expected 2 api entries, got %d", len(apiOnly))
	}

	// Filter by status
	failures := idx.List(ListOptions{Status: "failure"})
	if len(failures) != 1 {
		t.Errorf("expected 1 failure, got %d", len(failures))
	}
	if failures[0].Repo != "web" {
		t.Errorf("expected web repo failure, got %s", failures[0].Repo)
	}

	// Filter by grade
	gradeA := idx.List(ListOptions{Grade: "A"})
	if len(gradeA) != 1 {
		t.Errorf("expected 1 grade-A entry, got %d", len(gradeA))
	}

	// Sort by repo descending
	sorted := idx.List(ListOptions{SortField: "repo", SortDesc: true})
	if sorted[0].Repo != "web" {
		t.Errorf("expected web first in desc sort, got %s", sorted[0].Repo)
	}
}

func TestLatestPerRepo(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().UTC()

	writePBOM(t, dir, "acme_api_100.pbom.json",
		samplePBOM("acme/api", "main", "success", "A", 95, now.Add(-time.Hour)))
	writePBOM(t, dir, "acme_api_200.pbom.json",
		samplePBOM("acme/api", "main", "success", "B", 85, now))
	writePBOM(t, dir, "acme_web_300.pbom.json",
		samplePBOM("acme/web", "main", "failure", "C", 72, now))

	idx := NewIndex(dir)
	if err := idx.Load(); err != nil {
		t.Fatal(err)
	}

	latest := idx.LatestPerRepo()
	if len(latest) != 2 {
		t.Fatalf("expected 2 repos, got %d", len(latest))
	}

	// Find api entry — should be the most recent (run 200)
	for _, e := range latest {
		if e.Repo == "api" && e.RunID != "200" {
			t.Errorf("expected latest api run 200, got %s", e.RunID)
		}
	}
}

func TestGet(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().UTC()

	writePBOM(t, dir, "acme_api_100.pbom.json",
		samplePBOM("acme/api", "main", "success", "A", 95, now))

	idx := NewIndex(dir)
	if err := idx.Load(); err != nil {
		t.Fatal(err)
	}

	pbom, err := idx.Get("acme", "api", "100")
	if err != nil {
		t.Fatal(err)
	}
	if pbom.Source.Repository != "acme/api" {
		t.Errorf("expected acme/api, got %s", pbom.Source.Repository)
	}

	// Not found
	_, err = idx.Get("acme", "missing", "999")
	if err == nil {
		t.Error("expected error for missing PBOM")
	}
}

func TestParseFilename(t *testing.T) {
	tests := []struct {
		name  string
		owner string
		repo  string
		runID string
	}{
		{"acme_api_12345.pbom.json", "acme", "api", "12345"},
		{"org_repo_999.pbom.json", "org", "repo", "999"},
		{"single.pbom.json", "single", "", ""},
	}

	for _, tt := range tests {
		owner, repo, runID := parseFilename(tt.name)
		if owner != tt.owner || repo != tt.repo || runID != tt.runID {
			t.Errorf("parseFilename(%q) = (%q, %q, %q), want (%q, %q, %q)",
				tt.name, owner, repo, runID, tt.owner, tt.repo, tt.runID)
		}
	}
}

func TestLoadEmptyDir(t *testing.T) {
	dir := t.TempDir()
	idx := NewIndex(dir)
	if err := idx.Load(); err != nil {
		t.Fatal(err)
	}
	if idx.Count() != 0 {
		t.Errorf("expected 0 entries, got %d", idx.Count())
	}
}

func TestLoadNonexistentDir(t *testing.T) {
	idx := NewIndex("/nonexistent/path")
	if err := idx.Load(); err != nil {
		t.Fatal("expected no error for nonexistent dir, got", err)
	}
	if idx.Count() != 0 {
		t.Errorf("expected 0 entries, got %d", idx.Count())
	}
}
