// Package dashboard provides a web UI for viewing PBOMs.
package dashboard

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/build-flow-labs/blueprint/pbom/schema"
)

// IndexEntry is a denormalized PBOM summary for fast listing.
type IndexEntry struct {
	Owner         string
	Repo          string
	RunID         string
	Branch        string
	Status        string
	Grade         string
	Score         int
	ArtifactCount int
	Timestamp     time.Time
	FilePath      string
	Actor         string
	WorkflowName  string
}

// ListOptions controls filtering and sorting of PBOM listings.
type ListOptions struct {
	Repo      string // filter by repo name substring (case-insensitive)
	Status    string // filter by build status
	Grade     string // filter by health grade
	SortField string // "timestamp", "repo", "grade", "status"
	SortDesc  bool
}

// Index is an in-memory store of PBOM summaries.
type Index struct {
	mu         sync.RWMutex
	entries    []IndexEntry
	storageDir string
}

// NewIndex creates an index backed by a storage directory.
func NewIndex(storageDir string) *Index {
	return &Index{storageDir: storageDir}
}

// Load reads all .pbom.json files from the storage directory into the index.
func (idx *Index) Load() error {
	idx.mu.Lock()
	defer idx.mu.Unlock()

	dirEntries, err := os.ReadDir(idx.storageDir)
	if err != nil {
		if os.IsNotExist(err) {
			idx.entries = nil
			return nil
		}
		return fmt.Errorf("reading storage dir: %w", err)
	}

	var entries []IndexEntry
	for _, de := range dirEntries {
		if de.IsDir() || !strings.HasSuffix(de.Name(), ".pbom.json") {
			continue
		}

		path := filepath.Join(idx.storageDir, de.Name())
		entry, err := loadEntry(path, de.Name())
		if err != nil {
			continue // skip corrupt files
		}
		entries = append(entries, entry)
	}

	idx.entries = entries
	return nil
}

// loadEntry reads a single PBOM file and extracts an IndexEntry.
func loadEntry(path, filename string) (IndexEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return IndexEntry{}, err
	}

	var pbom schema.PBOM
	if err := json.Unmarshal(data, &pbom); err != nil {
		return IndexEntry{}, err
	}

	// Parse owner/repo from filename: {owner}_{repo}_{runID}.pbom.json
	owner, repo, runID := parseFilename(filename)

	entry := IndexEntry{
		Owner:         owner,
		Repo:          repo,
		RunID:         runID,
		Branch:        pbom.Source.Branch,
		Status:        pbom.Build.Status,
		ArtifactCount: len(pbom.Artifacts),
		Timestamp:     pbom.Timestamp,
		FilePath:      path,
		Actor:         pbom.Build.Actor,
		WorkflowName:  pbom.Build.WorkflowName,
	}

	if pbom.HealthScore != nil {
		entry.Grade = pbom.HealthScore.Grade
		entry.Score = pbom.HealthScore.Score
	}

	return entry, nil
}

// parseFilename extracts owner, repo, runID from "{owner}_{repo}_{runID}.pbom.json".
func parseFilename(name string) (owner, repo, runID string) {
	name = strings.TrimSuffix(name, ".pbom.json")
	parts := strings.SplitN(name, "_", 3)
	if len(parts) >= 3 {
		return parts[0], parts[1], parts[2]
	}
	if len(parts) == 2 {
		return parts[0], parts[1], ""
	}
	return name, "", ""
}

// List returns entries matching the given options.
func (idx *Index) List(opts ListOptions) []IndexEntry {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	var filtered []IndexEntry
	for _, e := range idx.entries {
		if opts.Repo != "" && !strings.Contains(strings.ToLower(e.Owner+"/"+e.Repo), strings.ToLower(opts.Repo)) {
			continue
		}
		if opts.Status != "" && e.Status != opts.Status {
			continue
		}
		if opts.Grade != "" && e.Grade != opts.Grade {
			continue
		}
		filtered = append(filtered, e)
	}

	sortEntries(filtered, opts.SortField, opts.SortDesc)
	return filtered
}

// Get returns the full PBOM for a specific entry.
func (idx *Index) Get(owner, repo, runID string) (*schema.PBOM, error) {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	for _, e := range idx.entries {
		if e.Owner == owner && e.Repo == repo && e.RunID == runID {
			data, err := os.ReadFile(e.FilePath)
			if err != nil {
				return nil, err
			}
			var pbom schema.PBOM
			if err := json.Unmarshal(data, &pbom); err != nil {
				return nil, err
			}
			return &pbom, nil
		}
	}
	return nil, fmt.Errorf("PBOM not found: %s/%s/%s", owner, repo, runID)
}

// LatestPerRepo returns the most recent IndexEntry per owner/repo.
func (idx *Index) LatestPerRepo() []IndexEntry {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	latest := make(map[string]IndexEntry)
	for _, e := range idx.entries {
		key := e.Owner + "/" + e.Repo
		if existing, ok := latest[key]; !ok || e.Timestamp.After(existing.Timestamp) {
			latest[key] = e
		}
	}

	result := make([]IndexEntry, 0, len(latest))
	for _, e := range latest {
		result = append(result, e)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Owner+"/"+result[i].Repo < result[j].Owner+"/"+result[j].Repo
	})
	return result
}

// Count returns the total number of indexed PBOMs.
func (idx *Index) Count() int {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	return len(idx.entries)
}

func sortEntries(entries []IndexEntry, field string, desc bool) {
	sort.Slice(entries, func(i, j int) bool {
		var less bool
		switch field {
		case "repo":
			less = entries[i].Owner+"/"+entries[i].Repo < entries[j].Owner+"/"+entries[j].Repo
		case "grade":
			less = entries[i].Grade < entries[j].Grade
		case "status":
			less = entries[i].Status < entries[j].Status
		default: // "timestamp" or empty
			less = entries[i].Timestamp.Before(entries[j].Timestamp)
		}
		if desc {
			return !less
		}
		return less
	})
}
