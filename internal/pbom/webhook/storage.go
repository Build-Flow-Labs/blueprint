package webhook

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/build-flow-labs/blueprint/pbom/schema"
)

// Store writes an enriched PBOM to the storage directory as JSON.
// File naming: {owner}_{repo}_{runID}.pbom.json
func Store(dir string, pbom *schema.PBOM, owner, repo string, runID int64) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("creating storage dir: %w", err)
	}

	filename := fmt.Sprintf("%s_%s_%d.pbom.json", owner, repo, runID)
	path := filepath.Join(dir, filename)

	data, err := json.MarshalIndent(pbom, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshaling PBOM: %w", err)
	}

	if err := os.WriteFile(path, data, 0o644); err != nil {
		return "", fmt.Errorf("writing PBOM file: %w", err)
	}

	return path, nil
}
