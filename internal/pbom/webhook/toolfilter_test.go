package webhook

import (
	"reflect"
	"testing"
)

func TestFilterToolVersions(t *testing.T) {
	allTools := map[string]string{
		"go":     "1.23.0",
		"node":   "20.11.0",
		"npm":    "10.2.0",
		"python": "3.12.0",
		"java":   "17.0.9",
		"docker": "28.0.0",
		"rustc":  "1.77.0",
		"cargo":  "1.77.0",
		"dotnet": "8.0.0",
		"gradle": "8.5.0",
		"mvn":    "3.9.6",
		"helm":   "3.14.0",
	}

	tests := []struct {
		name      string
		tools     map[string]string
		languages map[string]int64
		wantKeys  []string
	}{
		{
			name:      "Go repo keeps go and docker",
			tools:     allTools,
			languages: map[string]int64{"Go": 50000, "Dockerfile": 200},
			wantKeys:  []string{"go", "docker"},
		},
		{
			name:      "Python repo keeps python and docker",
			tools:     allTools,
			languages: map[string]int64{"Python": 30000},
			wantKeys:  []string{"python", "docker"},
		},
		{
			name:      "JavaScript repo keeps node npm docker",
			tools:     allTools,
			languages: map[string]int64{"JavaScript": 40000},
			wantKeys:  []string{"node", "npm", "docker"},
		},
		{
			name:      "TypeScript repo keeps node npm docker",
			tools:     allTools,
			languages: map[string]int64{"TypeScript": 40000},
			wantKeys:  []string{"node", "npm", "docker"},
		},
		{
			name:      "Java repo keeps java gradle mvn docker",
			tools:     allTools,
			languages: map[string]int64{"Java": 60000},
			wantKeys:  []string{"java", "gradle", "mvn", "docker"},
		},
		{
			name:      "Rust repo keeps rustc cargo docker",
			tools:     allTools,
			languages: map[string]int64{"Rust": 25000},
			wantKeys:  []string{"rustc", "cargo", "docker"},
		},
		{
			name:      "C# repo keeps dotnet docker",
			tools:     allTools,
			languages: map[string]int64{"C#": 35000},
			wantKeys:  []string{"dotnet", "docker"},
		},
		{
			name:      "multi-language Go+JS keeps go node npm docker",
			tools:     allTools,
			languages: map[string]int64{"Go": 40000, "JavaScript": 10000},
			wantKeys:  []string{"go", "node", "npm", "docker"},
		},
		{
			name:      "nil languages returns all tools",
			tools:     allTools,
			languages: nil,
			wantKeys:  nil, // special: check all returned
		},
		{
			name:      "empty languages returns all tools",
			tools:     allTools,
			languages: map[string]int64{},
			wantKeys:  nil, // special: check all returned
		},
		{
			name:      "unrecognized language returns all tools",
			tools:     allTools,
			languages: map[string]int64{"Haskell": 5000},
			wantKeys:  nil, // special: check all returned
		},
		{
			name:      "nil tools returns nil",
			tools:     nil,
			languages: map[string]int64{"Go": 50000},
			wantKeys:  nil, // special: nil returned
		},
		{
			name:      "empty tools returns empty",
			tools:     map[string]string{},
			languages: map[string]int64{"Go": 50000},
			wantKeys:  nil, // special: empty returned
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FilterToolVersions(tt.tools, tt.languages)

			// Special cases: should return original map
			if tt.wantKeys == nil {
				if tt.tools == nil {
					if got != nil {
						t.Errorf("expected nil, got %v", got)
					}
					return
				}
				if len(tt.tools) == 0 {
					if len(got) != 0 {
						t.Errorf("expected empty, got %v", got)
					}
					return
				}
				// Should return all tools unfiltered
				if len(got) != len(tt.tools) {
					t.Errorf("expected %d tools (unfiltered), got %d: %v", len(tt.tools), len(got), keys(got))
				}
				return
			}

			gotKeys := keys(got)
			wantSet := make(map[string]bool)
			for _, k := range tt.wantKeys {
				wantSet[k] = true
			}
			gotSet := make(map[string]bool)
			for _, k := range gotKeys {
				gotSet[k] = true
			}

			if !reflect.DeepEqual(gotSet, wantSet) {
				t.Errorf("keys = %v, want %v", gotKeys, tt.wantKeys)
			}

			// Verify values are preserved
			for k, v := range got {
				if tt.tools[k] != v {
					t.Errorf("tool %s version = %q, want %q", k, v, tt.tools[k])
				}
			}
		})
	}
}

func keys(m map[string]string) []string {
	var result []string
	for k := range m {
		result = append(result, k)
	}
	return result
}
