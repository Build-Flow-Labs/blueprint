package webhook

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestInferSLSALevel(t *testing.T) {
	tests := []struct {
		name      string
		builderID string
		want      int
	}{
		{
			name:      "attest-build-provenance builder",
			builderID: "https://github.com/actions/attest-build-provenance@v2",
			want:      3,
		},
		{
			name:      "generic github builder",
			builderID: "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/builder_go_slsa3.yml",
			want:      1,
		},
		{
			name:      "unknown builder",
			builderID: "https://example.com/builder",
			want:      1,
		},
		{
			name:      "empty builder",
			builderID: "",
			want:      0,
		},
		{
			name:      "attest-build-provenance in path",
			builderID: "https://github.com/actions/attest-build-provenance/internal/runner@abc123",
			want:      3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := InferSLSALevel(tt.builderID)
			if got != tt.want {
				t.Errorf("InferSLSALevel(%q) = %d, want %d", tt.builderID, got, tt.want)
			}
		})
	}
}

func TestExtractBuilderID(t *testing.T) {
	tests := []struct {
		name string
		// Build a base64-encoded in-toto statement
		builderID string
		wantID    string
	}{
		{
			name:      "valid payload",
			builderID: "https://github.com/actions/attest-build-provenance@v2",
			wantID:    "https://github.com/actions/attest-build-provenance@v2",
		},
		{
			name:      "empty builder",
			builderID: "",
			wantID:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build a minimal in-toto statement with SLSA predicate
			stmt := map[string]interface{}{
				"predicateType": "https://slsa.dev/provenance/v1",
				"predicate": map[string]interface{}{
					"buildDefinition": map[string]interface{}{
						"buildType": "https://actions.github.io/buildtypes/workflow/v1",
					},
					"runDetails": map[string]interface{}{
						"builder": map[string]interface{}{
							"id": tt.builderID,
						},
					},
				},
			}

			payload, _ := json.Marshal(stmt)
			b64 := base64.StdEncoding.EncodeToString(payload)

			got := extractBuilderID(b64)
			if got != tt.wantID {
				t.Errorf("extractBuilderID() = %q, want %q", got, tt.wantID)
			}
		})
	}
}

func TestExtractBuilderIDInvalidPayload(t *testing.T) {
	tests := []struct {
		name    string
		payload string
	}{
		{name: "not base64", payload: "not-valid-base64!!!"},
		{name: "valid base64 but not JSON", payload: base64.StdEncoding.EncodeToString([]byte("not json"))},
		{name: "empty string", payload: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractBuilderID(tt.payload)
			if got != "" {
				t.Errorf("extractBuilderID(%q) = %q, want empty", tt.payload, got)
			}
		})
	}
}

func TestTruncDigest(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"sha256:abc123def456789abcdef0123456789", "sha256:abc123def456..."},
		{"short", "short"},
		{"exactly_19_chars__!", "exactly_19_chars__!"},
		{"exactly_twenty_char", "exactly_twenty_char"},
		{"", ""},
	}

	for _, tt := range tests {
		got := truncDigest(tt.input)
		if got != tt.want {
			t.Errorf("truncDigest(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
