package cli

import "testing"

func TestIsValidSHA(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"valid 40-char hex", "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2", true},
		{"all zeros", "0000000000000000000000000000000000000000", true},
		{"all f", "ffffffffffffffffffffffffffffffffffffffff", true},
		{"too short", "a1b2c3d4e5f6", false},
		{"too long", "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2a", false},
		{"uppercase hex", "A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2", false},
		{"non-hex char", "g1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2", false},
		{"empty", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isValidSHA(tt.input); got != tt.want {
				t.Errorf("isValidSHA(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestIsValidDigest(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"valid digest", "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", true},
		{"all zeros", "sha256:0000000000000000000000000000000000000000000000000000000000000000", true},
		{"missing prefix", "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", false},
		{"wrong prefix", "md5:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", false},
		{"too short hex", "sha256:9f86d081884c7d65", false},
		{"uppercase hex", "sha256:9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08", false},
		{"empty", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isValidDigest(tt.input); got != tt.want {
				t.Errorf("isValidDigest(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestMapTrigger(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"push", "push"},
		{"pull_request", "pull_request"},
		{"workflow_dispatch", "workflow_dispatch"},
		{"schedule", "schedule"},
		{"release", "release"},
		{"", ""},
		{"repository_dispatch", "other"},
		{"workflow_call", "other"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := mapTrigger(tt.input); got != tt.want {
				t.Errorf("mapTrigger(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
