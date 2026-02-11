package detect

import "testing"

func TestParseGo(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"standard", "go version go1.22.4 linux/amd64", "1.22.4"},
		{"darwin", "go version go1.25.5 darwin/arm64", "1.25.5"},
		{"rc", "go version go1.23rc1 linux/amd64", "1.23rc1"},
		{"no match returns input", "some unknown output", "some unknown output"},
		{"empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseGo(tt.input); got != tt.want {
				t.Errorf("parseGo(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestTrimV(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"with v", "v20.11.0", "20.11.0"},
		{"without v", "20.11.0", "20.11.0"},
		{"leading space", "  v3.14.2", "3.14.2"},
		{"empty", "", ""},
		{"just v", "v", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := trimV(tt.input); got != tt.want {
				t.Errorf("trimV(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestLastField(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"python", "Python 3.12.1", "3.12.1"},
		{"kubectl", "Client Version: v1.29.0", "v1.29.0"},
		{"single", "3.12.1", "3.12.1"},
		{"empty returns input", "", ""},
		{"multi space", "cargo  1.77.0", "1.77.0"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := lastField(tt.input); got != tt.want {
				t.Errorf("lastField(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestSecondField(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"rustc", "rustc 1.77.0 (aedd173a2 2024-03-17)", "1.77.0"},
		{"two fields", "rustc 1.77.0", "1.77.0"},
		{"single returns input", "1.77.0", "1.77.0"},
		{"empty returns input", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := secondField(tt.input); got != tt.want {
				t.Errorf("secondField(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestParseJava(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"openjdk", "openjdk version \"21.0.1\" 2023-10-17\nOpenJDK Runtime", "21.0.1"},
		{"oracle", "java version \"1.8.0_392\"\nJava(TM) SE Runtime", "1.8.0_392"},
		{"no quotes", "java 21.0.1", "21.0.1"},
		{"empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseJava(tt.input); got != tt.want {
				t.Errorf("parseJava(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestParseGradle(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"standard", "\n------------------------------------------------------------\nGradle 8.5\n----\n", "8.5"},
		{"with patch", "Gradle 7.6.3", "7.6.3"},
		{"no match", "some unknown output\nno version here", ""},
		{"empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseGradle(tt.input); got != tt.want {
				t.Errorf("parseGradle(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestParseMaven(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"standard", "Apache Maven 3.9.6 (bc0240f3c)\nMaven home: /usr", "3.9.6"},
		{"simple", "Apache Maven 3.8.1", "3.8.1"},
		{"no keyword", "some other output", ""},
		{"empty", "", ""},
		{"maven last word", "Apache Maven", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseMaven(tt.input); got != tt.want {
				t.Errorf("parseMaven(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
