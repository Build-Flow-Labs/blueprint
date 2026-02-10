package sbom

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestGenerateSPDXJSON(t *testing.T) {
	testCases := []struct {
		name          string
		input         *GeneratorInput
		deps          []Dependency
		expectedError bool
		assertFunc    func(t *testing.T, result string)
	}{
		{
			name: "valid input",
			input: &GeneratorInput{
				OrgName:   "testorg",
				RepoName:  "testrepo",
				CommitSHA: "testsha",
			},
			deps: []Dependency{
				{
					Name:    "testdep",
					Version: "1.2.3",
					PURL:    "pkg:test/testdep@1.2.3",
					License: "MIT",
					Direct:  true,
				},
			},
			expectedError: false,
			assertFunc: func(t *testing.T, result string) {
				var doc SPDXDocument
				err := json.Unmarshal([]byte(result), &doc)
				if err != nil {
					t.Fatalf("Failed to unmarshal JSON: %v", err)
				}

				if doc.SPDXVersion != "SPDX-2.3" {
					t.Errorf("Expected SPDXVersion to be SPDX-2.3, got %s", doc.SPDXVersion)
				}

				if len(doc.Packages) != 2 {
					t.Fatalf("Expected 2 packages, got %d", len(doc.Packages))
				}

				if doc.Packages[1].Name != "testdep" {
					t.Errorf("Expected package name to be testdep, got %s", doc.Packages[1].Name)
				}

				if len(doc.Relationships) != 2 {
					t.Fatalf("Expected 2 relationships, got %d", len(doc.Relationships))
				}

				foundDependsOn := false
				for _, rel := range doc.Relationships {
					if rel.RelationshipType == "DEPENDS_ON" {
						foundDependsOn = true
						break
					}
				}
				if !foundDependsOn {
					t.Error("Expected DEPENDS_ON relationship")
				}
			},
		},
		{
			name: "no dependencies",
			input: &GeneratorInput{
				OrgName:   "testorg",
				RepoName:  "testrepo",
				CommitSHA: "testsha",
			},
			deps:          []Dependency{},
			expectedError: false,
			assertFunc: func(t *testing.T, result string) {
				var doc SPDXDocument
				err := json.Unmarshal([]byte(result), &doc)
				if err != nil {
					t.Fatalf("Failed to unmarshal JSON: %v", err)
				}

				if len(doc.Packages) != 1 {
					t.Fatalf("Expected 1 package, got %d", len(doc.Packages))
				}

				if len(doc.Relationships) != 1 {
					t.Fatalf("Expected 1 relationship, got %d", len(doc.Relationships))
				}
			},
		},
		{
			name: "marshal error",
			input: &GeneratorInput{
				OrgName:   "testorg",
				RepoName:  "testrepo",
				CommitSHA: "testsha",
			},
			deps: []Dependency{
				{
					Name:    "testdep",
					Version: "1.2.3",
					PURL:    "pkg:test/testdep@1.2.3",
					License: "MIT",
				},
			},
			expectedError: false,
			assertFunc: func(t *testing.T, result string) {
			},
		},
		{
			name: "no org name",
			input: &GeneratorInput{
				RepoName:  "testrepo",
				CommitSHA: "testsha",
			},
			deps: []Dependency{
				{
					Name:    "testdep",
					Version: "1.2.3",
					PURL:    "pkg:test/testdep@1.2.3",
					License: "MIT",
					Direct:  true,
				},
			},
			expectedError: false,
			assertFunc: func(t *testing.T, result string) {
				var doc SPDXDocument
				err := json.Unmarshal([]byte(result), &doc)
				if err != nil {
					t.Fatalf("Failed to unmarshal JSON: %v", err)
				}

				if !strings.Contains(doc.DocumentNamespace, "testrepo") {
					t.Errorf("Expected DocumentNamespace to contain testrepo, got %s", doc.DocumentNamespace)
				}
				if doc.Packages[0].Name != "testrepo" {
					t.Errorf("Expected root package name to be testrepo, got %s", doc.Packages[0].Name)
				}
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := &Generator{ToolName: "testtool", ToolVersion: "1.0.0"}
			result, err := generateSPDXJSON(tc.input, tc.deps, g)

			if tc.expectedError && err == nil {
				t.Fatalf("Expected error, got nil")
			}

			if !tc.expectedError && err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if tc.assertFunc != nil {
				tc.assertFunc(t, result)
			}
		})
	}
}

func TestBuildSPDXDocument(t *testing.T) {
	testCases := []struct {
		name     string
		input    *GeneratorInput
		deps     []Dependency
		assertFn func(t *testing.T, doc *SPDXDocument)
	}{
		{
			name: "valid input",
			input: &GeneratorInput{
				OrgName:   "testorg",
				RepoName:  "testrepo",
				CommitSHA: "testsha",
			},
			deps: []Dependency{
				{
					Name:    "testdep",
					Version: "1.2.3",
					PURL:    "pkg:test/testdep@1.2.3",
					License: "MIT",
					Direct:  true,
				},
			},
			assertFn: func(t *testing.T, doc *SPDXDocument) {
				if doc.SPDXVersion != "SPDX-2.3" {
					t.Errorf("Expected SPDXVersion to be SPDX-2.3, got %s", doc.SPDXVersion)
				}
				if doc.Name != "SBOM for testorg/testrepo" {
					t.Errorf("Expected Name to be SBOM for testorg/testrepo, got %s", doc.Name)
				}
				if doc.DataLicense != "CC0-1.0" {
					t.Errorf("Expected DataLicense to be CC0-1.0, got %s", doc.DataLicense)
				}
				if len(doc.Packages) != 2 {
					t.Fatalf("Expected 2 packages, got %d", len(doc.Packages))
				}
				if doc.Packages[0].Name != "testorg/testrepo" {
					t.Errorf("Expected root package name to be testorg/testrepo, got %s", doc.Packages[0].Name)
				}
				if doc.Packages[1].Name != "testdep" {
					t.Errorf("Expected component name to be testdep, got %s", doc.Packages[1].Name)
				}
				if doc.Packages[1].LicenseConcluded != "MIT" {
					t.Errorf("Expected license to be MIT, got %s", doc.Packages[1].LicenseConcluded)
				}
				if len(doc.Relationships) != 2 {
					t.Fatalf("Expected 2 relationships, got %d", len(doc.Relationships))
				}
				foundDependsOn := false
				for _, rel := range doc.Relationships {
					if rel.RelationshipType == "DEPENDS_ON" {
						foundDependsOn = true
						break
					}
				}
				if !foundDependsOn {
					t.Error("Expected DEPENDS_ON relationship")
				}
			},
		},
		{
			name: "no org name",
			input: &GeneratorInput{
				RepoName:  "testrepo",
				CommitSHA: "testsha",
			},
			deps: []Dependency{
				{
					Name:    "testdep",
					Version: "1.2.3",
					PURL:    "pkg:test/testdep@1.2.3",
					License: "MIT",
					Direct:  true,
				},
			},
			assertFn: func(t *testing.T, doc *SPDXDocument) {
				if doc.Name != "SBOM for testrepo" {
					t.Errorf("Expected Name to be SBOM for testrepo, got %s", doc.Name)
				}
				if doc.Packages[0].Name != "testrepo" {
					t.Errorf("Expected root package name to be testrepo, got %s", doc.Packages[0].Name)
				}
				if !strings.Contains(doc.DocumentNamespace, "testrepo") {
					t.Errorf("Expected DocumentNamespace to contain testrepo, got %s", doc.DocumentNamespace)
				}
			},
		},
		{
			name: "no license",
			input: &GeneratorInput{
				OrgName:   "testorg",
				RepoName:  "testrepo",
				CommitSHA: "testsha",
			},
			deps: []Dependency{
				{
					Name:    "testdep",
					Version: "1.2.3",
					PURL:    "pkg:test/testdep@1.2.3",
					Direct:  true,
				},
			},
			assertFn: func(t *testing.T, doc *SPDXDocument) {
				if doc.Packages[1].LicenseConcluded != "NOASSERTION" {
					t.Errorf("Expected license to be NOASSERTION, got %s", doc.Packages[1].LicenseConcluded)
				}
			},
		},
		{
			name: "no purl",
			input: &GeneratorInput{
				OrgName:   "testorg",
				RepoName:  "testrepo",
				CommitSHA: "testsha",
			},
			deps: []Dependency{
				{
					Name:    "testdep",
					Version: "1.2.3",
					License: "MIT",
					Direct:  true,
				},
			},
			assertFn: func(t *testing.T, doc *SPDXDocument) {
				if len(doc.Packages[1].ExternalRefs) != 0 {
					t.Errorf("Expected no external refs, got %d", len(doc.Packages[1].ExternalRefs))
				}
			},
		},
		{
			name: "indirect dependency",
			input: &GeneratorInput{
				OrgName:   "testorg",
				RepoName:  "testrepo",
				CommitSHA: "testsha",
			},
			deps: []Dependency{
				{
					Name:    "testdep",
					Version: "1.2.3",
					PURL:    "pkg:test/testdep@1.2.3",
					License: "MIT",
					Direct:  false,
				},
			},
			assertFn: func(t *testing.T, doc *SPDXDocument) {
				foundDependsOn := false
				for _, rel := range doc.Relationships {
					if rel.RelationshipType == "DEPENDS_ON" {
						foundDependsOn = true
						break
					}
				}
				if foundDependsOn {
					t.Error("Did not expect DEPENDS_ON relationship")
				}
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := &Generator{ToolName: "testtool", ToolVersion: "1.0.0"}
			doc := buildSPDXDocument(tc.input, tc.deps, g)
			tc.assertFn(t, doc)

			// Check that the created timestamp is a valid RFC3339 string
			_, err := time.Parse(time.RFC3339, doc.CreationInfo.Created)
			if err != nil {
				t.Errorf("Created timestamp is not a valid RFC3339 string: %v", err)
			}

			// Check that the document namespace is a valid URI
			if !strings.HasPrefix(doc.DocumentNamespace, "https://buildguard.io/spdx/") {
				t.Errorf("DocumentNamespace does not have the expected prefix: %s", doc.DocumentNamespace)
			}
		})
	}
}

func TestSPDXDocumentMarshalJSON(t *testing.T) {
	doc := SPDXDocument{
		SPDXID:            "SPDXRef-DOCUMENT",
		SPDXVersion:       "SPDX-2.3",
		DataLicense:       "CC0-1.0",
		Name:              "Test Document",
		DocumentNamespace: "https://example.com/spdx/test-document",
		CreationInfo: SPDXCreationInfo{
			Created:            "2024-01-01T00:00:00Z",
			Creators:           []string{"Tool: test-tool-1.0", "Organization: Test Org"},
			LicenseListVersion: "3.19",
		},
		DocumentDescribes: []string{"SPDXRef-Package-root"},
		Packages: []SPDXPackage{
			{
				SPDXID:                "SPDXRef-Package-root",
				Name:                  "test-package",
				VersionInfo:           "1.0.0",
				DownloadLocation:      "https://example.com/test-package",
				FilesAnalyzed:         false,
				LicenseConcluded:      "MIT",
				CopyrightText:         "Copyright 2024 Test Org",
				PrimaryPackagePurpose: "APPLICATION",
			},
		},
		Relationships: []SPDXRelationship{
			{
				SPDXElementID:      "SPDXRef-DOCUMENT",
				RelationshipType:   "DESCRIBES",
				RelatedSPDXElement: "SPDXRef-Package-root",
			},
		},
	}

	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal JSON: %v", err)
	}

	jsonString := string(data)
	if !strings.Contains(jsonString, "\"spdxVersion\": \"SPDX-2.3\"") {
		t.Errorf("Expected spdxVersion in JSON, got: %s", jsonString)
	}
	if !strings.Contains(jsonString, "\"dataLicense\": \"CC0-1.0\"") {
		t.Errorf("Expected dataLicense in JSON, got: %s", jsonString)
	}
	if !strings.Contains(jsonString, "\"name\": \"Test Document\"") {
		t.Errorf("Expected name in JSON, got: %s", jsonString)
	}
	if !strings.Contains(jsonString, "\"SPDXID\": \"SPDXRef-Package-root\"") {
		t.Errorf("Expected package SPDXID in JSON, got: %s", jsonString)
	}
	if !strings.Contains(jsonString, "\"relationshipType\": \"DESCRIBES\"") {
		t.Errorf("Expected relationshipType in JSON, got: %s", jsonString)
	}
}