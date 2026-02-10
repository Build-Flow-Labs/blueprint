package sbom

import (
	"encoding/json"
	"encoding/xml"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestGenerateCycloneDXJSON(t *testing.T) {
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
				},
			},
			expectedError: false,
			assertFunc: func(t *testing.T, result string) {
				var bom CDXBom
				err := json.Unmarshal([]byte(result), &bom)
				if err != nil {
					t.Fatalf("Failed to unmarshal JSON: %v", err)
				}

				if bom.BomFormat != "CycloneDX" {
					t.Errorf("Expected BomFormat to be CycloneDX, got %s", bom.BomFormat)
				}

				if len(bom.Components) != 1 {
					t.Fatalf("Expected 1 component, got %d", len(bom.Components))
				}

				if bom.Components[0].Name != "testdep" {
					t.Errorf("Expected component name to be testdep, got %s", bom.Components[0].Name)
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
				var bom CDXBom
				err := json.Unmarshal([]byte(result), &bom)
				if err != nil {
					t.Fatalf("Failed to unmarshal JSON: %v", err)
				}

				if len(bom.Components) != 0 {
					t.Fatalf("Expected 0 components, got %d", len(bom.Components))
				}
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := &Generator{ToolName: "testtool", ToolVersion: "1.0.0"}
			result, err := generateCycloneDXJSON(tc.input, tc.deps, g)

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

func TestGenerateCycloneDXXML(t *testing.T) {
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
				},
			},
			expectedError: false,
			assertFunc: func(t *testing.T, result string) {
				var bom CDXBom
				err := xml.Unmarshal([]byte(result), &bom)
				if err != nil {
					t.Fatalf("Failed to unmarshal XML: %v", err)
				}

				if bom.SpecVersion != "1.4" {
					t.Errorf("Expected SpecVersion to be 1.4, got %s", bom.SpecVersion)
				}

				if len(bom.Components) != 1 {
					t.Fatalf("Expected 1 component, got %d", len(bom.Components))
				}

				if bom.Components[0].Name != "testdep" {
					t.Errorf("Expected component name to be testdep, got %s", bom.Components[0].Name)
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
				var bom CDXBom
				err := xml.Unmarshal([]byte(result), &bom)
				if err != nil {
					t.Fatalf("Failed to unmarshal XML: %v", err)
				}

				if len(bom.Components) != 0 {
					t.Fatalf("Expected 0 components, got %d", len(bom.Components))
				}
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := &Generator{ToolName: "testtool", ToolVersion: "1.0.0"}
			result, err := generateCycloneDXXML(tc.input, tc.deps, g)

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

func TestBuildCycloneDXBom(t *testing.T) {
	testCases := []struct {
		name     string
		input    *GeneratorInput
		deps     []Dependency
		assertFn func(t *testing.T, bom *CDXBom)
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
				},
			},
			assertFn: func(t *testing.T, bom *CDXBom) {
				if bom.BomFormat != "CycloneDX" {
					t.Errorf("Expected BomFormat to be CycloneDX, got %s", bom.BomFormat)
				}
				if bom.SpecVersion != "1.4" {
					t.Errorf("Expected SpecVersion to be 1.4, got %s", bom.SpecVersion)
				}
				if bom.Version != 1 {
					t.Errorf("Expected Version to be 1, got %d", bom.Version)
				}
				if bom.Metadata == nil {
					t.Fatal("Expected Metadata to be non-nil")
				}
				if bom.Metadata.Component == nil {
					t.Fatal("Expected Metadata.Component to be non-nil")
				}
				if bom.Metadata.Component.Name != "testorg/testrepo" {
					t.Errorf("Expected Metadata.Component.Name to be testorg/testrepo, got %s", bom.Metadata.Component.Name)
				}
				if bom.Metadata.Component.Version != "testsha" {
					t.Errorf("Expected Metadata.Component.Version to be testsha, got %s", bom.Metadata.Component.Version)
				}
				if len(bom.Components) != 1 {
					t.Fatalf("Expected 1 component, got %d", len(bom.Components))
				}
				if bom.Components[0].Name != "testdep" {
					t.Errorf("Expected component name to be testdep, got %s", bom.Components[0].Name)
				}
				if bom.Components[0].Licenses[0].License.ID != "MIT" {
					t.Errorf("Expected license to be MIT, got %s", bom.Components[0].Licenses[0].License.ID)
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
				},
			},
			assertFn: func(t *testing.T, bom *CDXBom) {
				if bom.Metadata.Component.Name != "testrepo" {
					t.Errorf("Expected Metadata.Component.Name to be testrepo, got %s", bom.Metadata.Component.Name)
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
				},
			},
			assertFn: func(t *testing.T, bom *CDXBom) {
				if len(bom.Components[0].Licenses) != 0 {
					t.Errorf("Expected no licenses, got %d", len(bom.Components[0].Licenses))
				}
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := &Generator{ToolName: "testtool", ToolVersion: "1.0.0"}
			bom := buildCycloneDXBom(tc.input, tc.deps, g)
			tc.assertFn(t, bom)

			// Check that the timestamp is a valid RFC3339 string
			_, err := time.Parse(time.RFC3339, bom.Metadata.Timestamp)
			if err != nil {
				t.Errorf("Timestamp is not a valid RFC3339 string: %v", err)
			}

			// Check that the serial number is a valid UUID
			_, err = uuid.Parse(bom.SerialNumber[9:]) // Remove "urn:uuid:" prefix
			if err != nil {
				t.Errorf("SerialNumber is not a valid UUID: %v", err)
			}
		})
	}
}

func TestCDXBomMarshalJSON(t *testing.T) {
	bom := CDXBom{
		BomFormat:    "CycloneDX",
		SpecVersion:  "1.4",
		SerialNumber: "urn:uuid:123e4567-e89b-12d3-a456-426614174000",
		Version:      1,
		Metadata: &CDXMetadata{
			Timestamp: "2023-11-19T12:00:00Z",
			Tools: []CDXTool{
				{
					Vendor:  "Build-Guard",
					Name:    "testtool",
					Version: "1.0.0",
				},
			},
			Component: &CDXSubject{
				Type:    "application",
				Name:    "testapp",
				Version: "1.0",
			},
		},
		Components: []CDXComponent{
			{
				Type:    "library",
				BomRef:  "pkg-1",
				Name:    "testdep",
				Version: "1.2.3",
				PURL:    "pkg:test/testdep@1.2.3",
				Licenses: []CDXLicense{
					{
						License: CDXLicenseChoice{
							ID: "MIT",
						},
					},
				},
			},
		},
	}

	data, err := json.MarshalIndent(bom, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal JSON: %v", err)
	}

	// Basic validation of the marshaled JSON
	jsonString := string(data)
	if !strings.Contains(jsonString, "\"bomFormat\": \"CycloneDX\"") {
		t.Errorf("Expected bomFormat in JSON, got: %s", jsonString)
	}
	if !strings.Contains(jsonString, "\"specVersion\": \"1.4\"") {
		t.Errorf("Expected specVersion in JSON, got: %s", jsonString)
	}
	if !strings.Contains(jsonString, "\"serialNumber\": \"urn:uuid:123e4567-e89b-12d3-a456-426614174000\"") {
		t.Errorf("Expected serialNumber in JSON, got: %s", jsonString)
	}
	if !strings.Contains(jsonString, "\"version\": 1") {
		t.Errorf("Expected version in JSON, got: %s", jsonString)
	}
	if !strings.Contains(jsonString, "\"timestamp\": \"2023-11-19T12:00:00Z\"") {
		t.Errorf("Expected timestamp in JSON, got: %s", jsonString)
	}
	if !strings.Contains(jsonString, "\"name\": \"testdep\"") {
		t.Errorf("Expected component name in JSON, got: %s", jsonString)
	}
}

func TestCDXBomMarshalXML(t *testing.T) {
	bom := CDXBom{
		XMLNS:        "http://cyclonedx.org/schema/bom/1.4",
		SpecVersion:  "1.4",
		SerialNumber: "urn:uuid:123e4567-e89b-12d3-a456-426614174000",
		Version:      1,
		Metadata: &CDXMetadata{
			Timestamp: "2023-11-19T12:00:00Z",
			Tools: []CDXTool{
				{
					Vendor:  "Build-Guard",
					Name:    "testtool",
					Version: "1.0.0",
				},
			},
			Component: &CDXSubject{
				Type:    "application",
				Name:    "testapp",
				Version: "1.0",
			},
		},
		Components: []CDXComponent{
			{
				Type:    "library",
				BomRef:  "pkg-1",
				Name:    "testdep",
				Version: "1.2.3",
				PURL:    "pkg:test/testdep@1.2.3",
				Licenses: []CDXLicense{
					{
						License: CDXLicenseChoice{
							ID: "MIT",
						},
					},
				},
			},
		},
	}

	data, err := xml.MarshalIndent(bom, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal XML: %v", err)
	}

	xmlString := string(data)
	if !strings.Contains(xmlString, "<bom xmlns=\"http://cyclonedx.org/schema/bom/1.4\"") {
		t.Errorf("Expected xmlns in XML, got: %s", xmlString)
	}
	if !strings.Contains(xmlString, "version=\"1.4\"") {
		t.Errorf("Expected version attribute in XML, got: %s", xmlString)
	}
	if !strings.Contains(xmlString, "<name>testdep</name>") {
		t.Errorf("Expected component name in XML, got: %s", xmlString)
	}
}