package sbom

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// CycloneDX 1.4 JSON structures

// CDXBom represents a CycloneDX Bill of Materials.
type CDXBom struct {
	XMLName      xml.Name       `xml:"bom" json:"-"`
	XMLNS        string         `xml:"xmlns,attr,omitempty" json:"-"`
	BomFormat    string         `json:"bomFormat"`
	SpecVersion  string         `json:"specVersion" xml:"version,attr"`
	SerialNumber string         `json:"serialNumber" xml:"serialNumber,attr"`
	Version      int            `json:"version" xml:"version"`
	Metadata     *CDXMetadata   `json:"metadata" xml:"metadata"`
	Components   []CDXComponent `json:"components" xml:"components>component"`
}

// CDXMetadata contains metadata about the SBOM.
type CDXMetadata struct {
	Timestamp string      `json:"timestamp" xml:"timestamp"`
	Tools     []CDXTool   `json:"tools" xml:"tools>tool"`
	Component *CDXSubject `json:"component,omitempty" xml:"component,omitempty"`
}

// CDXTool represents a tool used to create the SBOM.
type CDXTool struct {
	Vendor  string `json:"vendor" xml:"vendor"`
	Name    string `json:"name" xml:"name"`
	Version string `json:"version" xml:"version"`
}

// CDXSubject represents the subject of the SBOM (the application/repo).
type CDXSubject struct {
	Type    string `json:"type" xml:"type,attr"`
	Name    string `json:"name" xml:"name"`
	Version string `json:"version,omitempty" xml:"version,omitempty"`
}

// CDXComponent represents a software component (dependency).
type CDXComponent struct {
	Type     string       `json:"type" xml:"type,attr"`
	BomRef   string       `json:"bom-ref" xml:"bom-ref,attr"`
	Name     string       `json:"name" xml:"name"`
	Version  string       `json:"version" xml:"version"`
	PURL     string       `json:"purl,omitempty" xml:"purl,omitempty"`
	Licenses []CDXLicense `json:"licenses,omitempty" xml:"licenses>license,omitempty"`
}

// CDXLicense represents a license declaration.
type CDXLicense struct {
	License CDXLicenseChoice `json:"license" xml:"license"`
}

// CDXLicenseChoice represents a license identifier or name.
type CDXLicenseChoice struct {
	ID   string `json:"id,omitempty" xml:"id,omitempty"`
	Name string `json:"name,omitempty" xml:"name,omitempty"`
}

// generateCycloneDXJSON creates a CycloneDX 1.4 JSON SBOM.
func generateCycloneDXJSON(input *GeneratorInput, deps []Dependency, g *Generator) (string, error) {
	bom := buildCycloneDXBom(input, deps, g)

	data, err := json.MarshalIndent(bom, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal CycloneDX JSON: %w", err)
	}

	return string(data), nil
}

// generateCycloneDXXML creates a CycloneDX 1.4 XML SBOM.
func generateCycloneDXXML(input *GeneratorInput, deps []Dependency, g *Generator) (string, error) {
	bom := buildCycloneDXBom(input, deps, g)
	bom.XMLNS = "http://cyclonedx.org/schema/bom/1.4"
	bom.BomFormat = "" // Not used in XML

	data, err := xml.MarshalIndent(bom, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal CycloneDX XML: %w", err)
	}

	return xml.Header + string(data), nil
}

// buildCycloneDXBom constructs a CycloneDX BOM structure.
func buildCycloneDXBom(input *GeneratorInput, deps []Dependency, g *Generator) *CDXBom {
	components := make([]CDXComponent, 0, len(deps))

	for i, dep := range deps {
		comp := CDXComponent{
			Type:    "library",
			BomRef:  fmt.Sprintf("pkg-%d", i+1),
			Name:    dep.Name,
			Version: dep.Version,
			PURL:    dep.PURL,
		}

		if dep.License != "" {
			comp.Licenses = []CDXLicense{
				{
					License: CDXLicenseChoice{
						ID: dep.License,
					},
				},
			}
		}

		components = append(components, comp)
	}

	repoName := input.RepoName
	if input.OrgName != "" {
		repoName = input.OrgName + "/" + input.RepoName
	}

	return &CDXBom{
		BomFormat:    "CycloneDX",
		SpecVersion:  "1.4",
		SerialNumber: "urn:uuid:" + uuid.New().String(),
		Version:      1,
		Metadata: &CDXMetadata{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Tools: []CDXTool{
				{
					Vendor:  "Build-Guard",
					Name:    g.ToolName,
					Version: g.ToolVersion,
				},
			},
			Component: &CDXSubject{
				Type:    "application",
				Name:    repoName,
				Version: input.CommitSHA,
			},
		},
		Components: components,
	}
}
