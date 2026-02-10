package sbom

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// SPDX 2.3 JSON structures

// SPDXDocument represents an SPDX 2.3 document.
type SPDXDocument struct {
	SPDXID                string                 `json:"SPDXID"`
	SPDXVersion           string                 `json:"spdxVersion"`
	CreationInfo          SPDXCreationInfo       `json:"creationInfo"`
	Name                  string                 `json:"name"`
	DataLicense           string                 `json:"dataLicense"`
	DocumentNamespace     string                 `json:"documentNamespace"`
	DocumentDescribes     []string               `json:"documentDescribes"`
	Packages              []SPDXPackage          `json:"packages"`
	Relationships         []SPDXRelationship     `json:"relationships"`
	ExternalDocumentRefs  []interface{}          `json:"externalDocumentRefs,omitempty"`
	HasExtractedLicensing []interface{}          `json:"hasExtractedLicensingInfo,omitempty"`
}

// SPDXCreationInfo contains information about the SPDX document creation.
type SPDXCreationInfo struct {
	Created            string   `json:"created"`
	Creators           []string `json:"creators"`
	LicenseListVersion string   `json:"licenseListVersion,omitempty"`
}

// SPDXPackage represents a software package in SPDX format.
type SPDXPackage struct {
	SPDXID                   string              `json:"SPDXID"`
	Name                     string              `json:"name"`
	VersionInfo              string              `json:"versionInfo,omitempty"`
	DownloadLocation         string              `json:"downloadLocation"`
	FilesAnalyzed            bool                `json:"filesAnalyzed"`
	LicenseConcluded         string              `json:"licenseConcluded"`
	LicenseDeclared          string              `json:"licenseDeclared,omitempty"`
	CopyrightText            string              `json:"copyrightText"`
	ExternalRefs             []SPDXExternalRef   `json:"externalRefs,omitempty"`
	PrimaryPackagePurpose    string              `json:"primaryPackagePurpose,omitempty"`
	Checksums                []SPDXChecksum      `json:"checksums,omitempty"`
}

// SPDXExternalRef represents an external reference (like PURL).
type SPDXExternalRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}

// SPDXChecksum represents a file checksum.
type SPDXChecksum struct {
	Algorithm     string `json:"algorithm"`
	ChecksumValue string `json:"checksumValue"`
}

// SPDXRelationship represents a relationship between SPDX elements.
type SPDXRelationship struct {
	SPDXElementID      string `json:"spdxElementId"`
	RelationshipType   string `json:"relationshipType"`
	RelatedSPDXElement string `json:"relatedSpdxElement"`
}

// generateSPDXJSON creates an SPDX 2.3 JSON SBOM.
func generateSPDXJSON(input *GeneratorInput, deps []Dependency, g *Generator) (string, error) {
	doc := buildSPDXDocument(input, deps, g)

	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal SPDX JSON: %w", err)
	}

	return string(data), nil
}

// buildSPDXDocument constructs an SPDX document structure.
func buildSPDXDocument(input *GeneratorInput, deps []Dependency, g *Generator) *SPDXDocument {
	documentID := uuid.New().String()
	repoName := input.RepoName
	if input.OrgName != "" {
		repoName = input.OrgName + "/" + input.RepoName
	}

	// Create root package for the repo
	rootSPDXID := "SPDXRef-Package-root"
	packages := []SPDXPackage{
		{
			SPDXID:               rootSPDXID,
			Name:                 repoName,
			VersionInfo:          input.CommitSHA,
			DownloadLocation:     fmt.Sprintf("https://github.com/%s", repoName),
			FilesAnalyzed:        false,
			LicenseConcluded:     "NOASSERTION",
			CopyrightText:        "NOASSERTION",
			PrimaryPackagePurpose: "APPLICATION",
		},
	}

	relationships := []SPDXRelationship{
		{
			SPDXElementID:      "SPDXRef-DOCUMENT",
			RelationshipType:   "DESCRIBES",
			RelatedSPDXElement: rootSPDXID,
		},
	}

	documentDescribes := []string{rootSPDXID}

	// Create packages for each dependency
	for i, dep := range deps {
		spdxID := fmt.Sprintf("SPDXRef-Package-%d", i+1)

		pkg := SPDXPackage{
			SPDXID:           spdxID,
			Name:             dep.Name,
			VersionInfo:      dep.Version,
			DownloadLocation: "NOASSERTION",
			FilesAnalyzed:    false,
			LicenseConcluded: "NOASSERTION",
			CopyrightText:    "NOASSERTION",
		}

		if dep.License != "" {
			pkg.LicenseConcluded = dep.License
			pkg.LicenseDeclared = dep.License
		}

		if dep.PURL != "" {
			pkg.ExternalRefs = []SPDXExternalRef{
				{
					ReferenceCategory: "PACKAGE-MANAGER",
					ReferenceType:     "purl",
					ReferenceLocator:  dep.PURL,
				},
			}
		}

		// Add checksum based on name+version
		checksum := sha256.Sum256([]byte(dep.Name + "@" + dep.Version))
		pkg.Checksums = []SPDXChecksum{
			{
				Algorithm:     "SHA256",
				ChecksumValue: hex.EncodeToString(checksum[:]),
			},
		}

		packages = append(packages, pkg)

		// Add DEPENDS_ON relationship from root to dependency
		if dep.Direct {
			relationships = append(relationships, SPDXRelationship{
				SPDXElementID:      rootSPDXID,
				RelationshipType:   "DEPENDS_ON",
				RelatedSPDXElement: spdxID,
			})
		}
	}

	return &SPDXDocument{
		SPDXID:            "SPDXRef-DOCUMENT",
		SPDXVersion:       "SPDX-2.3",
		Name:              fmt.Sprintf("SBOM for %s", repoName),
		DataLicense:       "CC0-1.0",
		DocumentNamespace: fmt.Sprintf("https://buildguard.io/spdx/%s/%s", strings.ReplaceAll(repoName, "/", "-"), documentID),
		CreationInfo: SPDXCreationInfo{
			Created: time.Now().UTC().Format(time.RFC3339),
			Creators: []string{
				fmt.Sprintf("Tool: %s-%s", g.ToolName, g.ToolVersion),
				"Organization: Build-Guard",
			},
			LicenseListVersion: "3.19",
		},
		DocumentDescribes:     documentDescribes,
		Packages:              packages,
		Relationships:         relationships,
		ExternalDocumentRefs:  []interface{}{},
		HasExtractedLicensing: []interface{}{},
	}
}
