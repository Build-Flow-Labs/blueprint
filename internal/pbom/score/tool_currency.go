package score

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/build-flow-labs/blueprint/pbom/schema"
)

// knownLatest maps tool names to their latest known major.minor versions.
// Updated periodically. Only tools we can meaningfully version-check are listed.
var knownLatest = map[string]toolVersion{
	"go":     {Major: 1, Minor: 23},
	"node":   {Major: 22, Minor: 0},
	"python": {Major: 3, Minor: 13},
	"java":   {Major: 21, Minor: 0},
	"docker": {Major: 28, Minor: 0},
	"rustc":  {Major: 1, Minor: 84},
	"npm":    {Major: 11, Minor: 0},
	"helm":   {Major: 3, Minor: 17},
	"dotnet": {Major: 9, Minor: 0},
	"gradle": {Major: 8, Minor: 12},
	"mvn":    {Major: 3, Minor: 9},
}

type toolVersion struct {
	Major int
	Minor int
}

var versionRe = regexp.MustCompile(`(\d+)\.(\d+)`)

func parseVersion(s string) (toolVersion, bool) {
	m := versionRe.FindStringSubmatch(s)
	if m == nil {
		return toolVersion{}, false
	}
	major, _ := strconv.Atoi(m[1])
	minor, _ := strconv.Atoi(m[2])
	return toolVersion{Major: major, Minor: minor}, true
}

// scoreToolCurrency grades how current the build tools are.
//
// Scoring:
//   - Start at 100
//   - For each recognized tool: deduct points based on version lag
//   - 1 minor behind: -5 per tool
//   - 1 major behind: -15 per tool
//   - 2+ major behind: -25 per tool
//   - No tool_versions at all: 50 (incomplete data)
func scoreToolCurrency(pbom *schema.PBOM) schema.AxisScore {
	if len(pbom.Build.ToolVersions) == 0 {
		return schema.AxisScore{
			Grade:    "D",
			Score:    50,
			Findings: []string{"no tool versions detected"},
		}
	}

	points := 100
	var findings []string
	checked := 0

	for tool, verStr := range pbom.Build.ToolVersions {
		latest, known := knownLatest[strings.ToLower(tool)]
		if !known {
			continue
		}

		current, ok := parseVersion(verStr)
		if !ok {
			findings = append(findings, fmt.Sprintf("%s: unable to parse version %q", tool, verStr))
			continue
		}

		checked++

		majorDiff := latest.Major - current.Major
		minorDiff := latest.Minor - current.Minor

		switch {
		case majorDiff >= 2:
			points -= 25
			findings = append(findings, fmt.Sprintf("%s %d.%d is 2+ majors behind latest %d.%d",
				tool, current.Major, current.Minor, latest.Major, latest.Minor))
		case majorDiff == 1:
			points -= 15
			findings = append(findings, fmt.Sprintf("%s %d.%d is 1 major behind latest %d.%d",
				tool, current.Major, current.Minor, latest.Major, latest.Minor))
		case majorDiff == 0 && minorDiff > 0:
			points -= 5
			findings = append(findings, fmt.Sprintf("%s %d.%d is %d minor(s) behind latest %d.%d",
				tool, current.Major, current.Minor, minorDiff, latest.Major, latest.Minor))
		}
	}

	if checked == 0 {
		return schema.AxisScore{
			Grade:    "C",
			Score:    60,
			Findings: append(findings, "no recognized tools to check"),
		}
	}

	if points < 0 {
		points = 0
	}

	return schema.AxisScore{
		Grade:    numericToGrade(points),
		Score:    points,
		Findings: findings,
	}
}
