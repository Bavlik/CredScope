// Package reporters defines the presentation boundary shared by all report
// formats. Reporters receive fully analyzed, secret-safe models and only write
// to the supplied writer.
package reporters

import (
	"io"
	"sort"
	"time"

	"github.com/Bavlik/CredScope/internal/domain"
)

const SchemaVersion = "2"

type Tool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Commit  string `json:"commit,omitempty"`
}

type Scan struct {
	Repository        string                  `json:"repository"`
	StartedAt         time.Time               `json:"started_at"`
	CompletedAt       time.Time               `json:"completed_at"`
	FailOn            string                  `json:"fail_on"`
	MinimumScore      int                     `json:"minimum_score"`
	Format            string                  `json:"format"`
	ThresholdExceeded bool                    `json:"threshold_exceeded"`
	Includes          []string                `json:"includes,omitempty"`
	Excludes          []string                `json:"excludes,omitempty"`
	DisabledRules     []string                `json:"disabled_rules,omitempty"`
	NoColor           bool                    `json:"no_color"`
	Quiet             bool                    `json:"quiet"`
	Verbose           bool                    `json:"verbose"`
	Profile           domain.ProfileSelection `json:"profile"`
}

type Input struct {
	Tool           Tool
	Scan           Scan
	Analysis       domain.AnalysisResult
	ParserWarnings []domain.ParseWarning
	NonFatalErrors []string
}

type Options struct {
	Verbose bool
	Quiet   bool
	Color   bool
	Pretty  bool
}

type Reporter interface {
	Name() string
	Validate(Options) error
	Render(io.Writer, Input, Options) error
}

type Summary struct {
	CredentialCount   int  `json:"credential_count"`
	Informational     int  `json:"informational"`
	Low               int  `json:"low"`
	Medium            int  `json:"medium"`
	High              int  `json:"high"`
	Critical          int  `json:"critical"`
	HighestScore      int  `json:"highest_score"`
	ThresholdExceeded bool `json:"threshold_exceeded"`
}

func Summarize(input Input) Summary {
	result := Summary{CredentialCount: len(input.Analysis.Credentials), ThresholdExceeded: input.Scan.ThresholdExceeded}
	for _, item := range input.Analysis.Credentials {
		if item.Score > result.HighestScore {
			result.HighestScore = item.Score
		}
		switch item.Severity {
		case domain.SeverityCritical:
			result.Critical++
		case domain.SeverityHigh:
			result.High++
		case domain.SeverityMedium:
			result.Medium++
		case domain.SeverityLow:
			result.Low++
		default:
			result.Informational++
		}
	}
	return result
}

func OrderedCredentials(input Input, applyMinimum bool) []domain.CredentialAnalysis {
	result := make([]domain.CredentialAnalysis, 0, len(input.Analysis.Credentials))
	for _, item := range input.Analysis.Credentials {
		if !applyMinimum || item.Score >= input.Scan.MinimumScore {
			result = append(result, item)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Score != result[j].Score {
			return result[i].Score > result[j].Score
		}
		if SeverityRank(result[i].Severity) != SeverityRank(result[j].Severity) {
			return SeverityRank(result[i].Severity) > SeverityRank(result[j].Severity)
		}
		return result[i].Credential.Label < result[j].Credential.Label
	})
	return result
}

func SeverityRank(value domain.Severity) int {
	switch value {
	case domain.SeverityCritical:
		return 4
	case domain.SeverityHigh:
		return 3
	case domain.SeverityMedium:
		return 2
	case domain.SeverityLow:
		return 1
	default:
		return 0
	}
}

func ThresholdExceeded(result domain.AnalysisResult, failOn string, minimumScore int) bool {
	if failOn == "none" {
		return false
	}
	threshold := map[string]int{"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[failOn]
	for _, item := range result.Credentials {
		if item.Score >= minimumScore && SeverityRank(item.Severity) >= threshold {
			return true
		}
	}
	return false
}
