// Package jsonreport renders the stable CredScope report schema version 1.
package jsonreport

import (
	"encoding/json"
	"io"
	"sort"
	"time"

	"github.com/credscope/credscope/internal/domain"
	"github.com/credscope/credscope/internal/reporters"
)

type Reporter struct{}

func New() Reporter                               { return Reporter{} }
func (Reporter) Name() string                     { return "json" }
func (Reporter) Validate(reporters.Options) error { return nil }

type document struct {
	SchemaVersion      string                      `json:"schema_version"`
	Tool               reporters.Tool              `json:"tool"`
	Scan               scan                        `json:"scan"`
	Policies           policies                    `json:"policies"`
	Summary            reporters.Summary           `json:"summary"`
	Credentials        []domain.CredentialAnalysis `json:"credentials"`
	Graph              domain.Graph                `json:"graph"`
	RepositoryWarnings []string                    `json:"repository_warnings"`
	ParserWarnings     []domain.ParseWarning       `json:"parser_warnings"`
	NonFatalErrors     []string                    `json:"non_fatal_errors"`
}

type scan struct {
	Repository        string        `json:"repository"`
	StartedAt         string        `json:"started_at"`
	CompletedAt       string        `json:"completed_at"`
	DurationMillis    int64         `json:"duration_ms"`
	Format            string        `json:"format"`
	FailOn            string        `json:"fail_on"`
	MinimumScore      int           `json:"minimum_score"`
	ThresholdExceeded bool          `json:"threshold_exceeded"`
	Configuration     configuration `json:"configuration"`
}

type configuration struct {
	Includes      []string `json:"include"`
	Excludes      []string `json:"exclude"`
	DisabledRules []string `json:"disabled_rules"`
	NoColor       bool     `json:"no_color"`
	Quiet         bool     `json:"quiet"`
	Verbose       bool     `json:"verbose"`
}

type policies struct {
	ScoringPolicy string `json:"scoring_policy"`
	RuleCatalog   string `json:"rule_catalog"`
}

func (Reporter) Render(writer io.Writer, input reporters.Input, options reporters.Options) error {
	warnings := append([]string{}, input.Analysis.Warnings...)
	sort.Strings(warnings)
	parserWarnings := append([]domain.ParseWarning{}, input.ParserWarnings...)
	sort.Slice(parserWarnings, func(i, j int) bool {
		if parserWarnings[i].Location.Path != parserWarnings[j].Location.Path {
			return parserWarnings[i].Location.Path < parserWarnings[j].Location.Path
		}
		if parserWarnings[i].Location.Line != parserWarnings[j].Location.Line {
			return parserWarnings[i].Location.Line < parserWarnings[j].Location.Line
		}
		return parserWarnings[i].Code < parserWarnings[j].Code
	})
	errors := append([]string{}, input.NonFatalErrors...)
	sort.Strings(errors)
	duration := input.Scan.CompletedAt.Sub(input.Scan.StartedAt)
	if duration < 0 {
		duration = 0
	}
	includes := append([]string{}, input.Scan.Includes...)
	excludes := append([]string{}, input.Scan.Excludes...)
	disabledRules := append([]string{}, input.Scan.DisabledRules...)
	sort.Strings(includes)
	sort.Strings(excludes)
	sort.Strings(disabledRules)
	doc := document{
		SchemaVersion:      reporters.SchemaVersion,
		Tool:               input.Tool,
		Scan:               scan{Repository: input.Scan.Repository, StartedAt: timestamp(input.Scan.StartedAt), CompletedAt: timestamp(input.Scan.CompletedAt), DurationMillis: duration.Milliseconds(), Format: input.Scan.Format, FailOn: input.Scan.FailOn, MinimumScore: input.Scan.MinimumScore, ThresholdExceeded: input.Scan.ThresholdExceeded, Configuration: configuration{Includes: includes, Excludes: excludes, DisabledRules: disabledRules, NoColor: input.Scan.NoColor, Quiet: input.Scan.Quiet, Verbose: input.Scan.Verbose}},
		Policies:           policies{ScoringPolicy: input.Analysis.PolicyVersion, RuleCatalog: input.Analysis.RuleCatalogVersion},
		Summary:            reporters.Summarize(input),
		Credentials:        compactCredentials(reporters.OrderedCredentials(input, false)),
		Graph:              input.Analysis.Graph,
		RepositoryWarnings: warnings,
		ParserWarnings:     parserWarnings,
		NonFatalErrors:     errors,
	}
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(true)
	if options.Pretty {
		encoder.SetIndent("", "  ")
	}
	return encoder.Encode(doc)
}

func timestamp(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}
