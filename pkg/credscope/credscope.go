// Package credscope exposes stable foundations for embedding CredScope.
package credscope

import (
	"context"

	"github.com/Bavlik/CredScope/internal/analysis"
	"github.com/Bavlik/CredScope/internal/config"
	"github.com/Bavlik/CredScope/internal/discovery"
	"github.com/Bavlik/CredScope/internal/domain"
	"github.com/Bavlik/CredScope/internal/ingest"
)

const (
	SchemaVersion = domain.SchemaVersion
	ScoringPolicy = domain.ScoringPolicy
)

type (
	Config             = config.Config
	Finding            = domain.Finding
	CredentialIdentity = domain.CredentialIdentity
	Report             = domain.Report
	DiscoveredFile     = discovery.File
	ParsedRepository   = domain.ParsedRepository
	Workflow           = domain.Workflow
	ComposeProject     = domain.ComposeProject
	AnalysisResult     = domain.AnalysisResult
	AnalysisOptions    = analysis.Options
)

func DefaultConfig() Config { return config.Default() }

// Discover returns supported inputs without parsing or executing them.
func Discover(repositoryRoot string, cfg Config) ([]DiscoveredFile, error) {
	finder, err := discovery.New(repositoryRoot, discovery.Options{
		Includes: cfg.Scan.Include,
		Excludes: cfg.Scan.Exclude,
	})
	if err != nil {
		return nil, err
	}
	return finder.Find()
}

// ParseRepository imports scanner findings and parses supported YAML inputs.
// It performs no graph construction, scoring, remediation, or reporting.
func ParseRepository(ctx context.Context, repositoryRoot string, cfg Config, gitleaksReport string) (ParsedRepository, error) {
	return ingest.Repository(ctx, repositoryRoot, cfg, gitleaksReport)
}

// Analyze builds deterministic graph, rule, score, confidence, and remediation
// models. It performs no reporting, network access, or repository execution.
func Analyze(ctx context.Context, parsed ParsedRepository, options AnalysisOptions) (AnalysisResult, error) {
	return analysis.Analyze(ctx, parsed, options)
}
