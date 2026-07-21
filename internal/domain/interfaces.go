package domain

import "context"

// FindingSource permits future scanner adapters without coupling the analysis
// engine to a scanner-specific JSON representation.
type FindingSource interface {
	Name() string
	Findings(context.Context) ([]Finding, error)
}

// Analyzer is the extension seam for supported repository input parsers.
type Analyzer interface {
	Name() string
	Analyze(context.Context, string) ([]Node, []Edge, error)
}
