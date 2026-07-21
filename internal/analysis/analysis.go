// Package analysis orchestrates graph construction, rule matching, scoring,
// and remediation without depending on any presentation format.
package analysis

import (
	"context"
	"fmt"
	"sort"

	"github.com/credscope/credscope/internal/domain"
	"github.com/credscope/credscope/internal/graph"
	"github.com/credscope/credscope/internal/remediation"
	"github.com/credscope/credscope/internal/rules"
	"github.com/credscope/credscope/internal/scoring"
)

type Options struct {
	MaxTraversalDepth int
	MaxEvidencePaths  int
	MaxTotalPaths     int
	DisabledRules     map[string]bool
}

const DefaultMaxTotalEvidencePaths = 50000

func Analyze(ctx context.Context, parsed domain.ParsedRepository, options Options) (domain.AnalysisResult, error) {
	if err := ctx.Err(); err != nil {
		return domain.AnalysisResult{}, err
	}
	built := graph.Build(parsed)
	if built.LimitExceeded {
		return domain.AnalysisResult{}, fmt.Errorf("analysis graph exceeded the safety limit of %d nodes or %d edges", graph.DefaultMaxGraphNodes, graph.DefaultMaxGraphEdges)
	}
	result := domain.AnalysisResult{PolicyVersion: scoring.PolicyVersion, RuleCatalogVersion: rules.CatalogVersion, Graph: built.Graph, Warnings: append([]string{}, built.Warnings...), Credentials: []domain.CredentialAnalysis{}}
	totalPaths := 0
	for _, warning := range parsed.Warnings {
		message := warning.Code + ": " + warning.Message
		if warning.Location.Path != "" {
			message += " (" + warning.Location.Path
			if warning.Location.Line > 0 {
				message += fmt.Sprintf(":%d", warning.Location.Line)
			}
			message += ")"
		}
		result.Warnings = append(result.Warnings, message)
	}
	for _, credential := range built.Credentials {
		if err := ctx.Err(); err != nil {
			return domain.AnalysisResult{}, err
		}
		paths, pathLimitExceeded := graph.TraverseLimited(built.Graph, credential.ID, options.MaxTraversalDepth, options.MaxEvidencePaths)
		if pathLimitExceeded {
			return domain.AnalysisResult{}, fmt.Errorf("credential %s exceeded the safety limit of %d evidence paths", credential.ID, effectivePathLimit(options.MaxEvidencePaths))
		}
		totalPaths += len(paths)
		if totalPaths > effectiveTotalPathLimit(options.MaxTotalPaths) {
			return domain.AnalysisResult{}, fmt.Errorf("repository exceeded the safety limit of %d total evidence paths", effectiveTotalPathLimit(options.MaxTotalPaths))
		}
		matches := rules.Evaluate(built.Graph, credential.ID, paths)
		if len(options.DisabledRules) > 0 {
			filtered := matches[:0]
			for _, match := range matches {
				if !options.DisabledRules[match.RuleID] {
					filtered = append(filtered, match)
				}
			}
			matches = filtered
		}
		score := scoring.Calculate(matches)
		remediations := remediation.Generate(credential, matches)
		remediationIDs := make([]string, 0, len(remediations))
		for _, item := range remediations {
			remediationIDs = append(remediationIDs, item.ID)
		}
		warnings := append([]string{}, score.Warnings...)
		for _, path := range paths {
			if path.Truncated {
				warnings = append(warnings, "Evidence traversal reached the configured maximum depth; deeper structural paths were not included.")
				break
			}
		}
		warnings = uniqueStrings(warnings)
		result.Credentials = append(result.Credentials, domain.CredentialAnalysis{
			Credential: credential, Score: score.Score, Severity: score.Severity,
			PolicyVersion: scoring.PolicyVersion, RuleCatalogVersion: rules.CatalogVersion,
			MatchedRules: matches, Contributions: score.Contributions, Confidence: score.Confidence,
			Reachable: reachableCounts(built.Graph, paths), EvidencePaths: paths, Warnings: warnings,
			RemediationIDs: remediationIDs, Remediations: remediations,
		})
	}
	sort.Slice(result.Credentials, func(i, j int) bool { return result.Credentials[i].Credential.ID < result.Credentials[j].Credential.ID })
	result.Warnings = uniqueStrings(result.Warnings)
	return result, nil
}

func effectivePathLimit(configured int) int {
	if configured > 0 {
		return configured
	}
	return graph.DefaultMaxEvidencePaths
}

func effectiveTotalPathLimit(configured int) int {
	if configured > 0 {
		return configured
	}
	return DefaultMaxTotalEvidencePaths
}

func reachableCounts(input domain.Graph, paths []domain.EvidencePath) domain.ReachableCounts {
	reached := make(map[string]bool)
	for _, path := range paths {
		for _, node := range path.Nodes {
			reached[node.ID] = true
		}
	}
	var result domain.ReachableCounts
	for _, node := range input.Nodes {
		if !reached[node.ID] {
			continue
		}
		switch node.Type {
		case domain.NodeWorkflow:
			result.Workflows++
		case domain.NodeJob:
			result.Jobs++
		case domain.NodeComposeService:
			result.Services++
		case domain.NodePermission:
			result.Permissions++
		case domain.NodeEnvironment:
			result.Environments++
		case domain.NodeExternalAction:
			result.ExternalActions++
		case domain.NodePortExposure:
			result.PublishedPorts++
		case domain.NodeVolumeMount:
			result.VolumeMounts++
		}
	}
	return result
}

func uniqueStrings(items []string) []string {
	seen := make(map[string]struct{}, len(items))
	for _, item := range items {
		if item != "" {
			seen[item] = struct{}{}
		}
	}
	result := make([]string, 0, len(seen))
	for item := range seen {
		result = append(result, item)
	}
	sort.Strings(result)
	return result
}
