// Package analysis orchestrates graph construction, rule matching, scoring,
// and remediation without depending on any presentation format.
package analysis

import (
	"context"
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/Bavlik/CredScope/internal/domain"
	"github.com/Bavlik/CredScope/internal/graph"
	profilepkg "github.com/Bavlik/CredScope/internal/profile"
	"github.com/Bavlik/CredScope/internal/remediation"
	"github.com/Bavlik/CredScope/internal/rules"
	"github.com/Bavlik/CredScope/internal/scoring"
)

type IgnoreDirective struct{ Value, Reason string }

type Options struct {
	MaxTraversalDepth int
	MaxEvidencePaths  int
	MaxTotalPaths     int
	DisabledRules     map[string]bool
	Profile           domain.Profile
	Classifications   map[string]domain.Classification
	IgnorePaths       []IgnoreDirective
	IgnoreVariables   []IgnoreDirective
	IgnoreFindings    []IgnoreDirective
	IgnoreRules       []IgnoreDirective
}

const DefaultMaxTotalEvidencePaths = 50000

func Analyze(ctx context.Context, parsed domain.ParsedRepository, options Options) (domain.AnalysisResult, error) {
	if err := ctx.Err(); err != nil {
		return domain.AnalysisResult{}, err
	}
	parsed, preIgnored := applyRepositoryIgnores(parsed, options)
	selection := profilepkg.Select(options.Profile, parsed)
	ignoredVariables := make(map[string]domain.IgnoredItem)
	for _, item := range options.IgnoreVariables {
		ignoredVariables[strings.ToUpper(item.Value)] = domain.IgnoredItem{Kind: "variable", Target: strings.ToUpper(item.Value), Reason: item.Reason}
	}
	built := graph.BuildWithOptions(parsed, graph.BuildOptions{Classifications: options.Classifications, IgnoredVariables: ignoredVariables})
	if built.LimitExceeded {
		return domain.AnalysisResult{}, fmt.Errorf("analysis graph exceeded the safety limit of %d nodes or %d edges", graph.DefaultMaxGraphNodes, graph.DefaultMaxGraphEdges)
	}
	result := domain.AnalysisResult{PolicyVersion: scoring.PolicyVersion, RuleCatalogVersion: rules.CatalogVersion, Graph: built.Graph, Warnings: append([]string{}, built.Warnings...), Credentials: []domain.CredentialAnalysis{}, Profile: selection, IgnoredItems: append(preIgnored, built.Ignored...)}
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
		if len(options.IgnoreRules) > 0 {
			ignoredRules := make(map[string]IgnoreDirective)
			for _, item := range options.IgnoreRules {
				ignoredRules[strings.ToUpper(item.Value)] = item
			}
			filtered := matches[:0]
			for _, match := range matches {
				if directive, ok := ignoredRules[match.RuleID]; ok {
					result.IgnoredItems = appendOrIncrement(result.IgnoredItems, domain.IgnoredItem{Kind: "rule", Target: match.RuleID, Reason: directive.Reason, Count: 1})
					continue
				}
				filtered = append(filtered, match)
			}
			matches = filtered
		}
		score := scoring.CalculateForProfile(matches, selection, credential.ExpectedSecret)
		remediations := remediation.Generate(credential, matches)
		if !credential.RotationApplicable {
			remediations = removeRotation(remediations)
		}
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
	sort.Slice(result.IgnoredItems, func(i, j int) bool {
		if result.IgnoredItems[i].Kind != result.IgnoredItems[j].Kind {
			return result.IgnoredItems[i].Kind < result.IgnoredItems[j].Kind
		}
		return result.IgnoredItems[i].Target < result.IgnoredItems[j].Target
	})
	for _, item := range result.IgnoredItems {
		result.IgnoredCount += item.Count
	}
	return result, nil
}

func removeRotation(items []domain.RemediationResult) []domain.RemediationResult {
	result := items[:0]
	for _, item := range items {
		if item.ID != "REM001" {
			result = append(result, item)
		}
	}
	return result
}

func applyRepositoryIgnores(parsed domain.ParsedRepository, options Options) (domain.ParsedRepository, []domain.IgnoredItem) {
	var ignored []domain.IgnoredItem
	pathReason := func(value string) (string, bool) {
		for _, item := range options.IgnorePaths {
			if matchPath(item.Value, value) {
				return item.Reason, true
			}
		}
		return "", false
	}
	workflows := parsed.Workflows[:0]
	for _, item := range parsed.Workflows {
		if reason, ok := pathReason(item.File); ok {
			ignored = appendOrIncrement(ignored, domain.IgnoredItem{Kind: "path", Target: item.File, Reason: reason, Count: 1})
		} else {
			workflows = append(workflows, item)
		}
	}
	parsed.Workflows = workflows
	compose := parsed.Compose[:0]
	for _, item := range parsed.Compose {
		if reason, ok := pathReason(item.File); ok {
			ignored = appendOrIncrement(ignored, domain.IgnoredItem{Kind: "path", Target: item.File, Reason: reason, Count: 1})
		} else {
			compose = append(compose, item)
		}
	}
	parsed.Compose = compose
	findingIDs := make(map[string]IgnoreDirective)
	for _, item := range options.IgnoreFindings {
		findingIDs[item.Value] = item
	}
	findings := parsed.Findings[:0]
	for _, item := range parsed.Findings {
		if directive, ok := findingIDs[item.ID]; ok {
			ignored = appendOrIncrement(ignored, domain.IgnoredItem{Kind: "finding", Target: item.ID, Reason: directive.Reason, Count: 1})
			continue
		}
		if directive, ok := findingIDs[item.RuleID]; ok {
			ignored = appendOrIncrement(ignored, domain.IgnoredItem{Kind: "finding", Target: item.RuleID, Reason: directive.Reason, Count: 1})
			continue
		}
		if reason, ok := pathReason(item.Location.Path); ok {
			ignored = appendOrIncrement(ignored, domain.IgnoredItem{Kind: "path", Target: item.Location.Path, Reason: reason, Count: 1})
			continue
		}
		findings = append(findings, item)
	}
	parsed.Findings = findings
	return parsed, ignored
}

func matchPath(pattern, value string) bool {
	pattern, value = strings.ReplaceAll(pattern, "\\", "/"), strings.ReplaceAll(value, "\\", "/")
	if strings.HasSuffix(pattern, "/**") {
		prefix := strings.TrimSuffix(pattern, "**")
		return strings.HasPrefix(value, prefix)
	}
	matched, _ := path.Match(pattern, value)
	return matched
}

func appendOrIncrement(items []domain.IgnoredItem, value domain.IgnoredItem) []domain.IgnoredItem {
	for index := range items {
		if items[index].Kind == value.Kind && items[index].Target == value.Target && items[index].Reason == value.Reason {
			items[index].Count += value.Count
			return items
		}
	}
	return append(items, value)
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
