package jsonreport

import (
	"sort"
	"strconv"
	"strings"

	"github.com/credscope/credscope/internal/domain"
)

// compactCredentials keeps schema v1 while avoiding repeated path prefixes and
// edge evidence already represented by the graph and matched-rule evidence.
// One shortest deterministic path is retained for every reachable endpoint.
func compactCredentials(credentials []domain.CredentialAnalysis) []domain.CredentialAnalysis {
	result := make([]domain.CredentialAnalysis, 0, len(credentials))
	for _, source := range credentials {
		item := source
		item.Credential.Fingerprints = uniqueStrings(source.Credential.Fingerprints)
		item.EvidencePaths = representativePaths(source.EvidencePaths)
		pathForNode := make(map[string]string, len(item.EvidencePaths))
		for _, path := range item.EvidencePaths {
			if len(path.Nodes) > 0 {
				pathForNode[path.Nodes[len(path.Nodes)-1].ID] = path.ID
			}
		}
		item.MatchedRules = make([]domain.RuleMatch, len(source.MatchedRules))
		pathsByRule := make(map[string][]string, len(source.MatchedRules))
		for index, match := range source.MatchedRules {
			match.Evidence = uniqueEvidence(match.Evidence)
			match.AffectedNodeIDs = uniqueStrings(match.AffectedNodeIDs)
			match.PathIDs = pathIDsForNodes(match.AffectedNodeIDs, pathForNode)
			pathsByRule[match.RuleID] = match.PathIDs
			item.MatchedRules[index] = match
		}
		item.Contributions = make([]domain.ScoreContribution, len(source.Contributions))
		for index, contribution := range source.Contributions {
			contribution.Evidence = uniqueEvidence(contribution.Evidence)
			contribution.Adjustments = append([]domain.ScoreAdjustment{}, contribution.Adjustments...)
			item.Contributions[index] = contribution
		}
		item.Remediations = make([]domain.RemediationResult, len(source.Remediations))
		for index, remediation := range source.Remediations {
			remediation.TriggeringRuleIDs = uniqueStrings(remediation.TriggeringRuleIDs)
			var pathIDs []string
			for _, ruleID := range remediation.TriggeringRuleIDs {
				pathIDs = append(pathIDs, pathsByRule[ruleID]...)
			}
			remediation.EvidencePathIDs = uniqueStrings(pathIDs)
			remediation.AffectedLocations = uniqueLocations(remediation.AffectedLocations)
			item.Remediations[index] = remediation
		}
		item.Warnings = uniqueStrings(source.Warnings)
		item.RemediationIDs = uniqueStrings(source.RemediationIDs)
		result = append(result, item)
	}
	return result
}

func representativePaths(paths []domain.EvidencePath) []domain.EvidencePath {
	best := make(map[string]domain.EvidencePath)
	for _, source := range paths {
		if len(source.Nodes) < 2 {
			continue
		}
		endpoint := source.Nodes[len(source.Nodes)-1].ID
		path := source
		path.Nodes = append([]domain.PathNode{}, source.Nodes...)
		path.Edges = make([]domain.PathEdge, len(source.Edges))
		for index, edge := range source.Edges {
			edge.Evidence = nil // graph.edges and rule evidence are canonical in schema v1
			path.Edges[index] = edge
		}
		current, exists := best[endpoint]
		if !exists || len(path.Edges) < len(current.Edges) || (len(path.Edges) == len(current.Edges) && path.ID < current.ID) {
			best[endpoint] = path
		}
	}
	result := make([]domain.EvidencePath, 0, len(best))
	for _, path := range best {
		result = append(result, path)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result
}

func pathIDsForNodes(nodeIDs []string, pathForNode map[string]string) []string {
	result := make([]string, 0, len(nodeIDs))
	for _, nodeID := range nodeIDs {
		if pathID := pathForNode[nodeID]; pathID != "" {
			result = append(result, pathID)
		}
	}
	return uniqueStrings(result)
}

func uniqueEvidence(items []domain.Evidence) []domain.Evidence {
	byKey := make(map[string]domain.Evidence, len(items))
	for _, item := range items {
		key := strings.Join([]string{item.RuleID, item.Type, item.Description, item.Location.Path, strconv.Itoa(item.Location.Line), strconv.Itoa(item.Location.Column), item.Field, item.Source, string(item.Confidence)}, "\x00")
		byKey[key] = item
	}
	keys := make([]string, 0, len(byKey))
	for key := range byKey {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]domain.Evidence, 0, len(keys))
	for _, key := range keys {
		result = append(result, byKey[key])
	}
	return result
}

func uniqueStrings(items []string) []string {
	set := make(map[string]struct{}, len(items))
	for _, item := range items {
		if item != "" {
			set[item] = struct{}{}
		}
	}
	result := make([]string, 0, len(set))
	for item := range set {
		result = append(result, item)
	}
	sort.Strings(result)
	return result
}

func uniqueLocations(items []domain.Location) []domain.Location {
	byKey := make(map[string]domain.Location, len(items))
	for _, item := range items {
		key := item.Path + "\x00" + strconv.Itoa(item.Line) + "\x00" + strconv.Itoa(item.Column)
		byKey[key] = item
	}
	keys := make([]string, 0, len(byKey))
	for key := range byKey {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]domain.Location, 0, len(keys))
	for _, key := range keys {
		result = append(result, byKey[key])
	}
	return result
}
