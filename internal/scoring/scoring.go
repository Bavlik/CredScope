// Package scoring implements deterministic scoring policy v1.
package scoring

import (
	"sort"
	"strconv"
	"strings"

	"github.com/credscope/credscope/internal/domain"
	"github.com/credscope/credscope/internal/rules"
)

const PolicyVersion = "v1"

type Result struct {
	Score          int
	Severity       domain.Severity
	Contributions  []domain.ScoreContribution
	Confidence     domain.ConfidenceSummary
	Warnings       []string
	RemediationIDs []string
}

// ConfidenceMultiplier returns the policy-v1 integer percentage.
func ConfidenceMultiplier(confidence domain.Confidence) int {
	switch confidence {
	case domain.ConfidenceConfirmed:
		return 100
	case domain.ConfidenceHigh:
		return 90
	case domain.ConfidenceMedium:
		return 70
	case domain.ConfidenceLow:
		return 40
	default:
		return 0
	}
}

// SeverityForScore applies the documented inclusive policy-v1 boundaries.
func SeverityForScore(score int) domain.Severity {
	switch {
	case score >= 80:
		return domain.SeverityCritical
	case score >= 60:
		return domain.SeverityHigh
	case score >= 40:
		return domain.SeverityMedium
	case score >= 20:
		return domain.SeverityLow
	default:
		return domain.SeverityInformational
	}
}

// Calculate scores each rule at most once. An affected-component adjustment of
// 10% per additional node is bounded at 30%; both adjustment and confidence
// multiplication use integer half-up rounding.
func Calculate(matches []domain.RuleMatch) Result {
	catalog := make(map[string]rules.Rule)
	for _, item := range rules.Catalog() {
		catalog[item.ID] = item
	}
	byRule := make(map[string]domain.RuleMatch, len(matches))
	for _, match := range matches {
		if current, ok := byRule[match.RuleID]; ok {
			current.AffectedNodeIDs = uniqueStrings(append(current.AffectedNodeIDs, match.AffectedNodeIDs...))
			current.PathIDs = uniqueStrings(append(current.PathIDs, match.PathIDs...))
			current.Evidence = uniqueEvidence(append(current.Evidence, match.Evidence...))
			if ConfidenceMultiplier(match.Confidence) > ConfidenceMultiplier(current.Confidence) {
				current.Confidence = match.Confidence
			}
			byRule[match.RuleID] = current
		} else {
			match.AffectedNodeIDs = uniqueStrings(match.AffectedNodeIDs)
			match.PathIDs = uniqueStrings(match.PathIDs)
			match.Evidence = uniqueEvidence(match.Evidence)
			byRule[match.RuleID] = match
		}
	}
	ids := make([]string, 0, len(byRule))
	for id := range byRule {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	result := Result{}
	remediations := make(map[string]struct{})
	weightedConfidence, confidenceWeight := 0, 0
	for _, id := range ids {
		match := byRule[id]
		item, ok := catalog[id]
		if !ok || !item.Enabled {
			continue
		}
		increment := len(uniqueStrings(match.AffectedNodeIDs)) - 1
		if increment < 0 {
			increment = 0
		}
		if increment > 3 {
			increment = 3
		}
		adjustmentPercent := increment * 10
		adjusted := roundDiv(item.Weight*(100+adjustmentPercent), 100)
		multiplier := ConfidenceMultiplier(match.Confidence)
		contribution := roundDiv(adjusted*multiplier, 100)
		adjustments := []domain.ScoreAdjustment{}
		if adjustmentPercent > 0 {
			adjustments = append(adjustments, domain.ScoreAdjustment{Kind: "affected_components", Percent: adjustmentPercent, Description: "Bounded 10% increase for each additional independently affected node (maximum 30%)."})
		}
		result.Contributions = append(result.Contributions, domain.ScoreContribution{RuleID: id, Description: item.Title, BaseWeight: item.Weight, Adjustments: adjustments, AdjustedWeight: adjusted, ConfidenceMultiplier: multiplier, FinalContribution: contribution, Confidence: match.Confidence, Evidence: match.Evidence})
		result.Score += contribution
		addConfidence(&result.Confidence, match.Confidence)
		if contribution > 0 {
			weightedConfidence += multiplier * contribution
			confidenceWeight += contribution
		}
		if item.Weight == 0 {
			result.Warnings = append(result.Warnings, id+": "+item.Title)
		}
		if match.RemediationID != "" {
			remediations[match.RemediationID] = struct{}{}
		}
	}
	if result.Score > 100 {
		result.Score = 100
	}
	result.Severity = SeverityForScore(result.Score)
	result.Confidence.Overall = overallConfidence(weightedConfidence, confidenceWeight)
	for id := range remediations {
		result.RemediationIDs = append(result.RemediationIDs, id)
	}
	sort.Strings(result.RemediationIDs)
	sort.Strings(result.Warnings)
	return result
}

func roundDiv(value, divisor int) int {
	if value <= 0 || divisor <= 0 {
		return 0
	}
	return (value + divisor/2) / divisor
}

func addConfidence(summary *domain.ConfidenceSummary, confidence domain.Confidence) {
	switch confidence {
	case domain.ConfidenceConfirmed:
		summary.Confirmed++
	case domain.ConfidenceHigh:
		summary.High++
	case domain.ConfidenceMedium:
		summary.Medium++
	case domain.ConfidenceLow:
		summary.Low++
	default:
		summary.Unknown++
	}
}

func overallConfidence(weighted, weight int) domain.Confidence {
	if weight == 0 {
		return domain.ConfidenceUnknown
	}
	average := roundDiv(weighted, weight)
	switch {
	case average >= 95:
		return domain.ConfidenceConfirmed
	case average >= 80:
		return domain.ConfidenceHigh
	case average >= 55:
		return domain.ConfidenceMedium
	default:
		return domain.ConfidenceLow
	}
}

func uniqueStrings(items []string) []string {
	seen := make(map[string]struct{}, len(items))
	for _, item := range items {
		seen[item] = struct{}{}
	}
	result := make([]string, 0, len(seen))
	for item := range seen {
		result = append(result, item)
	}
	sort.Strings(result)
	return result
}

func uniqueEvidence(items []domain.Evidence) []domain.Evidence {
	seen := make(map[string]domain.Evidence, len(items))
	for _, item := range items {
		key := strings.Join([]string{item.Type, item.RuleID, item.Description, item.Location.Path, strconv.Itoa(item.Location.Line), strconv.Itoa(item.Location.Column), item.Field, item.Source, string(item.Confidence)}, "\x00")
		seen[key] = item
	}
	keys := make([]string, 0, len(seen))
	for key := range seen {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]domain.Evidence, 0, len(keys))
	for _, key := range keys {
		result = append(result, seen[key])
	}
	return result
}
