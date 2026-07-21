// Package scoring implements deterministic scoring policy v2.
package scoring

import (
	"sort"
	"strconv"
	"strings"

	"github.com/Bavlik/CredScope/internal/domain"
	"github.com/Bavlik/CredScope/internal/rules"
)

const PolicyVersion = "v2"

type Result struct {
	Score          int
	Severity       domain.Severity
	Contributions  []domain.ScoreContribution
	Confidence     domain.ConfidenceSummary
	Warnings       []string
	RemediationIDs []string
}

// ConfidenceWeight maps evidence confidence to an integer used only when
// summarizing confidence. It never changes risk points.
func ConfidenceWeight(confidence domain.Confidence) int {
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

// SeverityForScore applies the documented inclusive policy-v2 boundaries.
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
// 10% per additional node is bounded at 30%. Risk and evidence confidence are
// calculated independently with deterministic integer half-up rounding.
func Calculate(matches []domain.RuleMatch) Result {
	return CalculateForProfile(matches, domain.ProfileSelection{Selected: domain.ProfileAuto}, true)
}

// CalculateForProfile keeps evidence confidence independent from risk points.
// Profile adjustments affect risk only and are recorded explicitly.
func CalculateForProfile(matches []domain.RuleMatch, profile domain.ProfileSelection, expectedSecret bool) Result {
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
			if ConfidenceWeight(match.Confidence) > ConfidenceWeight(current.Confidence) {
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
		confidenceWeightPercent := ConfidenceWeight(match.Confidence)
		profilePercent := profileAdjustment(id, profile.Selected)
		profileChanged := profilePercent != 0
		if profileChanged {
			adjusted = roundDiv(adjusted*(100+profilePercent), 100)
		}
		adjustments := []domain.ScoreAdjustment{}
		if adjustmentPercent > 0 {
			adjustments = append(adjustments, domain.ScoreAdjustment{Kind: "affected_components", Percent: adjustmentPercent, Description: "Bounded 10% increase for each additional independently affected node (maximum 30%).", RiskOrConfidence: "risk"})
		}
		if profileChanged {
			adjustments = append(adjustments, domain.ScoreAdjustment{Kind: "environment_profile", Percent: profilePercent, Description: "Selected environment profile changed this risk contribution.", RiskOrConfidence: "risk", ProfileChanged: true})
		}
		if !expectedSecret {
			adjusted = 0
			adjustments = append(adjustments, domain.ScoreAdjustment{Kind: "classification_gate", Percent: -100, Description: "The item is not expected to be secret, so credential-exposure risk points are not applied.", RiskOrConfidence: "risk"})
		}
		contribution := adjusted
		status := "confirmed"
		if match.Confidence != domain.ConfidenceConfirmed {
			status = "inferred"
		}
		result.Contributions = append(result.Contributions, domain.ScoreContribution{RuleID: id, Description: item.Title, BaseWeight: item.Weight, Adjustments: adjustments, AdjustedWeight: adjusted, ConfidenceWeight: confidenceWeightPercent, FinalContribution: contribution, Confidence: match.Confidence, ConditionStatus: status, RiskOrConfidence: "risk", ProfileChanged: profileChanged, Evidence: match.Evidence})
		result.Score += contribution
		addConfidence(&result.Confidence, match.Confidence)
		evidenceWeight := item.Weight
		if evidenceWeight <= 0 {
			evidenceWeight = 1
		}
		weightedConfidence += confidenceWeightPercent * evidenceWeight
		confidenceWeight += evidenceWeight
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

func profileAdjustment(ruleID string, selected domain.Profile) int {
	switch selected {
	case domain.ProfileLocal:
		if ruleID == "CRD303" {
			return -60
		}
	case domain.ProfileCI:
		if ruleID == "CRD303" {
			return -50
		}
	case domain.ProfileProduction:
		switch ruleID {
		case "CRD303":
			return 30
		case "CRD103", "CRD306", "CRD401", "CRD402", "CRD404":
			return 15
		case "CRD302", "CRD304", "CRD305", "CRD307":
			return 20
		}
	case domain.ProfileAuto:
		if ruleID == "CRD303" {
			return -25
		}
	}
	return 0
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
