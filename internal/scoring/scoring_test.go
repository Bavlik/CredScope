package scoring

import (
	"reflect"
	"testing"

	"github.com/credscope/credscope/internal/domain"
)

func TestConfidenceMultipliers(t *testing.T) {
	tests := map[domain.Confidence]int{domain.ConfidenceConfirmed: 100, domain.ConfidenceHigh: 90, domain.ConfidenceMedium: 70, domain.ConfidenceLow: 40, domain.ConfidenceUnknown: 0}
	for confidence, want := range tests {
		if got := ConfidenceMultiplier(confidence); got != want {
			t.Errorf("ConfidenceMultiplier(%q) = %d, want %d", confidence, got, want)
		}
	}
}

func TestSeverityBoundaries(t *testing.T) {
	tests := map[int]domain.Severity{0: domain.SeverityInformational, 19: domain.SeverityInformational, 20: domain.SeverityLow, 39: domain.SeverityLow, 40: domain.SeverityMedium, 59: domain.SeverityMedium, 60: domain.SeverityHigh, 79: domain.SeverityHigh, 80: domain.SeverityCritical, 100: domain.SeverityCritical}
	for score, want := range tests {
		if got := SeverityForScore(score); got != want {
			t.Errorf("SeverityForScore(%d) = %q, want %q", score, got, want)
		}
	}
}

func TestCalculateRoundingAdjustmentDuplicateSuppressionAndCapping(t *testing.T) {
	matches := []domain.RuleMatch{
		{RuleID: "CRD205", Confidence: domain.ConfidenceMedium, AffectedNodeIDs: []string{"a", "b"}, RemediationID: "REM006"},
		{RuleID: "CRD205", Confidence: domain.ConfidenceMedium, AffectedNodeIDs: []string{"a"}, RemediationID: "REM006"},
	}
	result := Calculate(matches)
	reversed := Calculate([]domain.RuleMatch{matches[1], matches[0]})
	if !reflect.DeepEqual(result, reversed) {
		t.Fatalf("duplicate input order changed score:\nfirst %#v\nsecond %#v", result, reversed)
	}
	if len(result.Contributions) != 1 {
		t.Fatalf("contributions = %d, want duplicate rule suppressed", len(result.Contributions))
	}
	contribution := result.Contributions[0]
	// weight 7 + 10% rounds to 8; medium 70% rounds to 6.
	if contribution.AdjustedWeight != 8 || contribution.FinalContribution != 6 {
		t.Fatalf("contribution = %#v", contribution)
	}
	var many []domain.RuleMatch
	for _, id := range []string{"CRD101", "CRD104", "CRD201", "CRD202", "CRD203", "CRD206", "CRD302", "CRD304", "CRD401", "CRD403"} {
		many = append(many, domain.RuleMatch{RuleID: id, Confidence: domain.ConfidenceConfirmed, AffectedNodeIDs: []string{id}, RemediationID: "REM001"})
	}
	capped := Calculate(many)
	if capped.Score != 100 || capped.Severity != domain.SeverityCritical {
		t.Fatalf("capped result = score %d severity %q", capped.Score, capped.Severity)
	}
}

func TestCalculateIsDeterministicAndWarningsDoNotScore(t *testing.T) {
	matches := []domain.RuleMatch{{RuleID: "CRD503", Confidence: domain.ConfidenceUnknown, AffectedNodeIDs: []string{"port"}, RemediationID: "REM020"}, {RuleID: "CRD101", Confidence: domain.ConfidenceConfirmed, AffectedNodeIDs: []string{"finding"}, RemediationID: "REM001"}}
	first := Calculate(matches)
	second := Calculate(matches)
	if !reflect.DeepEqual(first, second) {
		t.Fatal("scoring was not deterministic")
	}
	if first.Score != 15 || len(first.Warnings) != 1 || first.Confidence.Unknown != 1 {
		t.Fatalf("result = %#v", first)
	}
}
