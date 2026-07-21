package remediation

import (
	"reflect"
	"testing"

	"github.com/Bavlik/CredScope/internal/domain"
)

func TestGenerateDeduplicatesAggregatesAndOrders(t *testing.T) {
	matches := []domain.RuleMatch{
		{RuleID: "CRD306", RemediationID: "REM007", Confidence: domain.ConfidenceConfirmed, PathIDs: []string{"p2"}, Evidence: []domain.Evidence{{Location: domain.Location{Path: "compose.yml", Line: 8}}}},
		{RuleID: "CRD103", RemediationID: "REM007", Confidence: domain.ConfidenceHigh, PathIDs: []string{"p1", "p2"}, Evidence: []domain.Evidence{{Location: domain.Location{Path: ".github/workflows/deploy.yml", Line: 12}}}},
		{RuleID: "CRD304", RemediationID: "REM014", Confidence: domain.ConfidenceConfirmed, PathIDs: []string{"p3"}},
	}
	got := Generate(domain.CredentialSubject{Label: "DEMO_TOKEN"}, matches)
	if len(got) != 2 {
		t.Fatalf("recommendations = %d", len(got))
	}
	if got[0].ID != "REM014" || got[1].ID != "REM007" {
		t.Fatalf("ordering = %s, %s", got[0].ID, got[1].ID)
	}
	if !reflect.DeepEqual(got[1].TriggeringRuleIDs, []string{"CRD103", "CRD306"}) || !reflect.DeepEqual(got[1].EvidencePathIDs, []string{"p1", "p2"}) {
		t.Fatalf("aggregation = %#v", got[1])
	}
}

func TestGenerateAddsOIDCOnlyForAWSWorkflowCredential(t *testing.T) {
	match := domain.RuleMatch{RuleID: "CRD102", RemediationID: "REM007", Confidence: domain.ConfidenceConfirmed}
	aws := Generate(domain.CredentialSubject{Label: "EXAMPLE_AWS_DEPLOY_KEY"}, []domain.RuleMatch{match})
	other := Generate(domain.CredentialSubject{Label: "DEMO_TOKEN"}, []domain.RuleMatch{match})
	if !hasID(aws, "REM002") || hasID(other, "REM002") {
		t.Fatalf("OIDC recommendations aws=%#v other=%#v", aws, other)
	}
}

func hasID(items []domain.RemediationResult, id string) bool {
	for _, item := range items {
		if item.ID == id {
			return true
		}
	}
	return false
}
