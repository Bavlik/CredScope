package rules

import (
	"reflect"
	"testing"

	"github.com/credscope/credscope/internal/domain"
	"github.com/credscope/credscope/internal/graph"
)

func TestCatalogV1IsStableAndComplete(t *testing.T) {
	wantIDs := []string{"CRD101", "CRD102", "CRD103", "CRD104", "CRD201", "CRD202", "CRD203", "CRD204", "CRD205", "CRD206", "CRD207", "CRD208", "CRD301", "CRD302", "CRD303", "CRD304", "CRD305", "CRD306", "CRD307", "CRD308", "CRD401", "CRD402", "CRD403", "CRD404", "CRD501", "CRD502", "CRD503"}
	items := Catalog()
	gotIDs := make([]string, len(items))
	for index, item := range items {
		gotIDs[index] = item.ID
		if item.PolicyVersion != "v1" || !item.Enabled || item.RemediationID == "" || len(item.EvidenceRequirements) == 0 {
			t.Fatalf("incomplete catalog entry: %#v", item)
		}
	}
	if !reflect.DeepEqual(gotIDs, wantIDs) {
		t.Fatalf("catalog IDs changed:\ngot  %#v\nwant %#v", gotIDs, wantIDs)
	}
	wantWeights := map[string]int{"CRD101": 15, "CRD104": 16, "CRD202": 20, "CRD304": 20, "CRD501": 0, "CRD502": 0, "CRD503": 0}
	for id, weight := range wantWeights {
		item, ok := ByID(id)
		if !ok || item.Weight != weight {
			t.Fatalf("%s weight = %d, want %d", id, item.Weight, weight)
		}
	}
}

func TestEvaluateMatchesStructuralRulesAndOmitsAbsentRules(t *testing.T) {
	cred := domain.Node{ID: "cred", Type: domain.NodeCredential, Label: "TOKEN", Confidence: domain.ConfidenceConfirmed}
	workflow := domain.Node{ID: "wf", Type: domain.NodeWorkflow, Label: "deploy", Metadata: map[string]string{"missing_explicit_permissions": "false"}, Confidence: domain.ConfidenceConfirmed}
	job := domain.Node{ID: "job", Type: domain.NodeJob, Label: "deploy", Confidence: domain.ConfidenceConfirmed}
	permission := domain.Node{ID: "permission", Type: domain.NodePermission, Label: "contents:write", Metadata: map[string]string{"scope": "contents", "level": "write"}, Confidence: domain.ConfidenceConfirmed}
	environment := domain.Node{ID: "environment", Type: domain.NodeEnvironment, Label: "production", Metadata: map[string]string{"production_like": "true"}, Confidence: domain.ConfidenceMedium}
	service := domain.Node{ID: "service", Type: domain.NodeComposeService, Label: "production-api", Metadata: map[string]string{"privileged": "true", "user_specified": "false", "production_like": "true"}, Confidence: domain.ConfidenceConfirmed}
	port := domain.Node{ID: "port", Type: domain.NodePortExposure, Label: "443", Confidence: domain.ConfidenceMedium}
	input := domain.Graph{Nodes: []domain.Node{cred, workflow, job, permission, environment, service, port}, Edges: []domain.Edge{
		{ID: "e1", From: "cred", To: "wf", Type: domain.EdgeReferencedBy, Confidence: domain.ConfidenceConfirmed},
		{ID: "e2", From: "cred", To: "job", Type: domain.EdgePassedTo, Confidence: domain.ConfidenceConfirmed},
		{ID: "e3", From: "job", To: "permission", Type: domain.EdgeHasPermission, Confidence: domain.ConfidenceConfirmed},
		{ID: "e4", From: "job", To: "environment", Type: domain.EdgeUsesEnvironment, Confidence: domain.ConfidenceMedium},
		{ID: "e5", From: "cred", To: "service", Type: domain.EdgePassedTo, Confidence: domain.ConfidenceConfirmed},
		{ID: "e6", From: "service", To: "port", Type: domain.EdgePublishesPort, Confidence: domain.ConfidenceMedium},
	}}
	matches := Evaluate(input, "cred", graph.Traverse(input, "cred", 12))
	ids := matchIDs(matches)
	for _, want := range []string{"CRD102", "CRD201", "CRD208", "CRD301", "CRD302", "CRD303", "CRD308", "CRD401", "CRD402", "CRD403", "CRD404", "CRD502", "CRD503"} {
		if !contains(ids, want) {
			t.Errorf("expected match %s; got %v", want, ids)
		}
	}
	for _, absent := range []string{"CRD101", "CRD104", "CRD202", "CRD203", "CRD304", "CRD501"} {
		if contains(ids, absent) {
			t.Errorf("unexpected match %s", absent)
		}
	}
}

func TestEvaluateEmptyGraphDoesNotMatch(t *testing.T) {
	if got := Evaluate(domain.Graph{}, "missing", nil); len(got) != 0 {
		t.Fatalf("matches = %#v", got)
	}
}

func matchIDs(matches []domain.RuleMatch) []string {
	result := make([]string, len(matches))
	for index, item := range matches {
		result[index] = item.RuleID
	}
	return result
}

func contains(items []string, value string) bool {
	for _, item := range items {
		if item == value {
			return true
		}
	}
	return false
}
