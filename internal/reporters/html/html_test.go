package html

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Bavlik/CredScope/internal/domain"
	"github.com/Bavlik/CredScope/internal/reporters"
)

func TestHTMLStandaloneEscapedAccessibleAndDeterministic(t *testing.T) {
	input := htmlInput()
	var first, second bytes.Buffer
	if err := New().Render(&first, input, reporters.Options{}); err != nil {
		t.Fatal(err)
	}
	if err := New().Render(&second, input, reporters.Options{}); err != nil {
		t.Fatal(err)
	}
	if first.String() != second.String() {
		t.Fatal("HTML differs")
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(first.Bytes())); got != "eee3147bf9e74d5b650ff08bb10efb1a6c328c9c1f8bdee62ad3d878db561377" {
		t.Fatalf("HTML golden hash = %s", got)
	}
	output := first.String()
	for _, expected := range []string{"<!doctype html>", "Content-Security-Policy", "<header>", "<main>", "<footer>", "Rotate safely", "Typed graph", "Risk score", "Evidence confidence", "&lt;script&gt;"} {
		if !strings.Contains(output, expected) {
			t.Errorf("missing %q", expected)
		}
	}
	if strings.Contains(output, "https://") || strings.Contains(output, "http://") || strings.Count(output, "</style>") != 1 || strings.Contains(output, "RAW_SECRET_NOT_IN_MODEL") {
		t.Fatal("HTML contains external or injected content")
	}
}

func TestHTMLGraphIsBounded(t *testing.T) {
	input := htmlInput()
	for index := 0; index < maxGraphNodes+5; index++ {
		input.Analysis.Graph.Nodes = append(input.Analysis.Graph.Nodes, domain.Node{ID: string(rune(index + 1000)), Type: domain.NodeFile, Label: "node"})
	}
	var output bytes.Buffer
	if err := New().Render(&output, input, reporters.Options{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "Graph table was bounded") {
		t.Fatal("missing graph bound warning")
	}
}

func TestHTMLEvidenceIsPrioritizedAndBounded(t *testing.T) {
	input := htmlInput()
	credential := &input.Analysis.Credentials[0]
	for index := 0; index < reporters.HTMLEvidencePathLimit+7; index++ {
		id := fmt.Sprintf("permission:%02d", index)
		credential.EvidencePaths = append(credential.EvidencePaths, domain.EvidencePath{ID: fmt.Sprintf("path:%02d", index), Nodes: []domain.PathNode{{ID: "credential", Type: domain.NodeCredential, Label: "TOKEN"}, {ID: id, Type: domain.NodePermission, Label: fmt.Sprintf("permission-%02d", index)}}, Edges: []domain.PathEdge{{ID: "edge:" + id}}})
	}
	var output bytes.Buffer
	if err := New().Render(&output, input, reporters.Options{}); err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(output.String(), "TOKEN → permission-"); got != reporters.HTMLEvidencePathLimit {
		t.Fatalf("HTML paths = %d, want %d", got, reporters.HTMLEvidencePathLimit)
	}
	if !strings.Contains(output.String(), "7 additional relevant paths") {
		t.Fatal("missing accurate omitted count")
	}
}

func htmlInput() reporters.Input {
	return reporters.Input{Tool: reporters.Tool{Name: "CredScope", Version: "test"}, Scan: reporters.Scan{Repository: `demo<script></style>&"`, StartedAt: time.Unix(1, 0), CompletedAt: time.Unix(2, 0)}, Analysis: domain.AnalysisResult{PolicyVersion: "v2", RuleCatalogVersion: "v2", Profile: domain.ProfileSelection{Requested: domain.ProfileAuto, Selected: domain.ProfileAuto, Source: "conservative_fallback", Reason: "test context", Assumptions: []string{"runtime unknown"}}, Graph: domain.Graph{Nodes: []domain.Node{{ID: "node:safe", Type: domain.NodeCredential, Label: `<script>alert(1)</script>`}}, Edges: []domain.Edge{}}, Credentials: []domain.CredentialAnalysis{{Credential: domain.CredentialSubject{Label: `<script>TOKEN</script>`, Classification: domain.ClassificationSecret, ClassificationConfidence: domain.ConfidenceMedium, ClassificationReason: "name heuristic"}, Score: 80, Severity: domain.SeverityCritical, Confidence: domain.ConfidenceSummary{Overall: domain.ConfidenceHigh}, Contributions: []domain.ScoreContribution{{RuleID: "CRD101", Description: "Credential imported", FinalContribution: 15, RiskOrConfidence: "risk"}}, Remediations: []domain.RemediationResult{{ID: "REM001", Title: "Rotate safely", Why: "Exposure", SuggestedAction: "Rotate safely", Priority: 1}}, Warnings: []string{"Unknown runtime"}}}}}
}
