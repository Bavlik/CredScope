package html

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/credscope/credscope/internal/domain"
	"github.com/credscope/credscope/internal/reporters"
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
	if got := fmt.Sprintf("%x", sha256.Sum256(first.Bytes())); got != "6257b0d48215614f5d94ce31b8fc96fae135684176021ca01d0352c498dfdc88" {
		t.Fatalf("HTML golden hash = %s", got)
	}
	output := first.String()
	for _, expected := range []string{"<!doctype html>", "Content-Security-Policy", "<header>", "<main>", "<footer>", "Rotate safely", "Static reachability graph", "&lt;script&gt;"} {
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

func htmlInput() reporters.Input {
	return reporters.Input{Tool: reporters.Tool{Name: "CredScope", Version: "test"}, Scan: reporters.Scan{Repository: `demo<script></style>&"`, StartedAt: time.Unix(1, 0), CompletedAt: time.Unix(2, 0)}, Analysis: domain.AnalysisResult{PolicyVersion: "v1", RuleCatalogVersion: "v1", Graph: domain.Graph{Nodes: []domain.Node{{ID: "node:safe", Type: domain.NodeCredential, Label: `<script>alert(1)</script>`}}, Edges: []domain.Edge{}}, Credentials: []domain.CredentialAnalysis{{Credential: domain.CredentialSubject{Label: `<script>TOKEN</script>`}, Score: 80, Severity: domain.SeverityCritical, Confidence: domain.ConfidenceSummary{Overall: domain.ConfidenceHigh}, Contributions: []domain.ScoreContribution{{RuleID: "CRD101", Description: "Credential imported", FinalContribution: 15}}, Remediations: []domain.RemediationResult{{ID: "REM001", Title: "Rotate safely", Why: "Exposure", SuggestedAction: "Rotate safely", Priority: 1}}, Warnings: []string{"Unknown runtime"}}}}}
}
