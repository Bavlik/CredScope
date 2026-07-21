package terminal

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Bavlik/CredScope/internal/domain"
	"github.com/Bavlik/CredScope/internal/reporters"
)

func TestTerminalDeterministicDetailedAndControlSafe(t *testing.T) {
	input := terminalInput()
	var first, second bytes.Buffer
	options := reporters.Options{Verbose: true, Color: false}
	if err := New().Render(&first, input, options); err != nil {
		t.Fatal(err)
	}
	if err := New().Render(&second, input, options); err != nil {
		t.Fatal(err)
	}
	if first.String() != second.String() {
		t.Fatal("terminal output was not deterministic")
	}
	output := first.String()
	for _, expected := range []string{"CRITICAL - ALPHAevil", "Risk score: 91/100", "Evidence confidence:", "+15 CRD101", "Rotate the credential", "ALPHAevil -> production"} {
		if !strings.Contains(output, expected) {
			t.Errorf("missing %q in:\n%s", expected, output)
		}
	}
	if strings.Contains(output, "\x1b") || strings.Contains(output, "RAW_SECRET_NOT_IN_MODEL") {
		t.Fatal("terminal output contains unsafe material")
	}
}

func TestTerminalColorAndMinimumScore(t *testing.T) {
	input := terminalInput()
	input.Scan.MinimumScore = 99
	var output bytes.Buffer
	if err := New().Render(&output, input, reporters.Options{Color: true}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "\x1b") {
		t.Fatal("filtered credential unexpectedly emitted ANSI")
	}
	if !strings.Contains(output.String(), "No credential met the display minimum score") {
		t.Fatal(output.String())
	}
	input.Scan.MinimumScore = 0
	output.Reset()
	if err := New().Render(&output, input, reporters.Options{Color: true}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "\x1b[1;31m") {
		t.Fatal("expected severity color")
	}
}

func TestTerminalEvidenceIsRelevantAndBounded(t *testing.T) {
	input := terminalInput()
	credential := &input.Analysis.Credentials[0]
	credential.EvidencePaths = nil
	for index := 0; index < 50; index++ {
		id := fmt.Sprintf("permission:%02d", index)
		credential.EvidencePaths = append(credential.EvidencePaths, domain.EvidencePath{ID: fmt.Sprintf("path:%02d", index), Nodes: []domain.PathNode{{ID: "c", Type: domain.NodeCredential, Label: "TOKEN"}, {ID: id, Type: domain.NodePermission, Label: fmt.Sprintf("scope-%02d:write", index)}}, Edges: []domain.PathEdge{{ID: "edge:" + id}}})
	}
	var concise bytes.Buffer
	if err := New().Render(&concise, input, reporters.Options{}); err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(concise.String(), "  - TOKEN -> scope-"); got != reporters.DefaultEvidencePathLimit {
		t.Fatalf("concise paths = %d, want %d", got, reporters.DefaultEvidencePathLimit)
	}
	if !strings.Contains(concise.String(), "40 additional relevant paths omitted") {
		t.Fatal(concise.String())
	}
	var verbose bytes.Buffer
	if err := New().Render(&verbose, input, reporters.Options{Verbose: true}); err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(verbose.String(), "  - TOKEN -> scope-"); got != reporters.VerboseEvidencePathLimit {
		t.Fatalf("verbose paths = %d, want %d", got, reporters.VerboseEvidencePathLimit)
	}
}

func terminalInput() reporters.Input {
	ev := domain.Evidence{Type: "scanner_finding", Location: domain.Location{Path: "demo.yml", Line: 2}, Source: "test", Confidence: domain.ConfidenceConfirmed}
	return reporters.Input{Tool: reporters.Tool{Name: "CredScope", Version: "test"}, Scan: reporters.Scan{Repository: "demo", StartedAt: time.Unix(1, 0), CompletedAt: time.Unix(2, 0), FailOn: "high"}, Analysis: domain.AnalysisResult{PolicyVersion: "v2", RuleCatalogVersion: "v2", Credentials: []domain.CredentialAnalysis{{Credential: domain.CredentialSubject{ID: "credential:safe", Label: "ALPHA\x1b[31mevil"}, Score: 91, Severity: domain.SeverityCritical, Confidence: domain.ConfidenceSummary{Overall: domain.ConfidenceHigh}, Reachable: domain.ReachableCounts{Workflows: 1, Environments: 1}, EvidencePaths: []domain.EvidencePath{{Nodes: []domain.PathNode{{ID: "c", Label: "ALPHA\x1b[31mevil"}, {ID: "e", Type: domain.NodeEnvironment, Label: "production"}}}}, Contributions: []domain.ScoreContribution{{RuleID: "CRD101", Description: "Credential finding imported", BaseWeight: 15, FinalContribution: 15, Confidence: domain.ConfidenceConfirmed, ConfidenceWeight: 100, Evidence: []domain.Evidence{ev}}}, Remediations: []domain.RemediationResult{{ID: "REM001", Title: "Rotate the credential", SuggestedAction: "Rotate safely", Priority: 1}}, Warnings: []string{"Runtime exposure unknown"}}}}}
}
