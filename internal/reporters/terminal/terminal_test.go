package terminal

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/credscope/credscope/internal/domain"
	"github.com/credscope/credscope/internal/reporters"
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
	for _, expected := range []string{"CRITICAL - ALPHAevil", "Blast-radius score: 91/100", "+15 CRD101", "Rotate the credential", "ALPHAevil -> production"} {
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

func terminalInput() reporters.Input {
	ev := domain.Evidence{Type: "scanner_finding", Location: domain.Location{Path: "demo.yml", Line: 2}, Source: "test", Confidence: domain.ConfidenceConfirmed}
	return reporters.Input{Tool: reporters.Tool{Name: "CredScope", Version: "test"}, Scan: reporters.Scan{Repository: "demo", StartedAt: time.Unix(1, 0), CompletedAt: time.Unix(2, 0), FailOn: "high"}, Analysis: domain.AnalysisResult{PolicyVersion: "v1", RuleCatalogVersion: "v1", Credentials: []domain.CredentialAnalysis{{Credential: domain.CredentialSubject{ID: "credential:safe", Label: "ALPHA\x1b[31mevil"}, Score: 91, Severity: domain.SeverityCritical, Confidence: domain.ConfidenceSummary{Overall: domain.ConfidenceHigh}, Reachable: domain.ReachableCounts{Workflows: 1, Environments: 1}, EvidencePaths: []domain.EvidencePath{{Nodes: []domain.PathNode{{ID: "c", Label: "ALPHA\x1b[31mevil"}, {ID: "e", Type: domain.NodeEnvironment, Label: "production"}}}}, Contributions: []domain.ScoreContribution{{RuleID: "CRD101", Description: "Credential finding imported", BaseWeight: 15, FinalContribution: 15, Confidence: domain.ConfidenceConfirmed, ConfidenceMultiplier: 100, Evidence: []domain.Evidence{ev}}}, Remediations: []domain.RemediationResult{{ID: "REM001", Title: "Rotate the credential", SuggestedAction: "Rotate safely", Priority: 1}}, Warnings: []string{"Runtime exposure unknown"}}}}}
}
