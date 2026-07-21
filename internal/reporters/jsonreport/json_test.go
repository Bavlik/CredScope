package jsonreport

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/credscope/credscope/internal/domain"
	"github.com/credscope/credscope/internal/reporters"
)

func TestJSONSchemaStableValidDeterministicAndEscaped(t *testing.T) {
	input := jsonInput()
	var first, second bytes.Buffer
	options := reporters.Options{Pretty: true}
	if err := New().Render(&first, input, options); err != nil {
		t.Fatal(err)
	}
	if err := New().Render(&second, input, options); err != nil {
		t.Fatal(err)
	}
	if first.String() != second.String() {
		t.Fatal("JSON output differs")
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(first.Bytes())); got != "81f3ab4e86bc9690b9573c798b3b290b66b1d702ceaf724434247702fe412a41" {
		t.Fatalf("JSON golden hash = %s", got)
	}
	var decoded map[string]any
	if err := json.Unmarshal(first.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["schema_version"] != "1" {
		t.Fatalf("schema = %#v", decoded["schema_version"])
	}
	for _, field := range []string{"tool", "scan", "policies", "summary", "credentials", "graph", "repository_warnings", "parser_warnings", "non_fatal_errors"} {
		if _, ok := decoded[field]; !ok {
			t.Errorf("missing field %s", field)
		}
	}
	output := first.String()
	if !strings.Contains(output, `\u003cscript\u003e`) || strings.Contains(output, "RAW_SECRET_NOT_IN_MODEL") {
		t.Fatalf("unsafe JSON: %s", output)
	}
}

func TestJSONEmptyResultIsValid(t *testing.T) {
	input := jsonInput()
	input.Analysis.Credentials = []domain.CredentialAnalysis{}
	input.Analysis.Graph = domain.Graph{Nodes: []domain.Node{}, Edges: []domain.Edge{}}
	var output bytes.Buffer
	if err := New().Render(&output, input, reporters.Options{}); err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Credentials []any        `json:"credentials"`
		Graph       domain.Graph `json:"graph"`
	}
	if err := json.Unmarshal(output.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Credentials == nil || decoded.Graph.Nodes == nil || decoded.Graph.Edges == nil {
		t.Fatalf("empty arrays must be present: %s", output.String())
	}
}

func jsonInput() reporters.Input {
	return reporters.Input{Tool: reporters.Tool{Name: "CredScope", Version: "test"}, Scan: reporters.Scan{Repository: "demo<script>", StartedAt: time.Unix(10, 0), CompletedAt: time.Unix(11, 0), Format: "json", FailOn: "high", ThresholdExceeded: true}, Analysis: domain.AnalysisResult{PolicyVersion: "v1", RuleCatalogVersion: "v1", Graph: domain.Graph{Nodes: []domain.Node{}, Edges: []domain.Edge{}}, Credentials: []domain.CredentialAnalysis{{Credential: domain.CredentialSubject{ID: "credential:safe", Label: "TOKEN", Fingerprints: []string{"sha256:safe"}}, Score: 80, Severity: domain.SeverityCritical, PolicyVersion: "v1", RuleCatalogVersion: "v1", MatchedRules: []domain.RuleMatch{}, Contributions: []domain.ScoreContribution{}, EvidencePaths: []domain.EvidencePath{}, Warnings: []string{}, RemediationIDs: []string{}, Remediations: []domain.RemediationResult{}}}, Warnings: []string{}}, ParserWarnings: []domain.ParseWarning{}, NonFatalErrors: []string{}}
}
