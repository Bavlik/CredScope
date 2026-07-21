package jsonreport

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Bavlik/CredScope/internal/analysis"
	"github.com/Bavlik/CredScope/internal/config"
	"github.com/Bavlik/CredScope/internal/domain"
	"github.com/Bavlik/CredScope/internal/ingest"
	"github.com/Bavlik/CredScope/internal/reporters"
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
	if got := fmt.Sprintf("%x", sha256.Sum256(first.Bytes())); got != "6a7f2c70dbe36f0082819bc5ca6e74c6b4886a33c551d8b1a6b8819f5fac5bdc" {
		t.Fatalf("JSON golden hash = %s", got)
	}
	var decoded map[string]any
	if err := json.Unmarshal(first.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["schema_version"] != "2" {
		t.Fatalf("schema = %#v", decoded["schema_version"])
	}
	for _, field := range []string{"tool", "scan", "policies", "summary", "credentials", "graph", "ignored_count", "ignored_items", "repository_warnings", "parser_warnings", "non_fatal_errors"} {
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

func TestVulnerableFixtureJSONIsCompactAndReferencesExistingPaths(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", "..", "testdata", "vulnerable"))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ingest.Repository(context.Background(), root, config.Default(), filepath.Join(root, "gitleaks.json"))
	if err != nil {
		t.Fatal(err)
	}
	result, err := analysis.Analyze(context.Background(), parsed, analysis.Options{})
	if err != nil {
		t.Fatal(err)
	}
	input := reporters.Input{Tool: reporters.Tool{Name: "CredScope", Version: "test"}, Scan: reporters.Scan{Repository: "vulnerable", StartedAt: time.Unix(10, 0), CompletedAt: time.Unix(11, 0), Format: "json"}, Analysis: result}
	var output bytes.Buffer
	if err := New().Render(&output, input, reporters.Options{Pretty: true}); err != nil {
		t.Fatal(err)
	}
	const maximumFixtureBytes = 1_500_000
	if output.Len() > maximumFixtureBytes {
		t.Fatalf("vulnerable JSON = %d bytes, want <= %d", output.Len(), maximumFixtureBytes)
	}
	var decoded document
	if err := json.Unmarshal(output.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	for _, credential := range decoded.Credentials {
		paths := make(map[string]bool, len(credential.EvidencePaths))
		for _, path := range credential.EvidencePaths {
			if paths[path.ID] {
				t.Fatalf("duplicate path ID %s", path.ID)
			}
			paths[path.ID] = true
			for _, edge := range path.Edges {
				if len(edge.Evidence) != 0 {
					t.Fatal("path repeats canonical graph edge evidence")
				}
			}
		}
		for _, match := range credential.MatchedRules {
			for _, pathID := range match.PathIDs {
				if !paths[pathID] {
					t.Fatalf("rule %s references absent path %s", match.RuleID, pathID)
				}
			}
		}
	}
	for _, raw := range []string{"FAKE_RAW_SECRET_FOR_TESTS_ONLY", "DEMO_DATABASE_PASSWORD_VALUE_FOR_TESTS_ONLY"} {
		if strings.Contains(output.String(), raw) {
			t.Fatalf("JSON leaked known synthetic raw secret %q", raw)
		}
	}
}

func jsonInput() reporters.Input {
	return reporters.Input{Tool: reporters.Tool{Name: "CredScope", Version: "test"}, Scan: reporters.Scan{Repository: "demo<script>", StartedAt: time.Unix(10, 0), CompletedAt: time.Unix(11, 0), Format: "json", FailOn: "high", ThresholdExceeded: true}, Analysis: domain.AnalysisResult{PolicyVersion: "v2", RuleCatalogVersion: "v2", Profile: domain.ProfileSelection{Requested: domain.ProfileAuto, Selected: domain.ProfileAuto, Source: "conservative_fallback", Reason: "test context", Assumptions: []string{"runtime unknown"}}, Graph: domain.Graph{Nodes: []domain.Node{}, Edges: []domain.Edge{}}, Credentials: []domain.CredentialAnalysis{{Credential: domain.CredentialSubject{ID: "credential:safe", Label: "TOKEN", Fingerprints: []string{"sha256:safe"}, Classification: domain.ClassificationSecret, ClassificationConfidence: domain.ConfidenceMedium, ClassificationReason: "name heuristic", ClassificationSource: "variable_name_heuristic", ExpectedSecret: true}, Score: 80, Severity: domain.SeverityCritical, PolicyVersion: "v2", RuleCatalogVersion: "v2", MatchedRules: []domain.RuleMatch{}, Contributions: []domain.ScoreContribution{}, EvidencePaths: []domain.EvidencePath{}, Warnings: []string{}, RemediationIDs: []string{}, Remediations: []domain.RemediationResult{}}}, Warnings: []string{}}, ParserWarnings: []domain.ParseWarning{}, NonFatalErrors: []string{}}
}
