package analysis

import (
	"context"
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/credscope/credscope/internal/config"
	"github.com/credscope/credscope/internal/domain"
	"github.com/credscope/credscope/internal/ingest"
)

const (
	fixtureSecretOne = "FAKE_RAW_SECRET_FOR_TESTS_ONLY"
	fixtureSecretTwo = "DEMO_DATABASE_PASSWORD_VALUE_FOR_TESTS_ONLY"
)

func TestVulnerableRepositoryEndToEndIsCriticalDeterministicAndSecretSafe(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", "testdata", "vulnerable"))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ingest.Repository(context.Background(), root, config.Default(), filepath.Join(root, "gitleaks.json"))
	if err != nil {
		t.Fatalf("ingest fixture: %v", err)
	}
	first, err := Analyze(context.Background(), parsed, Options{})
	if err != nil {
		t.Fatalf("analyze fixture: %v", err)
	}
	second, err := Analyze(context.Background(), parsed, Options{})
	if err != nil {
		t.Fatalf("repeat analyze fixture: %v", err)
	}
	firstJSON, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	secondJSON, err := json.Marshal(second)
	if err != nil {
		t.Fatal(err)
	}
	if string(firstJSON) != string(secondJSON) || !reflect.DeepEqual(first, second) {
		t.Fatal("repeated analysis did not produce byte-stable results")
	}
	for _, raw := range []string{fixtureSecretOne, fixtureSecretTwo} {
		if strings.Contains(string(firstJSON), raw) {
			t.Fatalf("serialized analysis leaked known fake raw secret %q", raw)
		}
	}
	credential := findCredential(first, "FAKE_PRODUCTION_TOKEN")
	if credential == nil {
		t.Fatalf("credential not analyzed; labels = %v", credentialLabels(first))
	}
	if credential.Score < 80 || credential.Severity != domain.SeverityCritical {
		t.Fatalf("score = %d severity = %q, want critical", credential.Score, credential.Severity)
	}
	for _, ruleID := range []string{"CRD101", "CRD102", "CRD104", "CRD201", "CRD203", "CRD205", "CRD206", "CRD301", "CRD302", "CRD303", "CRD304", "CRD401", "CRD404", "CRD502", "CRD503"} {
		if !hasRule(credential.MatchedRules, ruleID) {
			t.Errorf("missing expected rule %s", ruleID)
		}
	}
	if credential.Reachable.Workflows == 0 || credential.Reachable.Jobs == 0 || credential.Reachable.Services < 2 || len(credential.EvidencePaths) == 0 || len(credential.Remediations) == 0 {
		t.Fatalf("incomplete reachability result: %#v", credential.Reachable)
	}
	aws := findCredential(first, "EXAMPLE_AWS_DEPLOY_KEY")
	if aws == nil {
		t.Fatal("AWS fixture credential was not analyzed")
	}
	for _, ruleID := range []string{"CRD103", "CRD208", "CRD403"} {
		if !hasRule(aws.MatchedRules, ruleID) {
			t.Errorf("AWS credential missing expected rule %s", ruleID)
		}
	}
}

func TestDuplicateFindingsDoNotInflateAnalysis(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", "testdata", "vulnerable"))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ingest.Repository(context.Background(), root, config.Default(), filepath.Join(root, "gitleaks.json"))
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := Analyze(context.Background(), parsed, Options{})
	if err != nil {
		t.Fatal(err)
	}
	duplicated := parsed
	duplicated.Findings = append(append([]domain.Finding{}, parsed.Findings...), parsed.Findings[0], parsed.Findings[0])
	withDuplicates, err := Analyze(context.Background(), duplicated, Options{})
	if err != nil {
		t.Fatal(err)
	}
	before := findCredential(baseline, parsed.Findings[0].Credential.Label)
	after := findCredential(withDuplicates, parsed.Findings[0].Credential.Label)
	if before == nil || after == nil || before.Score != after.Score || !reflect.DeepEqual(before.Contributions, after.Contributions) {
		t.Fatalf("duplicate findings changed scoring: before=%#v after=%#v", before, after)
	}
}

func TestEmptyAndIncompleteParsedRepository(t *testing.T) {
	empty, err := Analyze(context.Background(), domain.ParsedRepository{}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(empty.Credentials) != 0 || len(empty.Graph.Nodes) != 1 || empty.PolicyVersion != "v1" || empty.RuleCatalogVersion != "v1" {
		t.Fatalf("empty result = %#v", empty)
	}
	incomplete := domain.ParsedRepository{Findings: []domain.Finding{{ID: "finding:empty", Credential: domain.CredentialIdentity{}, Source: "test"}}}
	result, err := Analyze(context.Background(), incomplete, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Credentials) != 0 || len(result.Warnings) != 1 {
		t.Fatalf("incomplete result = %#v", result)
	}
}

func TestAnalyzeHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Analyze(ctx, domain.ParsedRepository{}, Options{}); err == nil {
		t.Fatal("expected cancellation error")
	}
}

func TestAnalyzeFailsClosedAtEvidencePathLimit(t *testing.T) {
	evidence := func(line int) domain.Evidence {
		return domain.Evidence{Location: domain.Location{Path: ".github/workflows/bounded.yml", Line: line}, Confidence: domain.ConfidenceConfirmed}
	}
	reference := func() domain.Reference {
		return domain.Reference{Kind: domain.ReferenceSecret, Name: "BOUNDED_TOKEN", Evidence: evidence(4)}
	}
	parsed := domain.ParsedRepository{Workflows: []domain.Workflow{{
		Name: "bounded", File: ".github/workflows/bounded.yml", Evidence: evidence(1),
		Jobs: []domain.WorkflowJob{
			{ID: "one", Evidence: evidence(2), References: []domain.Reference{reference()}},
			{ID: "two", Evidence: evidence(3), References: []domain.Reference{reference()}},
		},
	}}}
	_, err := Analyze(context.Background(), parsed, Options{MaxEvidencePaths: 1})
	if err == nil || !strings.Contains(err.Error(), "safety limit of 1 evidence paths") {
		t.Fatalf("expected fail-closed path limit, got %v", err)
	}
	_, err = Analyze(context.Background(), parsed, Options{MaxEvidencePaths: 10, MaxTotalPaths: 1})
	if err == nil || !strings.Contains(err.Error(), "safety limit of 1 total evidence paths") {
		t.Fatalf("expected fail-closed total path limit, got %v", err)
	}
}

func TestDisabledRuleIsRemovedBeforeScoringAndRemediation(t *testing.T) {
	parsed := domain.ParsedRepository{Findings: []domain.Finding{{ID: "finding:safe", RuleID: "demo", Credential: domain.CredentialIdentity{Label: "DEMO_TOKEN", Fingerprint: "sha256:safe"}, Source: "test"}}}
	result, err := Analyze(context.Background(), parsed, Options{DisabledRules: map[string]bool{"CRD101": true}})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Credentials) != 1 || result.Credentials[0].Score != 0 || hasRule(result.Credentials[0].MatchedRules, "CRD101") || len(result.Credentials[0].Remediations) != 0 {
		t.Fatalf("disabled rule survived: %#v", result.Credentials)
	}
}

func TestCriticalWriteAllAndUnresolvedReusableFixture(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", "testdata", "vulnerable", "write-all"))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ingest.Repository(context.Background(), root, config.Default(), "")
	if err != nil {
		t.Fatal(err)
	}
	result, err := Analyze(context.Background(), parsed, Options{})
	if err != nil {
		t.Fatal(err)
	}
	credential := findCredential(result, "CRITICAL_DEMO_TOKEN")
	if credential == nil || credential.Score != 100 || credential.Severity != domain.SeverityCritical {
		t.Fatalf("critical fixture result = %#v", credential)
	}
	for _, id := range []string{"CRD202", "CRD302", "CRD304", "CRD305", "CRD307", "CRD401", "CRD501"} {
		if !hasRule(credential.MatchedRules, id) {
			t.Errorf("critical fixture missing %s", id)
		}
	}
}

func TestDevelopmentOnlyFixtureRemainsLowRisk(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", "testdata", "vulnerable", "development"))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ingest.Repository(context.Background(), root, config.Default(), "")
	if err != nil {
		t.Fatal(err)
	}
	result, err := Analyze(context.Background(), parsed, Options{})
	if err != nil {
		t.Fatal(err)
	}
	credential := findCredential(result, "DEVELOPMENT_ONLY_TOKEN")
	if credential == nil || credential.Score >= 40 {
		t.Fatalf("development fixture should remain below medium: %#v", credential)
	}
	if hasRule(credential.MatchedRules, "CRD208") || hasRule(credential.MatchedRules, "CRD201") {
		t.Fatalf("development fixture gained production/write rules: %#v", credential.MatchedRules)
	}
}

func findCredential(result domain.AnalysisResult, label string) *domain.CredentialAnalysis {
	for index := range result.Credentials {
		if result.Credentials[index].Credential.Label == label {
			return &result.Credentials[index]
		}
	}
	return nil
}

func credentialLabels(result domain.AnalysisResult) []string {
	labels := make([]string, len(result.Credentials))
	for index, item := range result.Credentials {
		labels[index] = item.Credential.Label
	}
	return labels
}

func hasRule(matches []domain.RuleMatch, id string) bool {
	for _, match := range matches {
		if match.RuleID == id {
			return true
		}
	}
	return false
}
