package analysis

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/Bavlik/CredScope/internal/domain"
)

// deepCopyJSON produces a fully independent copy of v via a JSON
// marshal/unmarshal round trip. Unlike a shallow struct copy (which copies
// slice headers but leaves them pointing at the same backing arrays), this
// captures the complete content of every nested slice and struct
// positionally, so it is sensitive to in-place backing-array mutation, not
// just to slice length or header changes.
func deepCopyJSON[T any](t *testing.T, v T) T {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("deep copy: marshal: %v", err)
	}
	var out T
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("deep copy: unmarshal: %v", err)
	}
	return out
}

// evidence is a small helper for building minimal, valid domain.Evidence
// values in fixtures below.
func evidence(path string, line int) domain.Evidence {
	return domain.Evidence{Location: domain.Location{Path: path, Line: line}, Confidence: domain.ConfidenceConfirmed}
}

// mutationFixture builds a ParsedRepository with three workflows, three
// Compose projects, and three findings — enough that ignoring the first of
// each (which is what every test below does) forces the remaining two to
// shift position in the backing array under the old parsed.X[:0] bug. A
// fixture where nothing is ever filtered out would not exercise the bug at
// all, since appending every retained item back into the same backing array
// at its original position is harmless.
func mutationFixture() domain.ParsedRepository {
	workflow := func(name, file string) domain.Workflow {
		return domain.Workflow{Name: name, File: file, Evidence: evidence(file, 1)}
	}
	compose := func(file string) domain.ComposeProject {
		return domain.ComposeProject{File: file, Evidence: evidence(file, 1)}
	}
	finding := func(id, ruleID, path string) domain.Finding {
		return domain.Finding{
			ID: id, RuleID: ruleID, Description: "synthetic fixture finding",
			Credential: domain.CredentialIdentity{Label: ruleID + "_TOKEN", Fingerprint: "sha256:" + id, Type: ruleID},
			Location:   domain.Location{Path: path, Line: 1},
			Source:     "test",
		}
	}
	return domain.ParsedRepository{
		Workflows: []domain.Workflow{
			workflow("ignored", ".github/workflows/ignored.yml"),
			workflow("kept-one", ".github/workflows/kept-one.yml"),
			workflow("kept-two", ".github/workflows/kept-two.yml"),
		},
		Compose: []domain.ComposeProject{
			compose("ignored-compose.yml"),
			compose("kept-compose-one.yml"),
			compose("kept-compose-two.yml"),
		},
		Findings: []domain.Finding{
			finding("finding:ignored", "ignored-rule", "ignored.env"),
			finding("finding:kept-one", "kept-rule-one", "kept-one.env"),
			finding("finding:kept-two", "kept-rule-two", "kept-two.env"),
		},
	}
}

// mutationOptions ignores exactly the first workflow, first Compose file,
// and first finding from mutationFixture, via the same directive kinds
// applyRepositoryIgnores filters on.
func mutationOptions() Options {
	return Options{
		IgnorePaths: []IgnoreDirective{
			{Value: ".github/workflows/ignored.yml", Reason: "test fixture"},
			{Value: "ignored-compose.yml", Reason: "test fixture"},
		},
		IgnoreFindings: []IgnoreDirective{
			{Value: "finding:ignored", Reason: "test fixture"},
		},
	}
}

// TestAnalyzeDoesNotMutateParsedRepositoryWorkflows proves Analyze leaves
// the caller's ParsedRepository.Workflows backing array untouched, even
// when an ignore.paths directive removes the first of several workflows —
// exactly the shape that reordered the old parsed.Workflows[:0] bug's
// remaining elements in place.
func TestAnalyzeDoesNotMutateParsedRepositoryWorkflows(t *testing.T) {
	parsed := mutationFixture()
	before := deepCopyJSON(t, parsed.Workflows)
	if _, err := Analyze(context.Background(), parsed, mutationOptions()); err != nil {
		t.Fatal(err)
	}
	after := deepCopyJSON(t, parsed.Workflows)
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("Analyze mutated the caller's Workflows backing array\nbefore: %#v\nafter:  %#v", before, after)
	}
}

// TestAnalyzeDoesNotMutateParsedRepositoryCompose is the Compose analog of
// the Workflows test above.
func TestAnalyzeDoesNotMutateParsedRepositoryCompose(t *testing.T) {
	parsed := mutationFixture()
	before := deepCopyJSON(t, parsed.Compose)
	if _, err := Analyze(context.Background(), parsed, mutationOptions()); err != nil {
		t.Fatal(err)
	}
	after := deepCopyJSON(t, parsed.Compose)
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("Analyze mutated the caller's Compose backing array\nbefore: %#v\nafter:  %#v", before, after)
	}
}

// TestAnalyzeDoesNotMutateParsedRepositoryFindings is the Findings analog,
// additionally covering ignore.findings (rather than ignore.paths) removal.
func TestAnalyzeDoesNotMutateParsedRepositoryFindings(t *testing.T) {
	parsed := mutationFixture()
	before := deepCopyJSON(t, parsed.Findings)
	if _, err := Analyze(context.Background(), parsed, mutationOptions()); err != nil {
		t.Fatal(err)
	}
	after := deepCopyJSON(t, parsed.Findings)
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("Analyze mutated the caller's Findings backing array\nbefore: %#v\nafter:  %#v", before, after)
	}
}

// TestAnalyzeDoesNotMutateWholeParsedRepository is a whole-struct version
// of the three tests above: a single deep-copy comparison of the entire
// ParsedRepository value, proving the general Analyze(ctx, parsed, options)
// contract — parsed and any of its backing storage must never be mutated —
// holds beyond just the three fields the reported bug touched.
func TestAnalyzeDoesNotMutateWholeParsedRepository(t *testing.T) {
	parsed := mutationFixture()
	before := deepCopyJSON(t, parsed)
	if _, err := Analyze(context.Background(), parsed, mutationOptions()); err != nil {
		t.Fatal(err)
	}
	after := deepCopyJSON(t, parsed)
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("Analyze mutated the caller's ParsedRepository")
	}
}

// TestIgnoreDirectivesDoNotAlterCallerOwnedSlices exercises every ignore
// directive kind that touches ParsedRepository fields (paths and findings —
// ignore.variables and ignore.rules act only on graph/rule-match data, never
// on ParsedRepository.Workflows/Compose/Findings) and confirms none of them
// leave a visible mark on the caller's slices.
func TestIgnoreDirectivesDoNotAlterCallerOwnedSlices(t *testing.T) {
	parsed := mutationFixture()
	before := deepCopyJSON(t, parsed)
	options := mutationOptions()
	options.IgnoreVariables = []IgnoreDirective{{Value: "SOME_VARIABLE", Reason: "unrelated to this ParsedRepository fixture"}}
	options.IgnoreRules = []IgnoreDirective{{Value: "CRD999", Reason: "unrelated placeholder rule"}}
	if _, err := Analyze(context.Background(), parsed, options); err != nil {
		t.Fatal(err)
	}
	after := deepCopyJSON(t, parsed)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("an ignore directive mutated the caller's ParsedRepository")
	}
}

// TestAnalyzeTwiceOnSameParsedInstanceIsDeeplyEqual is the direct
// regression test for the reported bug: calling Analyze twice with the
// exact same caller-held ParsedRepository value and Options must produce
// byte-identical JSON and deeply equal results. Under the old bug, the
// first call's in-place filtering corrupted the shared backing array, so
// the second call saw already-filtered (and reordered) input.
func TestAnalyzeTwiceOnSameParsedInstanceIsDeeplyEqual(t *testing.T) {
	parsed := mutationFixture()
	options := mutationOptions()

	first, err := Analyze(context.Background(), parsed, options)
	if err != nil {
		t.Fatalf("first Analyze: %v", err)
	}
	second, err := Analyze(context.Background(), parsed, options)
	if err != nil {
		t.Fatalf("second Analyze: %v", err)
	}

	firstJSON, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	secondJSON, err := json.Marshal(second)
	if err != nil {
		t.Fatal(err)
	}
	if string(firstJSON) != string(secondJSON) {
		t.Fatal("two Analyze calls on the same ParsedRepository produced different JSON")
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatal("two Analyze calls on the same ParsedRepository produced different results")
	}
	if len(first.Credentials) != 2 {
		t.Fatalf("expected the two kept, unignored credentials, got %d: %v", len(first.Credentials), credentialLabels(first))
	}
}

// TestIntegratedAllowlistIgnoreScenarioRemainsDeterministic mirrors the
// shape of the corpus case that surfaced this bug
// (integrated-allowlist-ignore-config): a workflow referencing two
// variables (one allowlisted away, one active) plus two imported findings
// (one allowlisted by rule ID, one active), analyzed twice from the same
// parsed input under the production profile. This is a self-contained unit
// test — it does not depend on testdata/corpus — so it exercises the exact
// bug shape without requiring the corpus runner.
func TestIntegratedAllowlistIgnoreScenarioRemainsDeterministic(t *testing.T) {
	workflowEvidence := evidence(".github/workflows/deploy.yml", 1)
	parsed := domain.ParsedRepository{
		Findings: []domain.Finding{
			{
				ID: "finding:ignored-fixture", RuleID: "test-fixture-finding", Description: "allowlisted fixture finding",
				Credential: domain.CredentialIdentity{Label: "IGNORED_FIXTURE_TOKEN", Fingerprint: "sha256:ignored", Type: "test-fixture-finding"},
				Location:   domain.Location{Path: ".env.example", Line: 1}, Source: "gitleaks",
			},
			{
				ID: "finding:active", RuleID: "generic-api-key", Description: "active fixture finding",
				Credential: domain.CredentialIdentity{Label: "ACTIVE_PROD_TOKEN", Fingerprint: "sha256:active", Type: "generic-api-key"},
				Location:   domain.Location{Path: ".env.example", Line: 2}, Source: "gitleaks",
			},
		},
		Workflows: []domain.Workflow{
			{
				Name: "deploy", File: ".github/workflows/deploy.yml", Evidence: workflowEvidence,
				Jobs: []domain.WorkflowJob{
					{
						ID: "deploy", Evidence: workflowEvidence,
						Environment: []domain.EnvironmentBinding{
							{Name: "STAGING_DEBUG_TOKEN", Scope: "job", Evidence: workflowEvidence, References: []domain.Reference{{Kind: domain.ReferenceSecret, Name: "STAGING_DEBUG_TOKEN", Evidence: workflowEvidence}}},
							{Name: "ACTIVE_PROD_TOKEN", Scope: "job", Evidence: workflowEvidence, References: []domain.Reference{{Kind: domain.ReferenceSecret, Name: "ACTIVE_PROD_TOKEN", Evidence: workflowEvidence}}},
						},
						References: []domain.Reference{
							{Kind: domain.ReferenceSecret, Name: "STAGING_DEBUG_TOKEN", Evidence: workflowEvidence},
							{Kind: domain.ReferenceSecret, Name: "ACTIVE_PROD_TOKEN", Evidence: workflowEvidence},
						},
					},
				},
			},
		},
	}

	options := Options{
		Profile: domain.ProfileProduction,
		IgnoreFindings: []IgnoreDirective{
			{Value: "test-fixture-finding", Reason: "reviewed scanner rule in a fake fixture"},
		},
		IgnoreVariables: []IgnoreDirective{
			{Value: "STAGING_DEBUG_TOKEN", Reason: "known false positive; internal debug flag"},
		},
	}

	first, err := Analyze(context.Background(), parsed, options)
	if err != nil {
		t.Fatalf("first Analyze: %v", err)
	}
	second, err := Analyze(context.Background(), parsed, options)
	if err != nil {
		t.Fatalf("second Analyze: %v", err)
	}
	firstJSON, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	secondJSON, err := json.Marshal(second)
	if err != nil {
		t.Fatal(err)
	}
	if string(firstJSON) != string(secondJSON) {
		t.Fatal("integrated allowlist/ignore scenario was not deterministic across two Analyze calls")
	}

	if findCredential(first, "IGNORED_FIXTURE_TOKEN") != nil {
		t.Fatal("ignored finding must not appear as an analyzed credential")
	}
	active := findCredential(first, "ACTIVE_PROD_TOKEN")
	if active == nil {
		t.Fatalf("active credential missing; labels = %v", credentialLabels(first))
	}
	if !hasRule(active.MatchedRules, "CRD101") {
		t.Fatalf("active credential should match CRD101 (imported finding); matches = %v", active.MatchedRules)
	}
	foundIgnoredFinding, foundIgnoredVariable := false, false
	for _, item := range first.IgnoredItems {
		if item.Kind == "finding" && item.Target == "test-fixture-finding" {
			foundIgnoredFinding = true
		}
		if item.Kind == "variable" && item.Target == "STAGING_DEBUG_TOKEN" {
			foundIgnoredVariable = true
		}
	}
	if !foundIgnoredFinding || !foundIgnoredVariable {
		t.Fatalf("expected both ignore reasons recorded in IgnoredItems, got %#v", first.IgnoredItems)
	}
}
