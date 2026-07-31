package githubactions

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Bavlik/CredScope/internal/domain"
)

// parseWorkflowContent writes content as .github/workflows/test.yml under a
// fresh temp root and parses it, failing the test on any parse error.
func parseWorkflowContent(t *testing.T, content string) domain.Workflow {
	t.Helper()
	root := t.TempDir()
	path := filepath.Join(root, ".github", "workflows", "test.yml")
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	workflow, err := New().Parse(context.Background(), root, path)
	if err != nil {
		t.Fatal(err)
	}
	return workflow
}

// parseWorkflowContentExpectError is parseWorkflowContent's error-path
// counterpart: it requires Parse to fail and returns the error.
func parseWorkflowContentExpectError(t *testing.T, content string) error {
	t.Helper()
	root := t.TempDir()
	path := filepath.Join(root, ".github", "workflows", "test.yml")
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := New().Parse(context.Background(), root, path)
	if err == nil {
		t.Fatal("expected parse error")
	}
	return err
}

func withStepWorkflow(withBlock string) string {
	return "name: deploy\non: push\njobs:\n  deploy:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: ./.github/actions/deploy\n" + withBlock
}

// 1. with absent.
func TestWorkflowStepWithAbsent(t *testing.T) {
	workflow := parseWorkflowContent(t, withStepWorkflow(""))
	step := workflow.Jobs[0].Steps[0]
	if len(step.With) != 0 {
		t.Fatalf("expected empty With, got %#v", step.With)
	}
}

// 2. with empty mapping.
func TestWorkflowStepWithEmptyMapping(t *testing.T) {
	workflow := parseWorkflowContent(t, withStepWorkflow("        with: {}\n"))
	step := workflow.Jobs[0].Steps[0]
	if len(step.With) != 0 {
		t.Fatalf("expected empty With for empty mapping, got %#v", step.With)
	}
}

// 3. with explicit null rejected.
func TestWorkflowStepWithExplicitNullRejected(t *testing.T) {
	err := parseWorkflowContentExpectError(t, withStepWorkflow("        with: null\n"))
	if !strings.Contains(err.Error(), "with must be a mapping") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// 4. scalar with rejected.
func TestWorkflowStepWithScalarRejected(t *testing.T) {
	err := parseWorkflowContentExpectError(t, withStepWorkflow("        with: oops\n"))
	if !strings.Contains(err.Error(), "with must be a mapping") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// 5. sequence with rejected.
func TestWorkflowStepWithSequenceRejected(t *testing.T) {
	err := parseWorkflowContentExpectError(t, withStepWorkflow("        with:\n          - a\n          - b\n"))
	if !strings.Contains(err.Error(), "with must be a mapping") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// 6. empty string preserved internally.
func TestWorkflowStepWithEmptyStringPreserved(t *testing.T) {
	workflow := parseWorkflowContent(t, withStepWorkflow("        with:\n          token: \"\"\n"))
	binding := findBinding(t, workflow.Jobs[0].Steps[0], "token")
	if binding.Value != "" {
		t.Fatalf("expected empty string preserved, got %q", binding.Value)
	}
}

// 7. false preserved as text.
func TestWorkflowStepWithFalsePreservedAsText(t *testing.T) {
	workflow := parseWorkflowContent(t, withStepWorkflow("        with:\n          enabled: \"false\"\n"))
	binding := findBinding(t, workflow.Jobs[0].Steps[0], "enabled")
	if binding.Value != "false" {
		t.Fatalf("expected textual false, got %q", binding.Value)
	}
}

// 8. zero preserved as text.
func TestWorkflowStepWithZeroPreservedAsText(t *testing.T) {
	workflow := parseWorkflowContent(t, withStepWorkflow("        with:\n          retries: \"0\"\n"))
	binding := findBinding(t, workflow.Jobs[0].Steps[0], "retries")
	if binding.Value != "0" {
		t.Fatalf("expected textual zero, got %q", binding.Value)
	}
}

// 9. literal preserved internally.
func TestWorkflowStepWithLiteralPreserved(t *testing.T) {
	workflow := parseWorkflowContent(t, withStepWorkflow("        with:\n          region: production\n"))
	binding := findBinding(t, workflow.Jobs[0].Steps[0], "region")
	if binding.Value != "production" {
		t.Fatalf("expected literal preserved, got %q", binding.Value)
	}
	if len(binding.References) != 0 {
		t.Fatalf("literal binding must have no references, got %#v", binding.References)
	}
}

// 10. mapping value rejected.
func TestWorkflowStepWithMappingValueRejected(t *testing.T) {
	err := parseWorkflowContentExpectError(t, withStepWorkflow("        with:\n          token:\n            nested: value\n"))
	if !strings.Contains(err.Error(), "with value must be a scalar") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// 11. sequence value rejected.
func TestWorkflowStepWithSequenceValueRejected(t *testing.T) {
	err := parseWorkflowContentExpectError(t, withStepWorkflow("        with:\n          token:\n            - a\n            - b\n"))
	if !strings.Contains(err.Error(), "with value must be a scalar") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// 12. empty key rejected.
func TestWorkflowStepWithEmptyKeyRejected(t *testing.T) {
	err := parseWorkflowContentExpectError(t, withStepWorkflow("        with:\n          \"\": value\n"))
	if !strings.Contains(err.Error(), "with key must be a non-empty identifier") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// 13. duplicate keys rejected.
func TestWorkflowStepWithDuplicateKeysRejected(t *testing.T) {
	err := parseWorkflowContentExpectError(t, withStepWorkflow("        with:\n          token: a\n          token: b\n"))
	if !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("expected duplicate-key rejection, got: %v", err)
	}
}

// 14. exact evidence.
func TestWorkflowStepWithExactEvidence(t *testing.T) {
	workflow := parseWorkflowContent(t, withStepWorkflow("        with:\n          token: ${{ secrets.PROD_TOKEN }}\n"))
	binding := findBinding(t, workflow.Jobs[0].Steps[0], "token")
	if binding.Evidence.Location.Path != ".github/workflows/test.yml" {
		t.Fatalf("unexpected evidence path: %#v", binding.Evidence)
	}
	if binding.Evidence.Location.Line == 0 || binding.Evidence.Location.Column == 0 {
		t.Fatalf("expected non-zero line/column, got %#v", binding.Evidence.Location)
	}
	if !strings.Contains(binding.Evidence.Field, "with.token") {
		t.Fatalf("expected field to reference with.token, got %q", binding.Evidence.Field)
	}
}

// 15. deterministic ordering.
func TestWorkflowStepWithDeterministicOrdering(t *testing.T) {
	workflow := parseWorkflowContent(t, withStepWorkflow("        with:\n          zeta: 1\n          alpha: 2\n          mid: 3\n"))
	bindings := workflow.Jobs[0].Steps[0].With
	if len(bindings) != 3 || bindings[0].Name != "alpha" || bindings[1].Name != "mid" || bindings[2].Name != "zeta" {
		t.Fatalf("expected sorted bindings by name, got %#v", bindings)
	}
}

// 16. source YAML unchanged (parsing twice yields identical results; no
// mutation of the document leaks between runs).
func TestWorkflowStepWithSourceYAMLUnchanged(t *testing.T) {
	content := withStepWorkflow("        with:\n          token: ${{ secrets.PROD_TOKEN }}\n")
	first := parseWorkflowContent(t, content)
	second := parseWorkflowContent(t, content)
	firstJSON, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	secondJSON, err := json.Marshal(second)
	if err != nil {
		t.Fatal(err)
	}
	if string(firstJSON) != string(secondJSON) {
		t.Fatal("re-parsing identical content produced different output")
	}
}

// 17. static secret becomes ReferenceSecret.
func TestWorkflowStepWithStaticSecretBecomesReferenceSecret(t *testing.T) {
	workflow := parseWorkflowContent(t, withStepWorkflow("        with:\n          token: ${{ secrets.PROD_TOKEN }}\n"))
	binding := findBinding(t, workflow.Jobs[0].Steps[0], "token")
	if !containsReference(binding.References, domain.ReferenceSecret, "PROD_TOKEN") {
		t.Fatalf("expected ReferenceSecret PROD_TOKEN, got %#v", binding.References)
	}
}

// 18. github.token remains noncredential.
func TestWorkflowStepWithGithubTokenNoncredential(t *testing.T) {
	workflow := parseWorkflowContent(t, withStepWorkflow("        with:\n          token: ${{ github.token }}\n"))
	binding := findBinding(t, workflow.Jobs[0].Steps[0], "token")
	if containsReference(binding.References, domain.ReferenceSecret, "token") {
		t.Fatalf("github.token must never become ReferenceSecret: %#v", binding.References)
	}
	if !containsReference(binding.References, domain.ReferenceGitHubContext, "github.token") {
		t.Fatalf("expected github.token as ReferenceGitHubContext, got %#v", binding.References)
	}
}

// 19. workflow inputs.* behavior unchanged.
func TestWorkflowStepWithInputsBehaviorUnchanged(t *testing.T) {
	workflow := parseWorkflowContent(t, withStepWorkflow("        with:\n          environment: ${{ inputs.environment }}\n"))
	binding := findBinding(t, workflow.Jobs[0].Steps[0], "environment")
	if !containsReference(binding.References, domain.ReferenceGitHubContext, "inputs.environment") {
		t.Fatalf("expected ReferenceGitHubContext for inputs.environment, got %#v", binding.References)
	}
	for _, ref := range binding.References {
		if ref.Kind == domain.ReferenceActionInput {
			t.Fatalf("workflow-step with: must never produce ReferenceActionInput: %#v", ref)
		}
	}
}

// 20. env/vars/needs/steps/matrix behavior unchanged.
func TestWorkflowStepWithContextReferencesUnchanged(t *testing.T) {
	content := withStepWorkflow(
		"        with:\n" +
			"          a: ${{ env.TOKEN }}\n" +
			"          b: ${{ vars.REGION }}\n" +
			"          c: ${{ needs.build.outputs.token }}\n" +
			"          d: ${{ steps.prepare.outputs.token }}\n" +
			"          e: ${{ matrix.environment }}\n" +
			"          f: ${{ runner.os }}\n")
	workflow := parseWorkflowContent(t, content)
	step := workflow.Jobs[0].Steps[0]
	if !containsReference(findBinding(t, step, "a").References, domain.ReferenceEnvironment, "TOKEN") {
		t.Fatal("env.TOKEN must be ReferenceEnvironment")
	}
	if !containsReference(findBinding(t, step, "b").References, domain.ReferenceGitHubContext, "vars.REGION") {
		t.Fatal("vars.REGION must be generic ReferenceGitHubContext")
	}
	if !containsReference(findBinding(t, step, "c").References, domain.ReferenceGitHubContext, "needs.build.outputs.token") {
		t.Fatal("needs.* must be generic ReferenceGitHubContext")
	}
	if !containsReference(findBinding(t, step, "d").References, domain.ReferenceGitHubContext, "steps.prepare.outputs.token") {
		t.Fatal("steps.* must be generic ReferenceGitHubContext")
	}
	if !containsReference(findBinding(t, step, "e").References, domain.ReferenceGitHubContext, "matrix.environment") {
		t.Fatal("matrix.* must be generic ReferenceGitHubContext")
	}
	if !containsReference(findBinding(t, step, "f").References, domain.ReferenceGitHubContext, "runner.os") {
		t.Fatal("runner.* must be generic ReferenceGitHubContext")
	}
}

// 21. dynamic secrets indexing does not invent a ReferenceSecret.
func TestWorkflowStepWithDynamicSecretIndexingNoInventedReference(t *testing.T) {
	content := withStepWorkflow(
		"        with:\n" +
			"          a: ${{ secrets[\"PROD_TOKEN\"] }}\n" +
			"          b: ${{ secrets[inputs.secret_name] }}\n")
	workflow := parseWorkflowContent(t, content)
	step := workflow.Jobs[0].Steps[0]
	if len(findBinding(t, step, "a").References) != 0 {
		t.Fatalf("bracket-indexed secret must produce no references, got %#v", findBinding(t, step, "a").References)
	}
	if len(findBinding(t, step, "b").References) != 0 {
		t.Fatalf("dynamic-indexed secret must produce no references, got %#v", findBinding(t, step, "b").References)
	}
}

// Confirms the pre-existing generic WorkflowStep.References sweep still
// incidentally covers with: content in parallel with the new structured
// With field — CA2 must not remove or change that existing behavior.
func TestWorkflowStepWithGenericReferenceSweepStillCoversWith(t *testing.T) {
	workflow := parseWorkflowContent(t, withStepWorkflow("        with:\n          token: ${{ secrets.PROD_TOKEN }}\n"))
	step := workflow.Jobs[0].Steps[0]
	if !containsReference(step.References, domain.ReferenceSecret, "PROD_TOKEN") {
		t.Fatalf("expected generic step.References sweep to still include with: secret reference, got %#v", step.References)
	}
	if !containsReference(findBinding(t, step, "token").References, domain.ReferenceSecret, "PROD_TOKEN") {
		t.Fatal("expected structured With binding to also carry the reference")
	}
}

// distinct ordinary names accepted.
func TestWorkflowStepWithDistinctOrdinaryNamesAccepted(t *testing.T) {
	workflow := parseWorkflowContent(t, withStepWorkflow("        with:\n          token: a\n          region: b\n          environment: c\n"))
	bindings := workflow.Jobs[0].Steps[0].With
	if len(bindings) != 3 {
		t.Fatalf("expected three distinct bindings, got %#v", bindings)
	}
}

// two distinct raw keys normalizing to the same name rejected.
func TestWorkflowStepWithNormalizedNameCollisionRejected(t *testing.T) {
	err := parseWorkflowContentExpectError(t, withStepWorkflow("        with:\n          \"api token\": a\n          api_token: b\n"))
	if !strings.Contains(err.Error(), "normalizes to already-used identifier") || !strings.Contains(err.Error(), `"api_token"`) {
		t.Fatalf("unexpected error: %v", err)
	}
}

// two distinct raw keys normalizing to the same name rejected — second
// collision-prone example pair from the prompt ("token!" / "token_").
func TestWorkflowStepWithNormalizedNameCollisionRejectedBangUnderscore(t *testing.T) {
	err := parseWorkflowContentExpectError(t, withStepWorkflow("        with:\n          \"token!\": a\n          token_: b\n"))
	if !strings.Contains(err.Error(), "normalizes to already-used identifier") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// whitespace-only key rejected (normalizes to the empty identifier, same as
// an empty key).
func TestWorkflowStepWithWhitespaceOnlyKeyRejected(t *testing.T) {
	err := parseWorkflowContentExpectError(t, withStepWorkflow("        with:\n          \"   \": value\n"))
	if !strings.Contains(err.Error(), "with key must be a non-empty identifier") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// deterministic error: re-parsing identical colliding content produces the
// identical error message every time.
func TestWorkflowStepWithNormalizedNameCollisionDeterministicError(t *testing.T) {
	content := withStepWorkflow("        with:\n          \"api token\": a\n          api_token: b\n")
	first := parseWorkflowContentExpectError(t, content)
	second := parseWorkflowContentExpectError(t, content)
	if first.Error() != second.Error() {
		t.Fatalf("error not deterministic: first=%q second=%q", first.Error(), second.Error())
	}
}

// source YAML unchanged: a rejected collision must not leave any partial
// mutation visible on a subsequent, valid parse of the same file path.
func TestWorkflowStepWithNormalizedNameCollisionSourceYAMLUnchanged(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, ".github", "workflows", "test.yml")
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	collidingContent := withStepWorkflow("        with:\n          \"api token\": a\n          api_token: b\n")
	if err := os.WriteFile(path, []byte(collidingContent), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New().Parse(context.Background(), root, path); err == nil {
		t.Fatal("expected parse error")
	}
	onDisk, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(onDisk) != collidingContent {
		t.Fatal("source YAML was mutated by a failed parse")
	}

	validContent := withStepWorkflow("        with:\n          token: a\n")
	if err := os.WriteFile(path, []byte(validContent), 0o600); err != nil {
		t.Fatal(err)
	}
	workflow, err := New().Parse(context.Background(), root, path)
	if err != nil {
		t.Fatal(err)
	}
	if len(workflow.Jobs[0].Steps[0].With) != 1 {
		t.Fatal("subsequent valid parse of the same path was affected by the earlier rejected collision")
	}
}

func findBinding(t *testing.T, step domain.WorkflowStep, name string) domain.ActionCallInputBinding {
	t.Helper()
	for _, binding := range step.With {
		if binding.Name == name {
			return binding
		}
	}
	t.Fatalf("binding %q not found in %#v", name, step.With)
	return domain.ActionCallInputBinding{}
}
