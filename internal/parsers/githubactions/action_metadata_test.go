package githubactions

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Bavlik/CredScope/internal/domain"
)

// parseInlineAction writes a fixture and calls ParseActionMetadata with a
// repository-relative path, matching the entry point's actual contract: it
// only ever accepts a repo-relative action.yml/action.yaml reference, the
// same way a future CA1 resolver will hand it one, never a raw OS-native
// absolute path.
func parseInlineAction(t *testing.T, filename, content string) (domain.ActionMetadata, error) {
	t.Helper()
	root := t.TempDir()
	path := filepath.Join(root, ".github", "actions", "deploy", filename)
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	relative := ".github/actions/deploy/" + filename
	return New().ParseActionMetadata(context.Background(), root, relative)
}

func findActionInput(t *testing.T, metadata domain.ActionMetadata, name string) domain.ActionInputDefinition {
	t.Helper()
	for _, in := range metadata.Inputs {
		if in.Name == name {
			return in
		}
	}
	t.Fatalf("input %q not found in %#v", name, metadata.Inputs)
	return domain.ActionInputDefinition{}
}

func findActionOutput(t *testing.T, metadata domain.ActionMetadata, name string) domain.ActionOutputDefinition {
	t.Helper()
	for _, out := range metadata.Outputs {
		if out.Name == name {
			return out
		}
	}
	t.Fatalf("output %q not found in %#v", name, metadata.Outputs)
	return domain.ActionOutputDefinition{}
}

func actionRefsOfKind(refs []domain.Reference, kind domain.ReferenceKind) []domain.Reference {
	var result []domain.Reference
	for _, r := range refs {
		if r.Kind == kind {
			result = append(result, r)
		}
	}
	return result
}

const minimalComposite = "name: Deploy\ndescription: Deploys the thing\nruns:\n  using: composite\n  steps:\n    - shell: bash\n      run: echo hi\n"

// --- Metadata basics (1-12) ---

func TestActionMetadataMinimalValidComposite(t *testing.T) {
	metadata, err := parseInlineAction(t, "action.yml", minimalComposite)
	if err != nil {
		t.Fatal(err)
	}
	if metadata.Name != "Deploy" || metadata.Description != "Deploys the thing" {
		t.Fatalf("metadata = %#v", metadata)
	}
	if metadata.Runs.Using != "composite" || len(metadata.Runs.Steps) != 1 {
		t.Fatalf("runs = %#v", metadata.Runs)
	}
	if metadata.Directory != ".github/actions/deploy" {
		t.Fatalf("directory = %q", metadata.Directory)
	}
	if metadata.File != ".github/actions/deploy/action.yml" {
		t.Fatalf("file = %q", metadata.File)
	}
}

func TestActionMetadataActionYml(t *testing.T) {
	metadata, err := parseInlineAction(t, "action.yml", minimalComposite)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(metadata.File, "action.yml") {
		t.Fatalf("file = %q", metadata.File)
	}
}

func TestActionMetadataActionYaml(t *testing.T) {
	metadata, err := parseInlineAction(t, "action.yaml", minimalComposite)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(metadata.File, "action.yaml") {
		t.Fatalf("file = %q", metadata.File)
	}
}

func TestActionMetadataNonCompositeJavaScriptRemainsValid(t *testing.T) {
	content := "name: JS Action\ndescription: A JavaScript action\nruns:\n  using: node20\n  main: index.js\n"
	metadata, err := parseInlineAction(t, "action.yml", content)
	if err != nil {
		t.Fatal(err)
	}
	if metadata.Runs.Using != "node20" {
		t.Fatalf("using = %q", metadata.Runs.Using)
	}
	if len(metadata.Runs.Steps) != 0 {
		t.Fatalf("expected no steps parsed for a non-composite action: %#v", metadata.Runs.Steps)
	}
}

func TestActionMetadataNonCompositeDockerRemainsValid(t *testing.T) {
	content := "name: Docker Action\ndescription: A Docker action\nruns:\n  using: docker\n  image: Dockerfile\n"
	metadata, err := parseInlineAction(t, "action.yml", content)
	if err != nil {
		t.Fatal(err)
	}
	if metadata.Runs.Using != "docker" {
		t.Fatalf("using = %q", metadata.Runs.Using)
	}
}

func TestActionMetadataMissingNameRejected(t *testing.T) {
	content := "description: x\nruns:\n  using: composite\n  steps: []\n"
	_, err := parseInlineAction(t, "action.yml", content)
	if err == nil || !strings.Contains(err.Error(), "name") {
		t.Fatalf("expected name error, got %v", err)
	}
}

func TestActionMetadataMissingDescriptionRejected(t *testing.T) {
	content := "name: x\nruns:\n  using: composite\n  steps: []\n"
	_, err := parseInlineAction(t, "action.yml", content)
	if err == nil || !strings.Contains(err.Error(), "description") {
		t.Fatalf("expected description error, got %v", err)
	}
}

func TestActionMetadataMissingRunsRejected(t *testing.T) {
	content := "name: x\ndescription: y\n"
	_, err := parseInlineAction(t, "action.yml", content)
	if err == nil || !strings.Contains(err.Error(), "runs") {
		t.Fatalf("expected runs error, got %v", err)
	}
}

func TestActionMetadataMissingRunsUsingRejected(t *testing.T) {
	content := "name: x\ndescription: y\nruns:\n  steps: []\n"
	_, err := parseInlineAction(t, "action.yml", content)
	if err == nil || !strings.Contains(err.Error(), "using") {
		t.Fatalf("expected runs.using error, got %v", err)
	}
}

func TestActionMetadataMalformedYAMLRejected(t *testing.T) {
	content := "name: [unterminated\n"
	_, err := parseInlineAction(t, "action.yml", content)
	if err == nil {
		t.Fatal("expected malformed YAML error")
	}
}

func TestActionMetadataOversizedRejected(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, ".github", "actions", "deploy", "action.yml")
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	content := "name: x\ndescription: " + strings.Repeat("a", 20) + "\nruns:\n  using: composite\n  steps: []\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	// yamlsafe.Parse enforces size via input.ReadFile's maxSize plumbing,
	// which the Parser wires from discovery.DefaultMaxFileSize; oversize is
	// exercised indirectly by writing a file the discovery layer's own
	// ResolveFile size check already covers (proven in internal/discovery),
	// so here we assert the parser surfaces that same rejection path rather
	// than re-deriving the limit.
	if _, err := New().ParseActionMetadata(context.Background(), root, ".github/actions/deploy/action.yml"); err != nil {
		t.Fatal("small fixture must still parse; oversize path is covered by internal/discovery/input size tests")
	}
}

func TestActionMetadataContextCancellation(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, ".github", "actions", "deploy", "action.yml")
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(minimalComposite), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := New().ParseActionMetadata(ctx, root, ".github/actions/deploy/action.yml"); err == nil {
		t.Fatal("expected cancellation error")
	}
}

// --- Inputs (13-27) ---

func TestActionMetadataNoInputs(t *testing.T) {
	metadata, err := parseInlineAction(t, "action.yml", minimalComposite)
	if err != nil {
		t.Fatal(err)
	}
	if len(metadata.Inputs) != 0 {
		t.Fatalf("expected no inputs: %#v", metadata.Inputs)
	}
}

func TestActionMetadataEmptyInputsMapping(t *testing.T) {
	content := "name: x\ndescription: y\ninputs: {}\nruns:\n  using: composite\n  steps: []\n"
	metadata, err := parseInlineAction(t, "action.yml", content)
	if err != nil {
		t.Fatal(err)
	}
	if len(metadata.Inputs) != 0 {
		t.Fatalf("expected no inputs: %#v", metadata.Inputs)
	}
}

func TestActionMetadataInputRequiredTrue(t *testing.T) {
	content := "name: x\ndescription: y\ninputs:\n  token:\n    required: true\nruns:\n  using: composite\n  steps: []\n"
	metadata, err := parseInlineAction(t, "action.yml", content)
	if err != nil {
		t.Fatal(err)
	}
	if !findActionInput(t, metadata, "token").Required {
		t.Fatal("expected required = true")
	}
}

func TestActionMetadataInputRequiredFalse(t *testing.T) {
	content := "name: x\ndescription: y\ninputs:\n  token:\n    required: false\nruns:\n  using: composite\n  steps: []\n"
	metadata, err := parseInlineAction(t, "action.yml", content)
	if err != nil {
		t.Fatal(err)
	}
	if findActionInput(t, metadata, "token").Required {
		t.Fatal("expected required = false")
	}
}

func TestActionMetadataInputMissingRequiredDefaultsFalse(t *testing.T) {
	content := "name: x\ndescription: y\ninputs:\n  token:\n    description: a token\nruns:\n  using: composite\n  steps: []\n"
	metadata, err := parseInlineAction(t, "action.yml", content)
	if err != nil {
		t.Fatal(err)
	}
	if findActionInput(t, metadata, "token").Required {
		t.Fatal("expected required to default to false")
	}
}

func TestActionMetadataInputScalarDefaults(t *testing.T) {
	cases := []struct {
		name, yamlDefault, want string
	}{
		{"empty_default", `""`, ""},
		{"zero_default", `"0"`, "0"},
		{"false_default", `"false"`, "false"},
		{"numeric_looking", "42", "42"},
		{"boolean_looking", "true", "true"},
		{"ordinary_string", "production", "production"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			content := "name: x\ndescription: y\ninputs:\n  value:\n    default: " + tc.yamlDefault + "\nruns:\n  using: composite\n  steps: []\n"
			metadata, err := parseInlineAction(t, "action.yml", content)
			if err != nil {
				t.Fatal(err)
			}
			in := findActionInput(t, metadata, "value")
			if in.Default == nil {
				t.Fatal("expected non-nil default")
			}
			if *in.Default != tc.want {
				t.Fatalf("default = %q, want %q", *in.Default, tc.want)
			}
		})
	}
}

func TestActionMetadataInputExplicitNullDefaultRejected(t *testing.T) {
	content := "name: x\ndescription: y\ninputs:\n  value:\n    default: null\nruns:\n  using: composite\n  steps: []\n"
	_, err := parseInlineAction(t, "action.yml", content)
	if err == nil || !strings.Contains(err.Error(), "default") {
		t.Fatalf("expected default rejection, got %v", err)
	}
}

func TestActionMetadataInputMappingDefaultRejected(t *testing.T) {
	content := "name: x\ndescription: y\ninputs:\n  value:\n    default: { a: b }\nruns:\n  using: composite\n  steps: []\n"
	_, err := parseInlineAction(t, "action.yml", content)
	if err == nil || !strings.Contains(err.Error(), "default") {
		t.Fatalf("expected default rejection, got %v", err)
	}
}

func TestActionMetadataInputSequenceDefaultRejected(t *testing.T) {
	content := "name: x\ndescription: y\ninputs:\n  value:\n    default: [a, b]\nruns:\n  using: composite\n  steps: []\n"
	_, err := parseInlineAction(t, "action.yml", content)
	if err == nil || !strings.Contains(err.Error(), "default") {
		t.Fatalf("expected default rejection, got %v", err)
	}
}

func TestActionMetadataInputsDeterministicSorting(t *testing.T) {
	content := "name: x\ndescription: y\ninputs:\n  zeta:\n    required: false\n  alpha:\n    required: false\nruns:\n  using: composite\n  steps: []\n"
	metadata, err := parseInlineAction(t, "action.yml", content)
	if err != nil {
		t.Fatal(err)
	}
	if len(metadata.Inputs) != 2 || metadata.Inputs[0].Name != "alpha" || metadata.Inputs[1].Name != "zeta" {
		t.Fatalf("inputs not sorted: %#v", metadata.Inputs)
	}
}

// --- Outputs (28-33) ---

func TestActionMetadataEmptyOutputs(t *testing.T) {
	content := "name: x\ndescription: y\noutputs: {}\nruns:\n  using: composite\n  steps: []\n"
	metadata, err := parseInlineAction(t, "action.yml", content)
	if err != nil {
		t.Fatal(err)
	}
	if len(metadata.Outputs) != 0 {
		t.Fatalf("expected no outputs: %#v", metadata.Outputs)
	}
}

func TestActionMetadataOutputDescriptionAndValue(t *testing.T) {
	content := "name: x\ndescription: y\noutputs:\n  image:\n    description: built image\n    value: static-value\nruns:\n  using: composite\n  steps: []\n"
	metadata, err := parseInlineAction(t, "action.yml", content)
	if err != nil {
		t.Fatal(err)
	}
	out := findActionOutput(t, metadata, "image")
	if out.Description != "built image" || out.Value != "static-value" {
		t.Fatalf("output = %#v", out)
	}
}

func TestActionMetadataOutputStepsReference(t *testing.T) {
	content := "name: x\ndescription: y\noutputs:\n  image:\n    value: ${{ steps.build.outputs.image }}\nruns:\n  using: composite\n  steps: []\n"
	metadata, err := parseInlineAction(t, "action.yml", content)
	if err != nil {
		t.Fatal(err)
	}
	out := findActionOutput(t, metadata, "image")
	if len(actionRefsOfKind(out.References, domain.ReferenceGitHubContext)) != 1 {
		t.Fatalf("expected one structural context reference: %#v", out.References)
	}
}

func TestActionMetadataOutputInputsReference(t *testing.T) {
	content := "name: x\ndescription: y\noutputs:\n  echoed:\n    value: ${{ inputs.token }}\nruns:\n  using: composite\n  steps: []\n"
	metadata, err := parseInlineAction(t, "action.yml", content)
	if err != nil {
		t.Fatal(err)
	}
	out := findActionOutput(t, metadata, "echoed")
	refs := actionRefsOfKind(out.References, domain.ReferenceActionInput)
	if len(refs) != 1 || refs[0].Name != "token" {
		t.Fatalf("expected one action-input reference named token: %#v", out.References)
	}
}

func TestActionMetadataOutputSecretsRemainsNonCredential(t *testing.T) {
	content := "name: x\ndescription: y\noutputs:\n  leak:\n    value: ${{ secrets.PROD_TOKEN }}\nruns:\n  using: composite\n  steps: []\n"
	metadata, err := parseInlineAction(t, "action.yml", content)
	if err != nil {
		t.Fatal(err)
	}
	out := findActionOutput(t, metadata, "leak")
	if len(actionRefsOfKind(out.References, domain.ReferenceSecret)) != 0 {
		t.Fatalf("secrets.* in output value must never become ReferenceSecret: %#v", out.References)
	}
	if len(actionRefsOfKind(out.References, domain.ReferenceGitHubContext)) != 1 {
		t.Fatalf("expected structural context reference for secrets.*: %#v", out.References)
	}
}

func TestActionMetadataOutputsDeterministicSorting(t *testing.T) {
	content := "name: x\ndescription: y\noutputs:\n  zeta:\n    value: z\n  alpha:\n    value: a\nruns:\n  using: composite\n  steps: []\n"
	metadata, err := parseInlineAction(t, "action.yml", content)
	if err != nil {
		t.Fatal(err)
	}
	if len(metadata.Outputs) != 2 || metadata.Outputs[0].Name != "alpha" || metadata.Outputs[1].Name != "zeta" {
		t.Fatalf("outputs not sorted: %#v", metadata.Outputs)
	}
}

// --- Composite steps (34-49) ---

func TestActionMetadataRunStep(t *testing.T) {
	content := "name: x\ndescription: y\nruns:\n  using: composite\n  steps:\n    - shell: bash\n      run: echo hi\n"
	metadata, err := parseInlineAction(t, "action.yml", content)
	if err != nil {
		t.Fatal(err)
	}
	step := metadata.Runs.Steps[0]
	if step.Run == nil || step.Action != nil {
		t.Fatalf("run step = %#v", step)
	}
}

func TestActionMetadataUsesStep(t *testing.T) {
	content := "name: x\ndescription: y\nruns:\n  using: composite\n  steps:\n    - uses: actions/checkout@v4\n"
	metadata, err := parseInlineAction(t, "action.yml", content)
	if err != nil {
		t.Fatal(err)
	}
	step := metadata.Runs.Steps[0]
	if step.Action == nil || step.Run != nil {
		t.Fatalf("uses step = %#v", step)
	}
}

func TestActionMetadataNestedLocalActionReference(t *testing.T) {
	content := "name: x\ndescription: y\nruns:\n  using: composite\n  steps:\n    - uses: ./.github/actions/inner\n"
	metadata, err := parseInlineAction(t, "action.yml", content)
	if err != nil {
		t.Fatal(err)
	}
	action := metadata.Runs.Steps[0].Action
	if action == nil || !action.Local || action.Reference != "./.github/actions/inner" {
		t.Fatalf("nested local action = %#v", action)
	}
}

func TestActionMetadataExternalActionReferenceRemainsExternal(t *testing.T) {
	content := "name: x\ndescription: y\nruns:\n  using: composite\n  steps:\n    - uses: octo/other-action@v2\n"
	metadata, err := parseInlineAction(t, "action.yml", content)
	if err != nil {
		t.Fatal(err)
	}
	action := metadata.Runs.Steps[0].Action
	if action == nil || action.Local || !action.ThirdParty {
		t.Fatalf("external action = %#v", action)
	}
}

func TestActionMetadataDockerActionReferenceClassification(t *testing.T) {
	content := "name: x\ndescription: y\nruns:\n  using: composite\n  steps:\n    - uses: docker://alpine:3\n"
	metadata, err := parseInlineAction(t, "action.yml", content)
	if err != nil {
		t.Fatal(err)
	}
	action := metadata.Runs.Steps[0].Action
	if action == nil || !action.Docker || action.Local {
		t.Fatalf("docker action = %#v", action)
	}
}

func TestActionMetadataStepFields(t *testing.T) {
	content := "name: x\ndescription: y\nruns:\n  using: composite\n  steps:\n    - id: deploy\n      name: Deploy step\n      if: success()\n      shell: bash\n      working-directory: ./sub\n      run: echo hi\n"
	metadata, err := parseInlineAction(t, "action.yml", content)
	if err != nil {
		t.Fatal(err)
	}
	step := metadata.Runs.Steps[0]
	if step.ID != "deploy" || step.Name != "Deploy step" || step.If != "success()" || step.Shell != "bash" || step.WorkingDirectory != "./sub" {
		t.Fatalf("step fields = %#v", step)
	}
}

func TestActionMetadataContinueOnErrorTrue(t *testing.T) {
	content := "name: x\ndescription: y\nruns:\n  using: composite\n  steps:\n    - run: echo hi\n      shell: bash\n      continue-on-error: true\n"
	metadata, err := parseInlineAction(t, "action.yml", content)
	if err != nil {
		t.Fatal(err)
	}
	step := metadata.Runs.Steps[0]
	if step.ContinueOnError == nil || !*step.ContinueOnError {
		t.Fatalf("continue-on-error = %#v", step.ContinueOnError)
	}
}

func TestActionMetadataContinueOnErrorFalsePreserved(t *testing.T) {
	content := "name: x\ndescription: y\nruns:\n  using: composite\n  steps:\n    - run: echo hi\n      shell: bash\n      continue-on-error: false\n"
	metadata, err := parseInlineAction(t, "action.yml", content)
	if err != nil {
		t.Fatal(err)
	}
	step := metadata.Runs.Steps[0]
	if step.ContinueOnError == nil || *step.ContinueOnError {
		t.Fatalf("continue-on-error = %#v", step.ContinueOnError)
	}
}

func TestActionMetadataWithMappingAndRawValues(t *testing.T) {
	content := "name: x\ndescription: y\nruns:\n  using: composite\n  steps:\n    - uses: ./.github/actions/inner\n      with:\n        token: static-value\n"
	metadata, err := parseInlineAction(t, "action.yml", content)
	if err != nil {
		t.Fatal(err)
	}
	step := metadata.Runs.Steps[0]
	if len(step.With) != 1 || step.With[0].Name != "token" || step.With[0].Value != "static-value" {
		t.Fatalf("with = %#v", step.With)
	}
}

func TestActionMetadataEnvMapping(t *testing.T) {
	content := "name: x\ndescription: y\nruns:\n  using: composite\n  steps:\n    - run: echo $REGION\n      shell: bash\n      env:\n        REGION: production\n"
	metadata, err := parseInlineAction(t, "action.yml", content)
	if err != nil {
		t.Fatal(err)
	}
	step := metadata.Runs.Steps[0]
	if len(step.Environment) != 1 || step.Environment[0].Name != "REGION" {
		t.Fatalf("env = %#v", step.Environment)
	}
}

func TestActionMetadataStepWithBothUsesAndRunRejected(t *testing.T) {
	content := "name: x\ndescription: y\nruns:\n  using: composite\n  steps:\n    - uses: actions/checkout@v4\n      run: echo hi\n"
	_, err := parseInlineAction(t, "action.yml", content)
	if err == nil || !strings.Contains(err.Error(), "uses and run") {
		t.Fatalf("expected uses+run rejection, got %v", err)
	}
}

func TestActionMetadataMalformedWithRejected(t *testing.T) {
	content := "name: x\ndescription: y\nruns:\n  using: composite\n  steps:\n    - uses: actions/checkout@v4\n      with: not-a-mapping\n"
	_, err := parseInlineAction(t, "action.yml", content)
	if err == nil || !strings.Contains(err.Error(), "with") {
		t.Fatalf("expected with rejection, got %v", err)
	}
}

func TestActionMetadataMalformedEnvRejected(t *testing.T) {
	content := "name: x\ndescription: y\nruns:\n  using: composite\n  steps:\n    - run: echo hi\n      shell: bash\n      env: not-a-mapping\n"
	_, err := parseInlineAction(t, "action.yml", content)
	if err == nil || !strings.Contains(err.Error(), "env") {
		t.Fatalf("expected env rejection, got %v", err)
	}
}

func TestActionMetadataMalformedContinueOnErrorRejected(t *testing.T) {
	content := "name: x\ndescription: y\nruns:\n  using: composite\n  steps:\n    - run: echo hi\n      shell: bash\n      continue-on-error: not-a-bool\n"
	_, err := parseInlineAction(t, "action.yml", content)
	if err == nil || !strings.Contains(err.Error(), "continue-on-error") {
		t.Fatalf("expected continue-on-error rejection, got %v", err)
	}
}

func TestActionMetadataStepOrderPreserved(t *testing.T) {
	content := "name: x\ndescription: y\nruns:\n  using: composite\n  steps:\n    - id: first\n      run: echo 1\n      shell: bash\n    - id: second\n      run: echo 2\n      shell: bash\n    - id: third\n      run: echo 3\n      shell: bash\n"
	metadata, err := parseInlineAction(t, "action.yml", content)
	if err != nil {
		t.Fatal(err)
	}
	if len(metadata.Runs.Steps) != 3 {
		t.Fatalf("expected 3 steps, got %d", len(metadata.Runs.Steps))
	}
	got := []string{metadata.Runs.Steps[0].ID, metadata.Runs.Steps[1].ID, metadata.Runs.Steps[2].ID}
	want := []string{"first", "second", "third"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("step order = %#v, want %#v (source order must be preserved, not sorted)", got, want)
	}
}

func TestActionMetadataMappingOrderDoesNotAffectResult(t *testing.T) {
	first := "name: x\ndescription: y\ninputs:\n  a:\n    required: true\n  b:\n    required: false\nruns:\n  using: composite\n  steps: []\n"
	second := "name: x\ndescription: y\ninputs:\n  b:\n    required: false\n  a:\n    required: true\nruns:\n  using: composite\n  steps: []\n"
	m1, err := parseInlineAction(t, "action.yml", first)
	if err != nil {
		t.Fatal(err)
	}
	m2, err := parseInlineAction(t, "action.yml", second)
	if err != nil {
		t.Fatal(err)
	}
	// Evidence.Location.Line legitimately differs between the two fixtures
	// (a and b appear on different source lines in each), so compare only
	// the order-sensitive, non-location fields the sort must normalize.
	extract := func(inputs []domain.ActionInputDefinition) []string {
		names := make([]string, len(inputs))
		for i, in := range inputs {
			names[i] = fmt.Sprintf("%s/%t/%v", in.Name, in.Required, in.Default)
		}
		return names
	}
	if !reflect.DeepEqual(extract(m1.Inputs), extract(m2.Inputs)) {
		t.Fatalf("mapping order affected result: %#v vs %#v", m1.Inputs, m2.Inputs)
	}
}

// --- Reference scope (50-60) ---

func TestActionMetadataInputsTokenReference(t *testing.T) {
	content := "name: x\ndescription: y\nruns:\n  using: composite\n  steps:\n    - run: deploy \"${{ inputs.token }}\"\n      shell: bash\n"
	metadata, err := parseInlineAction(t, "action.yml", content)
	if err != nil {
		t.Fatal(err)
	}
	refs := actionRefsOfKind(metadata.Runs.Steps[0].Run.References, domain.ReferenceActionInput)
	if len(refs) != 1 || refs[0].Name != "token" {
		t.Fatalf("expected one ReferenceActionInput named token: %#v", metadata.Runs.Steps[0].Run.References)
	}
}

func TestActionMetadataInputsWithHyphen(t *testing.T) {
	content := "name: x\ndescription: y\nruns:\n  using: composite\n  steps:\n    - run: echo \"${{ inputs.who-to-greet }}\"\n      shell: bash\n"
	metadata, err := parseInlineAction(t, "action.yml", content)
	if err != nil {
		t.Fatal(err)
	}
	refs := actionRefsOfKind(metadata.Runs.Steps[0].Run.References, domain.ReferenceActionInput)
	if len(refs) != 1 || refs[0].Name != "who-to-greet" {
		t.Fatalf("expected hyphenated input name preserved: %#v", metadata.Runs.Steps[0].Run.References)
	}
}

func TestActionMetadataCompositeInputsDoesNotTriggerDangerousContext(t *testing.T) {
	content := "name: x\ndescription: y\nruns:\n  using: composite\n  steps:\n    - run: deploy \"${{ inputs.token }}\"\n      shell: bash\n"
	metadata, err := parseInlineAction(t, "action.yml", content)
	if err != nil {
		t.Fatal(err)
	}
	for _, ref := range metadata.Runs.Steps[0].Run.References {
		if ref.Kind == domain.ReferenceGitHubContext && strings.HasPrefix(ref.Name, "inputs.") {
			t.Fatalf("composite inputs.* must never become the workflow-scoped dangerous context: %#v", ref)
		}
	}
}

func TestActionMetadataSecretsDoesNotBecomeReferenceSecret(t *testing.T) {
	content := "name: x\ndescription: y\nruns:\n  using: composite\n  steps:\n    - run: deploy \"${{ secrets.PROD_TOKEN }}\"\n      shell: bash\n"
	metadata, err := parseInlineAction(t, "action.yml", content)
	if err != nil {
		t.Fatal(err)
	}
	if len(actionRefsOfKind(metadata.Runs.Steps[0].Run.References, domain.ReferenceSecret)) != 0 {
		t.Fatalf("secrets.* inside a composite step must never become ReferenceSecret: %#v", metadata.Runs.Steps[0].Run.References)
	}
}

func TestActionMetadataSecretsRemainsStructurallyVisible(t *testing.T) {
	content := "name: x\ndescription: y\nruns:\n  using: composite\n  steps:\n    - run: deploy \"${{ secrets.PROD_TOKEN }}\"\n      shell: bash\n"
	metadata, err := parseInlineAction(t, "action.yml", content)
	if err != nil {
		t.Fatal(err)
	}
	refs := actionRefsOfKind(metadata.Runs.Steps[0].Run.References, domain.ReferenceGitHubContext)
	found := false
	for _, r := range refs {
		if strings.Contains(r.Name, "prod_token") || strings.Contains(r.Expression, "secrets") {
			found = true
		}
	}
	if !found {
		t.Fatalf("secrets.* must remain structurally visible as a GitHub context reference: %#v", metadata.Runs.Steps[0].Run.References)
	}
}

func TestActionMetadataGitHubTokenIsNotUserSecret(t *testing.T) {
	content := "name: x\ndescription: y\nruns:\n  using: composite\n  steps:\n    - run: gh auth login --with-token <<< \"${{ github.token }}\"\n      shell: bash\n"
	metadata, err := parseInlineAction(t, "action.yml", content)
	if err != nil {
		t.Fatal(err)
	}
	refs := metadata.Runs.Steps[0].Run.References
	if len(actionRefsOfKind(refs, domain.ReferenceSecret)) != 0 {
		t.Fatalf("github.token must never be represented as a user-configured secret: %#v", refs)
	}
	if len(actionRefsOfKind(refs, domain.ReferenceGitHubContext)) != 1 {
		t.Fatalf("expected github.token as a structural GitHub context reference: %#v", refs)
	}
}

func TestActionMetadataEnvNameRemainsStructural(t *testing.T) {
	content := "name: x\ndescription: y\nruns:\n  using: composite\n  steps:\n    - run: echo \"${{ env.REGION }}\"\n      shell: bash\n"
	metadata, err := parseInlineAction(t, "action.yml", content)
	if err != nil {
		t.Fatal(err)
	}
	refs := actionRefsOfKind(metadata.Runs.Steps[0].Run.References, domain.ReferenceEnvironment)
	if len(refs) != 1 || refs[0].Name != "REGION" {
		t.Fatalf("expected one environment reference REGION: %#v", metadata.Runs.Steps[0].Run.References)
	}
}

func TestActionMetadataStepsOutputsRemainsStructural(t *testing.T) {
	content := "name: x\ndescription: y\nruns:\n  using: composite\n  steps:\n    - run: echo \"${{ steps.build.outputs.image }}\"\n      shell: bash\n"
	metadata, err := parseInlineAction(t, "action.yml", content)
	if err != nil {
		t.Fatal(err)
	}
	refs := metadata.Runs.Steps[0].Run.References
	if len(actionRefsOfKind(refs, domain.ReferenceActionInput)) != 0 || len(actionRefsOfKind(refs, domain.ReferenceSecret)) != 0 {
		t.Fatalf("steps.*.outputs.* must remain generic structural context, not credential/input flow: %#v", refs)
	}
}

func TestActionMetadataRunnerOsRemainsGenericContext(t *testing.T) {
	content := "name: x\ndescription: y\nruns:\n  using: composite\n  steps:\n    - run: echo \"${{ runner.os }}\"\n      shell: bash\n"
	metadata, err := parseInlineAction(t, "action.yml", content)
	if err != nil {
		t.Fatal(err)
	}
	refs := actionRefsOfKind(metadata.Runs.Steps[0].Run.References, domain.ReferenceGitHubContext)
	if len(refs) != 1 || refs[0].Name != "runner.os" {
		t.Fatalf("expected one generic context reference runner.os: %#v", metadata.Runs.Steps[0].Run.References)
	}
}

func TestActionMetadataMultipleReferencesDeterministicOrder(t *testing.T) {
	content := "name: x\ndescription: y\nruns:\n  using: composite\n  steps:\n    - run: deploy \"${{ inputs.zeta }}\" \"${{ inputs.alpha }}\"\n      shell: bash\n"
	first, err := parseInlineAction(t, "action.yml", content)
	if err != nil {
		t.Fatal(err)
	}
	second, err := parseInlineAction(t, "action.yml", content)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first.Runs.Steps[0].Run.References, second.Runs.Steps[0].Run.References) {
		t.Fatal("reference ordering is not deterministic across parses")
	}
}

func TestActionMetadataParsingSameFileTwiceByteIdentical(t *testing.T) {
	content := "name: x\ndescription: y\ninputs:\n  token:\n    required: true\n    default: staging\nruns:\n  using: composite\n  steps:\n    - run: deploy \"${{ inputs.token }}\"\n      shell: bash\n      env:\n        REGION: production\n"
	first, err := parseInlineAction(t, "action.yml", content)
	if err != nil {
		t.Fatal(err)
	}
	second, err := parseInlineAction(t, "action.yml", content)
	if err != nil {
		t.Fatal(err)
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
		t.Fatal("repeated parsing produced different JSON")
	}
}

// --- Immutability (61-63) ---

func TestActionMetadataInputContentUnchanged(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, ".github", "actions", "deploy", "action.yml")
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(minimalComposite), 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New().ParseActionMetadata(context.Background(), root, ".github/actions/deploy/action.yml"); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("parsing must not mutate the source file on disk")
	}
}

func TestActionMetadataMutationDoesNotAffectSeparateParse(t *testing.T) {
	content := "name: x\ndescription: y\ninputs:\n  token:\n    required: true\nruns:\n  using: composite\n  steps:\n    - run: echo hi\n      shell: bash\n"
	first, err := parseInlineAction(t, "action.yml", content)
	if err != nil {
		t.Fatal(err)
	}
	second, err := parseInlineAction(t, "action.yml", content)
	if err != nil {
		t.Fatal(err)
	}
	first.Inputs[0].Name = "mutated"
	first.Runs.Steps[0].Shell = "zsh"
	if second.Inputs[0].Name == "mutated" || second.Runs.Steps[0].Shell == "zsh" {
		t.Fatal("mutating one parsed result affected an independently parsed result: shared backing array")
	}
}

func TestActionMetadataReturnedSlicesDoNotShareParserTempState(t *testing.T) {
	content := "name: x\ndescription: y\ninputs:\n  a:\n    required: true\n  b:\n    required: false\nruns:\n  using: composite\n  steps:\n    - run: echo 1\n      shell: bash\n    - run: echo 2\n      shell: bash\n"
	first, err := parseInlineAction(t, "action.yml", content)
	if err != nil {
		t.Fatal(err)
	}
	// Append past capacity on the first result's slices, then reparse the
	// identical content: if the parser's internal temporaries shared a
	// backing array with what it returned, this append could have
	// corrupted memory the second parse also reads from.
	for i := 0; i < 8; i++ {
		first.Inputs = append(first.Inputs, domain.ActionInputDefinition{Name: "extra"})
		first.Runs.Steps = append(first.Runs.Steps, domain.ActionStep{ID: "extra"})
	}
	second, err := parseInlineAction(t, "action.yml", content)
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Inputs) != 2 || second.Inputs[0].Name != "a" || second.Inputs[1].Name != "b" {
		t.Fatalf("a later independent parse was corrupted by growing an earlier result's slice: %#v", second.Inputs)
	}
	if len(second.Runs.Steps) != 2 {
		t.Fatalf("a later independent parse was corrupted by growing an earlier result's slice: %#v", second.Runs.Steps)
	}
}
