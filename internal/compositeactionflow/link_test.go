package compositeactionflow

import (
	"context"
	"testing"

	"github.com/Bavlik/CredScope/internal/domain"
)

const testDirectory = ".github/actions/deploy"

func loc(line int) domain.Location { return domain.Location{Path: "caller.yml", Line: line} }

func ev(line int, field string) domain.Evidence {
	return domain.Evidence{Location: loc(line), Field: field, Confidence: domain.ConfidenceConfirmed}
}

func secretRef(name string, line int) domain.Reference {
	return domain.Reference{Kind: domain.ReferenceSecret, Name: name, Evidence: ev(line, "with."+name)}
}

func binding(name, value string, refs ...domain.Reference) domain.ActionCallInputBinding {
	return domain.ActionCallInputBinding{Name: name, Value: value, References: refs, Evidence: ev(1, "with."+name)}
}

func cleanSecretBinding(name, secretName string) domain.ActionCallInputBinding {
	return binding(name, "${{ secrets."+secretName+" }}", secretRef(secretName, 1))
}

func inputDef(name string, required bool, def *string) domain.ActionInputDefinition {
	return domain.ActionInputDefinition{Name: name, Required: required, Default: def, Evidence: ev(1, "inputs."+name)}
}

func actionInputRef(name string, line int) domain.Reference {
	return domain.Reference{Kind: domain.ReferenceActionInput, Name: name, Evidence: ev(line, "runs.steps")}
}

func actionStep(id string, refs ...domain.Reference) domain.ActionStep {
	return domain.ActionStep{ID: id, References: refs}
}

func canonicalAction(directory string, inputs []domain.ActionInputDefinition, steps ...domain.ActionStep) domain.ActionMetadata {
	return domain.ActionMetadata{
		Directory: directory, Name: "Deploy",
		Inputs: inputs,
		Runs:   domain.ActionRuns{Using: "composite", Steps: steps},
	}
}

func resolvedCall(workflow, jobID string, stepIndex int, stepID, directory string) domain.CompositeActionCall {
	return domain.CompositeActionCall{
		CallerWorkflow: workflow, CallerJobID: jobID, CallerStepIndex: stepIndex, CallerStepID: stepID,
		CanonicalDirectory: directory, Status: domain.CompositeActionResolvedLocalComposite,
	}
}

func stepWithBindings(id string, bindings ...domain.ActionCallInputBinding) domain.WorkflowStep {
	return domain.WorkflowStep{ID: id, With: bindings}
}

func workflow(file string, jobs ...domain.WorkflowJob) domain.Workflow {
	return domain.Workflow{File: file, Jobs: jobs}
}

func job(id string, steps ...domain.WorkflowStep) domain.WorkflowJob {
	return domain.WorkflowJob{ID: id, Steps: steps}
}

func findFlow(t *testing.T, flows []ConfirmedInputFlow, inputName string) ConfirmedInputFlow {
	t.Helper()
	for _, flow := range flows {
		if flow.InputName == inputName {
			return flow
		}
	}
	t.Fatalf("flow for input %q not found in %#v", inputName, flows)
	return ConfirmedInputFlow{}
}

func hasDiagnostic(diagnostics []Diagnostic, kind DiagnosticKind, inputName string) bool {
	for _, d := range diagnostics {
		if d.Kind == kind && d.InputName == inputName {
			return true
		}
	}
	return false
}

// 22. exact static secret binding to declared used input.
func TestLinkExactStaticSecretBinding(t *testing.T) {
	action := canonicalAction(testDirectory, []domain.ActionInputDefinition{inputDef("token", true, nil)}, actionStep("deploy", actionInputRef("token", 10)))
	wf := workflow("caller.yml", job("deploy", stepWithBindings("s", cleanSecretBinding("token", "PROD_TOKEN"))))
	resolution := domain.CompositeActionResolution{Actions: []domain.ActionMetadata{action}, Calls: []domain.CompositeActionCall{resolvedCall("caller.yml", "deploy", 0, "s", testDirectory)}}

	result, err := Link(context.Background(), []domain.Workflow{wf}, resolution)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Flows) != 1 {
		t.Fatalf("expected exactly one flow, got %#v", result.Flows)
	}
	flow := result.Flows[0]
	if flow.SourceSecret != "PROD_TOKEN" || flow.InputName != "token" || flow.CanonicalDirectory != testDirectory {
		t.Fatalf("unexpected flow: %#v", flow)
	}
	if len(flow.Usages) != 1 || flow.Usages[0].ActionStepIndex != 0 || flow.Usages[0].ActionStepID != "deploy" {
		t.Fatalf("unexpected usages: %#v", flow.Usages)
	}
	if len(result.Diagnostics) != 0 {
		t.Fatalf("expected no diagnostics, got %#v", result.Diagnostics)
	}
}

// 23. surrounding whitespace accepted.
func TestLinkSurroundingWhitespaceAccepted(t *testing.T) {
	action := canonicalAction(testDirectory, []domain.ActionInputDefinition{inputDef("token", true, nil)}, actionStep("deploy", actionInputRef("token", 10)))
	b := binding("token", "${{   secrets.PROD_TOKEN   }}", secretRef("PROD_TOKEN", 1))
	wf := workflow("caller.yml", job("deploy", stepWithBindings("s", b)))
	resolution := domain.CompositeActionResolution{Actions: []domain.ActionMetadata{action}, Calls: []domain.CompositeActionCall{resolvedCall("caller.yml", "deploy", 0, "s", testDirectory)}}

	result, err := Link(context.Background(), []domain.Workflow{wf}, resolution)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Flows) != 1 {
		t.Fatalf("expected whitespace-padded expression to confirm, got flows=%#v diagnostics=%#v", result.Flows, result.Diagnostics)
	}
}

func setupUnsupported(t *testing.T, value string, refs ...domain.Reference) Result {
	t.Helper()
	action := canonicalAction(testDirectory, []domain.ActionInputDefinition{inputDef("token", true, nil)}, actionStep("deploy", actionInputRef("token", 10)))
	b := binding("token", value, refs...)
	wf := workflow("caller.yml", job("deploy", stepWithBindings("s", b)))
	resolution := domain.CompositeActionResolution{Actions: []domain.ActionMetadata{action}, Calls: []domain.CompositeActionCall{resolvedCall("caller.yml", "deploy", 0, "s", testDirectory)}}
	result, err := Link(context.Background(), []domain.Workflow{wf}, resolution)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

// 24. prefix plus secret not confirmed.
func TestLinkPrefixPlusSecretNotConfirmed(t *testing.T) {
	result := setupUnsupported(t, "prefix-${{ secrets.PROD_TOKEN }}", secretRef("PROD_TOKEN", 1))
	if len(result.Flows) != 0 {
		t.Fatalf("expected no confirmed flow, got %#v", result.Flows)
	}
	if !hasDiagnostic(result.Diagnostics, DiagnosticUnsupportedSecretExpression, "token") {
		t.Fatalf("expected unsupported_secret_expression diagnostic, got %#v", result.Diagnostics)
	}
}

// 25. secret plus suffix not confirmed.
func TestLinkSecretPlusSuffixNotConfirmed(t *testing.T) {
	result := setupUnsupported(t, "${{ secrets.PROD_TOKEN }}-suffix", secretRef("PROD_TOKEN", 1))
	if len(result.Flows) != 0 {
		t.Fatalf("expected no confirmed flow, got %#v", result.Flows)
	}
	if !hasDiagnostic(result.Diagnostics, DiagnosticUnsupportedSecretExpression, "token") {
		t.Fatalf("expected unsupported_secret_expression diagnostic, got %#v", result.Diagnostics)
	}
}

// 26. format function not confirmed.
func TestLinkFormatFunctionNotConfirmed(t *testing.T) {
	result := setupUnsupported(t, "${{ format('{0}', secrets.PROD_TOKEN) }}", secretRef("PROD_TOKEN", 1))
	if len(result.Flows) != 0 {
		t.Fatalf("expected no confirmed flow, got %#v", result.Flows)
	}
	if !hasDiagnostic(result.Diagnostics, DiagnosticUnsupportedSecretExpression, "token") {
		t.Fatalf("expected unsupported_secret_expression diagnostic, got %#v", result.Diagnostics)
	}
}

// 27. conditional with one secret not confirmed.
func TestLinkConditionalOneSecretNotConfirmed(t *testing.T) {
	result := setupUnsupported(t, "${{ condition && secrets.PROD_TOKEN || 'none' }}", secretRef("PROD_TOKEN", 1))
	if len(result.Flows) != 0 {
		t.Fatalf("expected no confirmed flow, got %#v", result.Flows)
	}
	if !hasDiagnostic(result.Diagnostics, DiagnosticUnsupportedSecretExpression, "token") {
		t.Fatalf("expected unsupported_secret_expression diagnostic, got %#v", result.Diagnostics)
	}
}

// 28. two secret sources ambiguous.
func TestLinkTwoSecretSourcesAmbiguous(t *testing.T) {
	result := setupUnsupported(t, "${{ secrets.A }}${{ secrets.B }}", secretRef("A", 1), secretRef("B", 1))
	if len(result.Flows) != 0 {
		t.Fatalf("expected no confirmed flow, got %#v", result.Flows)
	}
	if !hasDiagnostic(result.Diagnostics, DiagnosticAmbiguousSecretSources, "token") {
		t.Fatalf("expected ambiguous_secret_sources diagnostic, got %#v", result.Diagnostics)
	}
}

// 29. repeated same secret in a transformed expression not confirmed.
func TestLinkRepeatedSameSecretTransformedNotConfirmed(t *testing.T) {
	result := setupUnsupported(t, "${{ secrets.A }}${{ secrets.A }}", secretRef("A", 1))
	if len(result.Flows) != 0 {
		t.Fatalf("expected no confirmed flow even though only one distinct secret name appears, got %#v", result.Flows)
	}
	if !hasDiagnostic(result.Diagnostics, DiagnosticUnsupportedSecretExpression, "token") {
		t.Fatalf("expected unsupported_secret_expression diagnostic (proves len(References)==1 is not the confirming rule), got %#v", result.Diagnostics)
	}
}

// 30. dynamic bracket secret diagnostic.
func TestLinkDynamicBracketSecretDiagnostic(t *testing.T) {
	for _, value := range []string{`${{ secrets["PROD_TOKEN"] }}`, `${{ secrets[inputs.secret_name] }}`} {
		result := setupUnsupported(t, value)
		if len(result.Flows) != 0 {
			t.Fatalf("expected no confirmed flow for %q, got %#v", value, result.Flows)
		}
		if !hasDiagnostic(result.Diagnostics, DiagnosticDynamicSecretReference, "token") {
			t.Fatalf("expected dynamic_secret_reference diagnostic for %q, got %#v", value, result.Diagnostics)
		}
	}
}

// 31. github.token no confirmed flow.
func TestLinkGithubTokenNoConfirmedFlow(t *testing.T) {
	result := setupUnsupported(t, "${{ github.token }}", domain.Reference{Kind: domain.ReferenceGitHubContext, Name: "github.token"})
	if len(result.Flows) != 0 {
		t.Fatalf("expected no confirmed flow, got %#v", result.Flows)
	}
	if len(result.Diagnostics) != 0 {
		t.Fatalf("github.token is a legitimate noncredential binding and must be silent, got %#v", result.Diagnostics)
	}
}

// 32. env indirection no confirmed flow.
func TestLinkEnvIndirectionNoConfirmedFlow(t *testing.T) {
	result := setupUnsupported(t, "${{ env.TOKEN }}", domain.Reference{Kind: domain.ReferenceEnvironment, Name: "TOKEN"})
	if len(result.Flows) != 0 {
		t.Fatalf("expected no confirmed flow, got %#v", result.Flows)
	}
	if len(result.Diagnostics) != 0 {
		t.Fatalf("env indirection is a silent noncredential binding, got %#v", result.Diagnostics)
	}
}

// 33. literal no confirmed flow.
func TestLinkLiteralNoConfirmedFlow(t *testing.T) {
	result := setupUnsupported(t, "production")
	if len(result.Flows) != 0 {
		t.Fatalf("expected no confirmed flow, got %#v", result.Flows)
	}
	if len(result.Diagnostics) != 0 {
		t.Fatalf("literal binding is silent, got %#v", result.Diagnostics)
	}
}

// 34. undeclared input diagnostic.
func TestLinkUndeclaredInputDiagnostic(t *testing.T) {
	action := canonicalAction(testDirectory, []domain.ActionInputDefinition{inputDef("token", true, nil)}, actionStep("deploy", actionInputRef("token", 10)))
	wf := workflow("caller.yml", job("deploy", stepWithBindings("s", cleanSecretBinding("mystery", "PROD_TOKEN"))))
	resolution := domain.CompositeActionResolution{Actions: []domain.ActionMetadata{action}, Calls: []domain.CompositeActionCall{resolvedCall("caller.yml", "deploy", 0, "s", testDirectory)}}

	result, err := Link(context.Background(), []domain.Workflow{wf}, resolution)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Flows) != 0 {
		t.Fatalf("expected no flow for undeclared input, got %#v", result.Flows)
	}
	if !hasDiagnostic(result.Diagnostics, DiagnosticUndeclaredInput, "mystery") {
		t.Fatalf("expected undeclared_input diagnostic, got %#v", result.Diagnostics)
	}
}

// 35. required missing diagnostic.
func TestLinkRequiredMissingDiagnostic(t *testing.T) {
	action := canonicalAction(testDirectory, []domain.ActionInputDefinition{inputDef("token", true, nil)}, actionStep("deploy", actionInputRef("token", 10)))
	wf := workflow("caller.yml", job("deploy", stepWithBindings("s")))
	resolution := domain.CompositeActionResolution{Actions: []domain.ActionMetadata{action}, Calls: []domain.CompositeActionCall{resolvedCall("caller.yml", "deploy", 0, "s", testDirectory)}}

	result, err := Link(context.Background(), []domain.Workflow{wf}, resolution)
	if err != nil {
		t.Fatal(err)
	}
	if !hasDiagnostic(result.Diagnostics, DiagnosticRequiredInputMissing, "token") {
		t.Fatalf("expected required_input_missing diagnostic, got %#v", result.Diagnostics)
	}
}

// 36. required with default produces no missing diagnostic.
func TestLinkRequiredWithDefaultNoMissingDiagnostic(t *testing.T) {
	def := "us-east-1"
	action := canonicalAction(testDirectory, []domain.ActionInputDefinition{inputDef("region", true, &def)}, actionStep("deploy", actionInputRef("region", 10)))
	wf := workflow("caller.yml", job("deploy", stepWithBindings("s")))
	resolution := domain.CompositeActionResolution{Actions: []domain.ActionMetadata{action}, Calls: []domain.CompositeActionCall{resolvedCall("caller.yml", "deploy", 0, "s", testDirectory)}}

	result, err := Link(context.Background(), []domain.Workflow{wf}, resolution)
	if err != nil {
		t.Fatal(err)
	}
	if hasDiagnostic(result.Diagnostics, DiagnosticRequiredInputMissing, "region") {
		t.Fatalf("required input with a default must not produce required_input_missing, got %#v", result.Diagnostics)
	}
}

// 37. explicit empty caller binding counts as supplied.
func TestLinkExplicitEmptyBindingCountsAsSupplied(t *testing.T) {
	action := canonicalAction(testDirectory, []domain.ActionInputDefinition{inputDef("token", true, nil)}, actionStep("deploy", actionInputRef("token", 10)))
	wf := workflow("caller.yml", job("deploy", stepWithBindings("s", binding("token", ""))))
	resolution := domain.CompositeActionResolution{Actions: []domain.ActionMetadata{action}, Calls: []domain.CompositeActionCall{resolvedCall("caller.yml", "deploy", 0, "s", testDirectory)}}

	result, err := Link(context.Background(), []domain.Workflow{wf}, resolution)
	if err != nil {
		t.Fatal(err)
	}
	if hasDiagnostic(result.Diagnostics, DiagnosticRequiredInputMissing, "token") {
		t.Fatalf("explicit empty-string binding must count as supplied, got %#v", result.Diagnostics)
	}
	if len(result.Flows) != 0 {
		t.Fatalf("empty-string binding must not create confirmed flow, got %#v", result.Flows)
	}
}

// 38. optional missing silent.
func TestLinkOptionalMissingSilent(t *testing.T) {
	action := canonicalAction(testDirectory, []domain.ActionInputDefinition{inputDef("region", false, nil)}, actionStep("deploy", actionInputRef("region", 10)))
	wf := workflow("caller.yml", job("deploy", stepWithBindings("s")))
	resolution := domain.CompositeActionResolution{Actions: []domain.ActionMetadata{action}, Calls: []domain.CompositeActionCall{resolvedCall("caller.yml", "deploy", 0, "s", testDirectory)}}

	result, err := Link(context.Background(), []domain.Workflow{wf}, resolution)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Diagnostics) != 0 {
		t.Fatalf("optional missing input must be silent, got %#v", result.Diagnostics)
	}
}

// 39. one input used by two internal steps.
func TestLinkOneInputUsedByTwoInternalSteps(t *testing.T) {
	action := canonicalAction(testDirectory, []domain.ActionInputDefinition{inputDef("token", true, nil)},
		actionStep("first", actionInputRef("token", 10)),
		actionStep("second", actionInputRef("token", 20)),
	)
	wf := workflow("caller.yml", job("deploy", stepWithBindings("s", cleanSecretBinding("token", "PROD_TOKEN"))))
	resolution := domain.CompositeActionResolution{Actions: []domain.ActionMetadata{action}, Calls: []domain.CompositeActionCall{resolvedCall("caller.yml", "deploy", 0, "s", testDirectory)}}

	result, err := Link(context.Background(), []domain.Workflow{wf}, resolution)
	if err != nil {
		t.Fatal(err)
	}
	flow := findFlow(t, result.Flows, "token")
	if len(flow.Usages) != 2 || flow.Usages[0].ActionStepIndex != 0 || flow.Usages[1].ActionStepIndex != 1 {
		t.Fatalf("expected two usages across steps 0 and 1, got %#v", flow.Usages)
	}
}

// 40. repeated use in one internal step creates one usage.
func TestLinkRepeatedUseInOneStepCreatesOneUsage(t *testing.T) {
	action := canonicalAction(testDirectory, []domain.ActionInputDefinition{inputDef("token", true, nil)},
		actionStep("deploy", actionInputRef("token", 20), actionInputRef("token", 10)),
	)
	wf := workflow("caller.yml", job("deploy", stepWithBindings("s", cleanSecretBinding("token", "PROD_TOKEN"))))
	resolution := domain.CompositeActionResolution{Actions: []domain.ActionMetadata{action}, Calls: []domain.CompositeActionCall{resolvedCall("caller.yml", "deploy", 0, "s", testDirectory)}}

	result, err := Link(context.Background(), []domain.Workflow{wf}, resolution)
	if err != nil {
		t.Fatal(err)
	}
	flow := findFlow(t, result.Flows, "token")
	if len(flow.Usages) != 1 {
		t.Fatalf("expected exactly one usage collapsed from two references in the same step, got %#v", flow.Usages)
	}
	if flow.Usages[0].Evidence.Location.Line != 10 {
		t.Fatalf("expected earliest evidence line 10, got %#v", flow.Usages[0].Evidence)
	}
}

// 41. input used only in if/working-directory is found through ActionStep.References.
func TestLinkInputUsedOnlyInIfOrWorkingDirectoryFound(t *testing.T) {
	// ActionStep.References is the whole-step generic sweep, which already
	// covers if:/working-directory: content (unlike Run/Environment/With's
	// own dedicated sub-slices) — the linker deliberately scans this field
	// directly rather than any narrower sub-slice.
	action := canonicalAction(testDirectory, []domain.ActionInputDefinition{inputDef("enabled", true, nil)},
		actionStep("deploy", actionInputRef("enabled", 5)),
	)
	wf := workflow("caller.yml", job("deploy", stepWithBindings("s", cleanSecretBinding("enabled", "FEATURE_FLAG"))))
	resolution := domain.CompositeActionResolution{Actions: []domain.ActionMetadata{action}, Calls: []domain.CompositeActionCall{resolvedCall("caller.yml", "deploy", 0, "s", testDirectory)}}

	result, err := Link(context.Background(), []domain.Workflow{wf}, resolution)
	if err != nil {
		t.Fatal(err)
	}
	flow := findFlow(t, result.Flows, "enabled")
	if len(flow.Usages) != 1 {
		t.Fatalf("expected usage found via whole-step References sweep, got %#v", flow.Usages)
	}
}

// 42. declared input with zero step usages creates no confirmed flow.
func TestLinkZeroStepUsagesNoConfirmedFlow(t *testing.T) {
	action := canonicalAction(testDirectory, []domain.ActionInputDefinition{inputDef("unused", true, nil)}, actionStep("deploy"))
	wf := workflow("caller.yml", job("deploy", stepWithBindings("s", cleanSecretBinding("unused", "PROD_TOKEN"))))
	resolution := domain.CompositeActionResolution{Actions: []domain.ActionMetadata{action}, Calls: []domain.CompositeActionCall{resolvedCall("caller.yml", "deploy", 0, "s", testDirectory)}}

	result, err := Link(context.Background(), []domain.Workflow{wf}, resolution)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Flows) != 0 {
		t.Fatalf("expected no confirmed flow when the declared input has zero internal usages, got %#v", result.Flows)
	}
	if len(result.Diagnostics) != 0 {
		t.Fatalf("zero-usage drop must not itself produce a diagnostic (declared_but_unused is out of CA2 scope), got %#v", result.Diagnostics)
	}
}

// 43. same action called twice with different secrets stays separated.
func TestLinkSameActionCalledTwiceDifferentSecretsSeparated(t *testing.T) {
	action := canonicalAction(testDirectory, []domain.ActionInputDefinition{inputDef("token", true, nil)}, actionStep("deploy", actionInputRef("token", 10)))
	wf := workflow("caller.yml", job("deploy",
		stepWithBindings("prod-step", cleanSecretBinding("token", "PROD_TOKEN")),
		stepWithBindings("staging-step", cleanSecretBinding("token", "STAGING_TOKEN")),
	))
	resolution := domain.CompositeActionResolution{
		Actions: []domain.ActionMetadata{action},
		Calls: []domain.CompositeActionCall{
			resolvedCall("caller.yml", "deploy", 0, "prod-step", testDirectory),
			resolvedCall("caller.yml", "deploy", 1, "staging-step", testDirectory),
		},
	}

	result, err := Link(context.Background(), []domain.Workflow{wf}, resolution)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Flows) != 2 {
		t.Fatalf("expected two separated flows, got %#v", result.Flows)
	}
	bySecret := map[string]ConfirmedInputFlow{}
	for _, f := range result.Flows {
		bySecret[f.SourceSecret] = f
	}
	if bySecret["PROD_TOKEN"].CallerStepIndex != 0 || bySecret["STAGING_TOKEN"].CallerStepIndex != 1 {
		t.Fatalf("flows not correctly attributed to their call site: %#v", result.Flows)
	}
}

// 44. two workflows call same action stays separated.
func TestLinkTwoWorkflowsCallSameActionSeparated(t *testing.T) {
	action := canonicalAction(testDirectory, []domain.ActionInputDefinition{inputDef("token", true, nil)}, actionStep("deploy", actionInputRef("token", 10)))
	wfA := workflow("a.yml", job("deploy", stepWithBindings("s", cleanSecretBinding("token", "PROD_TOKEN"))))
	wfB := workflow("b.yml", job("deploy", stepWithBindings("s", cleanSecretBinding("token", "PROD_TOKEN"))))
	resolution := domain.CompositeActionResolution{
		Actions: []domain.ActionMetadata{action},
		Calls: []domain.CompositeActionCall{
			resolvedCall("a.yml", "deploy", 0, "s", testDirectory),
			resolvedCall("b.yml", "deploy", 0, "s", testDirectory),
		},
	}

	result, err := Link(context.Background(), []domain.Workflow{wfA, wfB}, resolution)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Flows) != 2 {
		t.Fatalf("expected two separated flows (one per workflow), got %#v", result.Flows)
	}
	if result.Flows[0].CallerWorkflow == result.Flows[1].CallerWorkflow {
		t.Fatalf("flows must be attributed to distinct caller workflows: %#v", result.Flows)
	}
}

// 45. same secret forwarded into two aliases stays separated.
func TestLinkSameSecretTwoAliasesSeparated(t *testing.T) {
	action := canonicalAction(testDirectory,
		[]domain.ActionInputDefinition{inputDef("token", true, nil), inputDef("password", true, nil)},
		actionStep("deploy", actionInputRef("token", 10), actionInputRef("password", 11)),
	)
	wf := workflow("caller.yml", job("deploy", stepWithBindings("s", cleanSecretBinding("token", "PROD_TOKEN"), cleanSecretBinding("password", "PROD_TOKEN"))))
	resolution := domain.CompositeActionResolution{Actions: []domain.ActionMetadata{action}, Calls: []domain.CompositeActionCall{resolvedCall("caller.yml", "deploy", 0, "s", testDirectory)}}

	result, err := Link(context.Background(), []domain.Workflow{wf}, resolution)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Flows) != 2 {
		t.Fatalf("expected two separate flows for two aliases sharing one secret, got %#v", result.Flows)
	}
	tokenFlow := findFlow(t, result.Flows, "token")
	passwordFlow := findFlow(t, result.Flows, "password")
	if tokenFlow.SourceSecret != "PROD_TOKEN" || passwordFlow.SourceSecret != "PROD_TOKEN" {
		t.Fatalf("both aliases should share the same source secret: %#v / %#v", tokenFlow, passwordFlow)
	}
}

// 46. same-name source secret/input does not collapse.
func TestLinkSameNameSourceInputDoesNotCollapse(t *testing.T) {
	action := canonicalAction(testDirectory, []domain.ActionInputDefinition{inputDef("TOKEN", true, nil)}, actionStep("deploy", actionInputRef("TOKEN", 10)))
	wf := workflow("caller.yml", job("deploy", stepWithBindings("s", cleanSecretBinding("TOKEN", "TOKEN"))))
	resolution := domain.CompositeActionResolution{Actions: []domain.ActionMetadata{action}, Calls: []domain.CompositeActionCall{resolvedCall("caller.yml", "deploy", 0, "s", testDirectory)}}

	result, err := Link(context.Background(), []domain.Workflow{wf}, resolution)
	if err != nil {
		t.Fatal(err)
	}
	flow := findFlow(t, result.Flows, "TOKEN")
	if flow.SourceSecret != "TOKEN" || flow.InputName != "TOKEN" {
		t.Fatalf("same-named source/input must still resolve correctly, got %#v", flow)
	}
}

// 47. unresolved action no flow.
func TestLinkUnresolvedActionNoFlow(t *testing.T) {
	wf := workflow("caller.yml", job("deploy", stepWithBindings("s", cleanSecretBinding("token", "PROD_TOKEN"))))
	call := domain.CompositeActionCall{CallerWorkflow: "caller.yml", CallerJobID: "deploy", CallerStepIndex: 0, CallerStepID: "s", Status: domain.CompositeActionOpaqueExternal}
	resolution := domain.CompositeActionResolution{Calls: []domain.CompositeActionCall{call}}

	result, err := Link(context.Background(), []domain.Workflow{wf}, resolution)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Flows) != 0 || len(result.Diagnostics) != 0 {
		t.Fatalf("expected no flow and no diagnostics for an unresolved (opaque_external) call, got flows=%#v diagnostics=%#v", result.Flows, result.Diagnostics)
	}
}

// 48. target_not_composite no flow.
func TestLinkTargetNotCompositeNoFlow(t *testing.T) {
	wf := workflow("caller.yml", job("deploy", stepWithBindings("s", cleanSecretBinding("token", "PROD_TOKEN"))))
	call := domain.CompositeActionCall{CallerWorkflow: "caller.yml", CallerJobID: "deploy", CallerStepIndex: 0, CallerStepID: "s", CanonicalDirectory: testDirectory, Status: domain.CompositeActionTargetNotComposite}
	resolution := domain.CompositeActionResolution{Calls: []domain.CompositeActionCall{call}}

	result, err := Link(context.Background(), []domain.Workflow{wf}, resolution)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Flows) != 0 || len(result.Diagnostics) != 0 {
		t.Fatalf("expected no flow and no diagnostics for target_not_composite, got flows=%#v diagnostics=%#v", result.Flows, result.Diagnostics)
	}
}

// 49. deterministic ordering.
func TestLinkDeterministicOrdering(t *testing.T) {
	action := canonicalAction(testDirectory,
		[]domain.ActionInputDefinition{inputDef("zeta", true, nil), inputDef("alpha", true, nil)},
		actionStep("deploy", actionInputRef("zeta", 10), actionInputRef("alpha", 11)),
	)
	wf := workflow("caller.yml", job("deploy", stepWithBindings("s", cleanSecretBinding("zeta", "Z"), cleanSecretBinding("alpha", "A"))))
	resolution := domain.CompositeActionResolution{Actions: []domain.ActionMetadata{action}, Calls: []domain.CompositeActionCall{resolvedCall("caller.yml", "deploy", 0, "s", testDirectory)}}

	result, err := Link(context.Background(), []domain.Workflow{wf}, resolution)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Flows) != 2 || result.Flows[0].InputName != "alpha" || result.Flows[1].InputName != "zeta" {
		t.Fatalf("expected flows sorted by input name, got %#v", result.Flows)
	}
}

// 50. separately linked results do not share slices.
func TestLinkSeparatelyLinkedResultsDoNotShareSlices(t *testing.T) {
	action := canonicalAction(testDirectory, []domain.ActionInputDefinition{inputDef("token", true, nil)}, actionStep("deploy", actionInputRef("token", 10)))
	wf := workflow("caller.yml", job("deploy", stepWithBindings("s", cleanSecretBinding("token", "PROD_TOKEN"))))
	resolution := domain.CompositeActionResolution{Actions: []domain.ActionMetadata{action}, Calls: []domain.CompositeActionCall{resolvedCall("caller.yml", "deploy", 0, "s", testDirectory)}}

	first, err := Link(context.Background(), []domain.Workflow{wf}, resolution)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Link(context.Background(), []domain.Workflow{wf}, resolution)
	if err != nil {
		t.Fatal(err)
	}
	first.Flows[0].Usages = append(first.Flows[0].Usages, InputUsage{ActionStepIndex: 99})
	if len(second.Flows[0].Usages) == len(first.Flows[0].Usages) {
		t.Fatal("mutating one Link result's nested slice affected a separately linked result")
	}
}

// 51. workflows immutable.
func TestLinkWorkflowsImmutable(t *testing.T) {
	action := canonicalAction(testDirectory, []domain.ActionInputDefinition{inputDef("token", true, nil)}, actionStep("deploy", actionInputRef("token", 10)))
	wf := workflow("caller.yml", job("deploy", stepWithBindings("s", cleanSecretBinding("token", "PROD_TOKEN"))))
	workflows := []domain.Workflow{wf}
	resolution := domain.CompositeActionResolution{Actions: []domain.ActionMetadata{action}, Calls: []domain.CompositeActionCall{resolvedCall("caller.yml", "deploy", 0, "s", testDirectory)}}

	before := workflows[0].Jobs[0].Steps[0].With[0].Value
	if _, err := Link(context.Background(), workflows, resolution); err != nil {
		t.Fatal(err)
	}
	after := workflows[0].Jobs[0].Steps[0].With[0].Value
	if before != after {
		t.Fatalf("workflows were mutated: before=%q after=%q", before, after)
	}
}

// 52. resolution immutable.
func TestLinkResolutionImmutable(t *testing.T) {
	action := canonicalAction(testDirectory, []domain.ActionInputDefinition{inputDef("token", true, nil)}, actionStep("deploy", actionInputRef("token", 10)))
	wf := workflow("caller.yml", job("deploy", stepWithBindings("s", cleanSecretBinding("token", "PROD_TOKEN"))))
	resolution := domain.CompositeActionResolution{Actions: []domain.ActionMetadata{action}, Calls: []domain.CompositeActionCall{resolvedCall("caller.yml", "deploy", 0, "s", testDirectory)}}

	beforeActions := len(resolution.Actions)
	beforeCalls := len(resolution.Calls)
	if _, err := Link(context.Background(), []domain.Workflow{wf}, resolution); err != nil {
		t.Fatal(err)
	}
	if len(resolution.Actions) != beforeActions || len(resolution.Calls) != beforeCalls {
		t.Fatal("resolution was mutated")
	}
}

// Defensive: a manually constructed binding whose raw Value names one
// secret while its structured References claims a different secret must
// never produce a confirmed flow. The two are always produced by the same
// parser call in real usage, but the linker must not trust Value alone —
// disagreement must fail closed.
func TestLinkValueReferenceDisagreementNoConfirmedFlow(t *testing.T) {
	action := canonicalAction(testDirectory, []domain.ActionInputDefinition{inputDef("token", true, nil)}, actionStep("deploy", actionInputRef("token", 10)))
	disagreeing := binding("token", "${{ secrets.PROD_TOKEN }}", secretRef("STAGING_TOKEN", 1))
	wf := workflow("caller.yml", job("deploy", stepWithBindings("s", disagreeing)))
	resolution := domain.CompositeActionResolution{Actions: []domain.ActionMetadata{action}, Calls: []domain.CompositeActionCall{resolvedCall("caller.yml", "deploy", 0, "s", testDirectory)}}

	result, err := Link(context.Background(), []domain.Workflow{wf}, resolution)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Flows) != 0 {
		t.Fatalf("Value/References disagreement must never produce a confirmed flow, got %#v", result.Flows)
	}
	if !hasDiagnostic(result.Diagnostics, DiagnosticUnsupportedSecretExpression, "token") {
		t.Fatalf("expected unsupported_secret_expression diagnostic for disagreement, got %#v", result.Diagnostics)
	}
}

// 53. context cancellation returns empty result and error.
func TestLinkContextCancellationReturnsEmptyResultAndError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, err := Link(ctx, nil, domain.CompositeActionResolution{})
	if err == nil {
		t.Fatal("expected an error for a canceled context")
	}
	if len(result.Flows) != 0 || len(result.Diagnostics) != 0 {
		t.Fatalf("expected an empty result, got %#v", result)
	}
}
