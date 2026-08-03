package nestedcompositeactionflow

import (
	"context"
	"fmt"
	"reflect"
	"testing"

	"github.com/Bavlik/CredScope/internal/compositeaction"
	"github.com/Bavlik/CredScope/internal/compositeactionflow"
	"github.com/Bavlik/CredScope/internal/domain"
)

const (
	dirA = ".github/actions/a"
	dirB = ".github/actions/b"
	dirC = ".github/actions/c"
	dirD = ".github/actions/d"

	dirDeploy       = ".github/actions/deploy"
	dirAuthenticate = ".github/actions/authenticate"
)

func ev(path string, line int, field string) domain.Evidence {
	return domain.Evidence{Location: domain.Location{Path: path, Line: line}, Field: field, Confidence: domain.ConfidenceConfirmed}
}

func inputRef(name string, line int) domain.Reference {
	return domain.Reference{Kind: domain.ReferenceActionInput, Name: name, Evidence: ev("action.yml", line, "runs.steps")}
}

func inputDef(name string, required bool, def *string) domain.ActionInputDefinition {
	return domain.ActionInputDefinition{Name: name, Required: required, Default: def, Evidence: ev("action.yml", 1, "inputs."+name)}
}

func withBinding(name, value string, refs ...domain.Reference) domain.ActionInputBinding {
	return domain.ActionInputBinding{Name: name, Value: value, References: refs, Evidence: ev("action.yml", 1, "with."+name)}
}

// nestedUsesStep builds one composite-action-internal `uses:` step. Its
// References field is populated exactly like the real parser's whole-step
// sweep would populate it (every binding's own References folded in), so a
// nested-call step can simultaneously serve as a lower level's confirmed
// internal usage — proving CA3B independently inspects With rather than
// trusting the mere existence of a usage record at this step.
func nestedUsesStep(id, target string, bindings ...domain.ActionInputBinding) domain.ActionStep {
	var refs []domain.Reference
	for _, b := range bindings {
		refs = append(refs, b.References...)
	}
	return domain.ActionStep{
		ID:         id,
		Action:     &domain.ActionReference{Reference: target, Local: true, Evidence: ev("action.yml", 1, "runs.steps.uses")},
		With:       bindings,
		References: refs,
	}
}

func plainStep(id string, refs ...domain.Reference) domain.ActionStep {
	return domain.ActionStep{ID: id, References: refs}
}

func action(directory string, inputs []domain.ActionInputDefinition, steps ...domain.ActionStep) domain.ActionMetadata {
	return domain.ActionMetadata{
		Directory: directory, File: directory + "/action.yml", Name: directory,
		Inputs: inputs, Runs: domain.ActionRuns{Using: "composite", Steps: steps},
		Evidence: ev(directory+"/action.yml", 1, "action"),
	}
}

func nestedCallWithStatus(parentDir string, parentStepIndex int, childDir string, status domain.CompositeActionResolutionStatus) domain.NestedCompositeActionCall {
	return domain.NestedCompositeActionCall{
		ParentCanonicalDirectory: parentDir, ParentActionStepIndex: parentStepIndex,
		CanonicalDirectory: childDir, Status: status,
		Evidence: ev(parentDir+"/action.yml", 1+parentStepIndex, "runs.steps"),
	}
}

func resolvedNestedCall(parentDir string, parentStepIndex int, childDir string) domain.NestedCompositeActionCall {
	return nestedCallWithStatus(parentDir, parentStepIndex, childDir, domain.CompositeActionResolvedLocalComposite)
}

func usageAt(stepIndex int, stepID string) compositeactionflow.InputUsage {
	return compositeactionflow.InputUsage{ActionStepIndex: stepIndex, ActionStepID: stepID, Evidence: ev("action.yml", 10+stepIndex, "runs.steps")}
}

func rootFlow(workflow, jobID string, stepIndex int, directory, inputName, secret string, usages ...compositeactionflow.InputUsage) compositeactionflow.ConfirmedInputFlow {
	return compositeactionflow.ConfirmedInputFlow{
		CallerWorkflow: workflow, CallerJobID: jobID, CallerStepIndex: stepIndex, CallerStepID: "call-step",
		CanonicalDirectory: directory, InputName: inputName, SourceSecret: secret,
		BindingEvidence: ev("caller.yml", 3, "with."+inputName), Usages: usages,
	}
}

func hasDiagnostic(diagnostics []Diagnostic, kind DiagnosticKind, childInputName string) bool {
	for _, d := range diagnostics {
		if d.Kind == kind && d.ChildInputName == childInputName {
			return true
		}
	}
	return false
}

func countDiagnostics(diagnostics []Diagnostic, kind DiagnosticKind) int {
	count := 0
	for _, d := range diagnostics {
		if d.Kind == kind {
			count++
		}
	}
	return count
}

// setupScenario builds one parent (dirA, single required input "token") ->
// child (dirB) nested call, with one With binding on the nested step, and
// runs Link against a single confirmed root flow for "token".
func setupScenario(t *testing.T, aliasName, bindingValue string, refs []domain.Reference, childInputs []domain.ActionInputDefinition, childSteps []domain.ActionStep) Result {
	t.Helper()
	parent := action(dirA, []domain.ActionInputDefinition{inputDef("token", true, nil)},
		nestedUsesStep("step0", "./"+dirB, withBinding(aliasName, bindingValue, refs...)))
	child := action(dirB, childInputs, childSteps...)
	resolution := domain.CompositeActionResolution{
		Actions:     []domain.ActionMetadata{parent, child},
		NestedCalls: []domain.NestedCompositeActionCall{resolvedNestedCall(dirA, 0, dirB)},
	}
	rootFlows := compositeactionflow.Result{Flows: []compositeactionflow.ConfirmedInputFlow{
		rootFlow("caller.yml", "deploy", 0, dirA, "token", "PROD_TOKEN", usageAt(0, "step0")),
	}}
	result, err := Link(context.Background(), rootFlows, resolution)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func defaultChildInputs() []domain.ActionInputDefinition {
	return []domain.ActionInputDefinition{inputDef("credential", true, nil)}
}

func defaultChildSteps() []domain.ActionStep {
	return []domain.ActionStep{plainStep("login", inputRef("credential", 20))}
}

// 1. exact nested forwarding — the target CA3B example end to end.
func TestLinkExactNestedForwarding(t *testing.T) {
	parent := action(dirDeploy, []domain.ActionInputDefinition{inputDef("token", true, nil)},
		nestedUsesStep("authenticate", "./"+dirAuthenticate, withBinding("credential", "${{ inputs.token }}", inputRef("token", 1))))
	child := action(dirAuthenticate, []domain.ActionInputDefinition{inputDef("credential", true, nil)},
		plainStep("login", inputRef("credential", 20)))
	resolution := domain.CompositeActionResolution{
		Actions:     []domain.ActionMetadata{parent, child},
		NestedCalls: []domain.NestedCompositeActionCall{resolvedNestedCall(dirDeploy, 0, dirAuthenticate)},
	}
	rootFlows := compositeactionflow.Result{Flows: []compositeactionflow.ConfirmedInputFlow{
		rootFlow(".github/workflows/deploy.yml", "deploy", 0, dirDeploy, "token", "PROD_TOKEN", usageAt(0, "authenticate")),
	}}

	result, err := Link(context.Background(), rootFlows, resolution)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Flows) != 1 {
		t.Fatalf("expected exactly one confirmed nested flow, got %#v", result.Flows)
	}
	flow := result.Flows[0]
	if flow.RootCallerWorkflow != ".github/workflows/deploy.yml" || flow.RootCallerJobID != "deploy" || flow.RootCallerStepIndex != 0 {
		t.Fatalf("unexpected root identity: %#v", flow)
	}
	if flow.RootInputName != "token" || flow.RootSourceSecret != "PROD_TOKEN" {
		t.Fatalf("unexpected root input/secret: %#v", flow)
	}
	if flow.ParentCanonicalDirectory != dirDeploy || flow.ParentInputName != "token" {
		t.Fatalf("unexpected parent identity: %#v", flow)
	}
	if flow.ParentUsageStepIndex != 0 || flow.ParentUsageStepID != "authenticate" {
		t.Fatalf("unexpected parent usage identity: %#v", flow)
	}
	if flow.ChildCanonicalDirectory != dirAuthenticate || flow.ChildInputName != "credential" {
		t.Fatalf("unexpected child identity: %#v", flow)
	}
	if len(flow.CallPath) != 1 || flow.CallPath[0] != (CallPathSegment{ParentCanonicalDirectory: dirDeploy, ParentActionStepIndex: 0, ChildCanonicalDirectory: dirAuthenticate}) {
		t.Fatalf("unexpected call path: %#v", flow.CallPath)
	}
	if len(flow.Usages) != 1 || flow.Usages[0].ActionStepIndex != 0 || flow.Usages[0].ActionStepID != "login" {
		t.Fatalf("unexpected child usages: %#v", flow.Usages)
	}
	if len(result.Diagnostics) != 0 {
		t.Fatalf("expected no diagnostics, got %#v", result.Diagnostics)
	}
}

// 2. surrounding whitespace accepted.
func TestLinkWhitespaceAccepted(t *testing.T) {
	result := setupScenario(t, "credential", "${{   inputs.token   }}", []domain.Reference{inputRef("token", 1)}, defaultChildInputs(), defaultChildSteps())
	if len(result.Flows) != 1 {
		t.Fatalf("expected whitespace-padded expression to confirm, got flows=%#v diagnostics=%#v", result.Flows, result.Diagnostics)
	}
}

// 3. prefix rejected.
func TestLinkPrefixRejected(t *testing.T) {
	result := setupScenario(t, "credential", "prefix-${{ inputs.token }}", []domain.Reference{inputRef("token", 1)}, defaultChildInputs(), defaultChildSteps())
	if len(result.Flows) != 0 {
		t.Fatalf("expected no confirmed flow, got %#v", result.Flows)
	}
	if !hasDiagnostic(result.Diagnostics, DiagnosticUnsupportedInputExpression, "credential") {
		t.Fatalf("expected nested_unsupported_input_expression, got %#v", result.Diagnostics)
	}
}

// 4. suffix rejected.
func TestLinkSuffixRejected(t *testing.T) {
	result := setupScenario(t, "credential", "${{ inputs.token }}-suffix", []domain.Reference{inputRef("token", 1)}, defaultChildInputs(), defaultChildSteps())
	if len(result.Flows) != 0 {
		t.Fatalf("expected no confirmed flow, got %#v", result.Flows)
	}
	if !hasDiagnostic(result.Diagnostics, DiagnosticUnsupportedInputExpression, "credential") {
		t.Fatalf("expected nested_unsupported_input_expression, got %#v", result.Diagnostics)
	}
}

// 5. format() rejected.
func TestLinkFormatRejected(t *testing.T) {
	result := setupScenario(t, "credential", "${{ format('{0}', inputs.token) }}", []domain.Reference{inputRef("token", 1)}, defaultChildInputs(), defaultChildSteps())
	if len(result.Flows) != 0 {
		t.Fatalf("expected no confirmed flow, got %#v", result.Flows)
	}
	if !hasDiagnostic(result.Diagnostics, DiagnosticUnsupportedInputExpression, "credential") {
		t.Fatalf("expected nested_unsupported_input_expression, got %#v", result.Diagnostics)
	}
}

// 6. conditional rejected.
func TestLinkConditionalRejected(t *testing.T) {
	result := setupScenario(t, "credential", "${{ condition && inputs.token || 'none' }}", []domain.Reference{inputRef("token", 1)}, defaultChildInputs(), defaultChildSteps())
	if len(result.Flows) != 0 {
		t.Fatalf("expected no confirmed flow, got %#v", result.Flows)
	}
	if !hasDiagnostic(result.Diagnostics, DiagnosticUnsupportedInputExpression, "credential") {
		t.Fatalf("expected nested_unsupported_input_expression, got %#v", result.Diagnostics)
	}
}

// 7. repeated same input in transformed text rejected.
func TestLinkRepeatedSameReferenceTransformedRejected(t *testing.T) {
	result := setupScenario(t, "credential", "${{ inputs.token }}${{ inputs.token }}", []domain.Reference{inputRef("token", 1)}, defaultChildInputs(), defaultChildSteps())
	if len(result.Flows) != 0 {
		t.Fatalf("expected no confirmed flow even though only one distinct input name appears, got %#v", result.Flows)
	}
	if !hasDiagnostic(result.Diagnostics, DiagnosticUnsupportedInputExpression, "credential") {
		t.Fatalf("expected nested_unsupported_input_expression (proves len(References)==1 is not the confirming rule), got %#v", result.Diagnostics)
	}
}

// 8. multiple distinct references rejected.
func TestLinkMultipleDistinctReferencesRejected(t *testing.T) {
	result := setupScenario(t, "credential", "${{ inputs.token }}${{ inputs.other }}", []domain.Reference{inputRef("token", 1), inputRef("other", 1)}, defaultChildInputs(), defaultChildSteps())
	if len(result.Flows) != 0 {
		t.Fatalf("expected no confirmed flow, got %#v", result.Flows)
	}
	if !hasDiagnostic(result.Diagnostics, DiagnosticAmbiguousInputSources, "credential") {
		t.Fatalf("expected nested_ambiguous_input_sources, got %#v", result.Diagnostics)
	}
}

// 9. dynamic literal indexing rejected.
func TestLinkDynamicLiteralIndexingRejected(t *testing.T) {
	result := setupScenario(t, "credential", `${{ inputs["token"] }}`, nil, defaultChildInputs(), defaultChildSteps())
	if len(result.Flows) != 0 {
		t.Fatalf("expected no confirmed flow, got %#v", result.Flows)
	}
	if !hasDiagnostic(result.Diagnostics, DiagnosticDynamicInputReference, "credential") {
		t.Fatalf("expected nested_dynamic_input_reference, got %#v", result.Diagnostics)
	}
}

// 10. dynamic variable indexing rejected.
func TestLinkDynamicVariableIndexingRejected(t *testing.T) {
	result := setupScenario(t, "credential", `${{ inputs[var] }}`, nil, defaultChildInputs(), defaultChildSteps())
	if len(result.Flows) != 0 {
		t.Fatalf("expected no confirmed flow, got %#v", result.Flows)
	}
	if !hasDiagnostic(result.Diagnostics, DiagnosticDynamicInputReference, "credential") {
		t.Fatalf("expected nested_dynamic_input_reference, got %#v", result.Diagnostics)
	}
}

// 11. structured references / raw-value disagreement rejected.
func TestLinkValueReferenceDisagreementRejected(t *testing.T) {
	result := setupScenario(t, "credential", "${{ inputs.token }}", []domain.Reference{inputRef("other", 1)}, defaultChildInputs(), defaultChildSteps())
	if len(result.Flows) != 0 {
		t.Fatalf("Value/References disagreement must never produce a confirmed flow, got %#v", result.Flows)
	}
	if !hasDiagnostic(result.Diagnostics, DiagnosticUnsupportedInputExpression, "credential") {
		t.Fatalf("expected nested_unsupported_input_expression for disagreement, got %#v", result.Diagnostics)
	}
}

// 12. clean reference to a different parent input is silent.
func TestLinkCleanReferenceToDifferentParentInputSilent(t *testing.T) {
	result := setupScenario(t, "credential", "${{ inputs.username }}", []domain.Reference{inputRef("username", 1)}, defaultChildInputs(), defaultChildSteps())
	if len(result.Flows) != 0 {
		t.Fatalf("expected no confirmed flow for a different (possibly separately confirmed) parent input, got %#v", result.Flows)
	}
	if len(result.Diagnostics) != 0 {
		t.Fatalf("a clean reference to a different parent input must be silent, not an error, got %#v", result.Diagnostics)
	}
}

// 13. undeclared child alias diagnostic.
func TestLinkUndeclaredChildAliasDiagnostic(t *testing.T) {
	result := setupScenario(t, "mystery", "${{ inputs.token }}", []domain.Reference{inputRef("token", 1)}, defaultChildInputs(), defaultChildSteps())
	if len(result.Flows) != 0 {
		t.Fatalf("expected no confirmed flow for an undeclared alias, got %#v", result.Flows)
	}
	if !hasDiagnostic(result.Diagnostics, DiagnosticUndeclaredInput, "mystery") {
		t.Fatalf("expected nested_undeclared_input, got %#v", result.Diagnostics)
	}
}

// 14. required child input omitted diagnostic.
func TestLinkRequiredChildInputMissingDiagnostic(t *testing.T) {
	result := setupScenario(t, "unrelated", "literal", nil, defaultChildInputs(), defaultChildSteps())
	if !hasDiagnostic(result.Diagnostics, DiagnosticRequiredInputMissing, "credential") {
		t.Fatalf("expected nested_required_input_missing, got %#v", result.Diagnostics)
	}
}

// 15. required child input with a default is silent (no missing diagnostic).
func TestLinkRequiredChildInputWithDefaultSilent(t *testing.T) {
	def := "us-east-1"
	result := setupScenario(t, "unrelated", "literal", nil, []domain.ActionInputDefinition{inputDef("region", true, &def)}, []domain.ActionStep{plainStep("login", inputRef("region", 20))})
	if hasDiagnostic(result.Diagnostics, DiagnosticRequiredInputMissing, "region") {
		t.Fatalf("required input with a default must not produce nested_required_input_missing, got %#v", result.Diagnostics)
	}
}

// 16. optional child input omitted is silent.
func TestLinkOptionalChildInputOmittedSilent(t *testing.T) {
	result := setupScenario(t, "unrelated", "literal", nil, []domain.ActionInputDefinition{inputDef("region", false, nil)}, []domain.ActionStep{plainStep("login", inputRef("region", 20))})
	if len(result.Diagnostics) != 0 {
		t.Fatalf("optional missing child input must be silent, got %#v", result.Diagnostics)
	}
}

// 17. explicit empty string silent.
func TestLinkExplicitEmptyStringSilent(t *testing.T) {
	result := setupScenario(t, "credential", "", nil, defaultChildInputs(), defaultChildSteps())
	if len(result.Flows) != 0 || len(result.Diagnostics) != 0 {
		t.Fatalf("explicit empty-string binding must be silent with no flow, got flows=%#v diagnostics=%#v", result.Flows, result.Diagnostics)
	}
}

// 18. false silent.
func TestLinkFalseSilent(t *testing.T) {
	result := setupScenario(t, "credential", "false", nil, defaultChildInputs(), defaultChildSteps())
	if len(result.Flows) != 0 || len(result.Diagnostics) != 0 {
		t.Fatalf("literal false binding must be silent with no flow, got flows=%#v diagnostics=%#v", result.Flows, result.Diagnostics)
	}
}

// 19. zero silent.
func TestLinkZeroSilent(t *testing.T) {
	result := setupScenario(t, "credential", "0", nil, defaultChildInputs(), defaultChildSteps())
	if len(result.Flows) != 0 || len(result.Diagnostics) != 0 {
		t.Fatalf("literal zero binding must be silent with no flow, got flows=%#v diagnostics=%#v", result.Flows, result.Diagnostics)
	}
}

// 20. literal silent.
func TestLinkLiteralSilent(t *testing.T) {
	result := setupScenario(t, "credential", "production", nil, defaultChildInputs(), defaultChildSteps())
	if len(result.Flows) != 0 || len(result.Diagnostics) != 0 {
		t.Fatalf("literal binding must be silent with no flow, got flows=%#v diagnostics=%#v", result.Flows, result.Diagnostics)
	}
}

// 21. child input declared but unused produces no flow.
func TestLinkChildInputDeclaredButUnusedNoFlow(t *testing.T) {
	result := setupScenario(t, "credential", "${{ inputs.token }}", []domain.Reference{inputRef("token", 1)}, defaultChildInputs(), nil)
	if len(result.Flows) != 0 {
		t.Fatalf("expected no confirmed flow when the declared child input has zero internal usages, got %#v", result.Flows)
	}
	if len(result.Diagnostics) != 0 {
		t.Fatalf("zero-usage drop must not itself produce a diagnostic, got %#v", result.Diagnostics)
	}
}

// 22. child input used in multiple internal steps.
func TestLinkChildInputUsedInMultipleSteps(t *testing.T) {
	result := setupScenario(t, "credential", "${{ inputs.token }}", []domain.Reference{inputRef("token", 1)}, defaultChildInputs(),
		[]domain.ActionStep{plainStep("first", inputRef("credential", 10)), plainStep("second", inputRef("credential", 20))})
	if len(result.Flows) != 1 {
		t.Fatalf("expected exactly one flow, got %#v", result.Flows)
	}
	if len(result.Flows[0].Usages) != 2 {
		t.Fatalf("expected two child usages across steps 0 and 1, got %#v", result.Flows[0].Usages)
	}
}

// 23. same parent input forwarded to two aliases.
func TestLinkSameParentInputForwardedToTwoAliases(t *testing.T) {
	parent := action(dirA, []domain.ActionInputDefinition{inputDef("token", true, nil)},
		nestedUsesStep("step0", "./"+dirB,
			withBinding("username", "${{ inputs.token }}", inputRef("token", 1)),
			withBinding("password", "${{ inputs.token }}", inputRef("token", 1)),
		))
	child := action(dirB, []domain.ActionInputDefinition{inputDef("username", true, nil), inputDef("password", true, nil)},
		plainStep("login", inputRef("username", 20), inputRef("password", 21)))
	resolution := domain.CompositeActionResolution{
		Actions:     []domain.ActionMetadata{parent, child},
		NestedCalls: []domain.NestedCompositeActionCall{resolvedNestedCall(dirA, 0, dirB)},
	}
	rootFlows := compositeactionflow.Result{Flows: []compositeactionflow.ConfirmedInputFlow{
		rootFlow("caller.yml", "deploy", 0, dirA, "token", "PROD_TOKEN", usageAt(0, "step0")),
	}}
	result, err := Link(context.Background(), rootFlows, resolution)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Flows) != 2 {
		t.Fatalf("expected two independent child binding flows, got %#v", result.Flows)
	}
	aliases := map[string]bool{}
	for _, f := range result.Flows {
		aliases[f.ChildInputName] = true
		if f.ParentInputName != "token" {
			t.Fatalf("both aliases must be attributed to the token parent input, got %#v", f)
		}
	}
	if !aliases["username"] || !aliases["password"] {
		t.Fatalf("expected both username and password aliases confirmed, got %#v", result.Flows)
	}
}

// 24. two parent inputs forwarded to two aliases.
func TestLinkTwoParentInputsForwardedToTwoAliases(t *testing.T) {
	parent := action(dirA, []domain.ActionInputDefinition{inputDef("token", true, nil), inputDef("region", true, nil)},
		nestedUsesStep("step0", "./"+dirB,
			withBinding("alias1", "${{ inputs.token }}", inputRef("token", 1)),
			withBinding("alias2", "${{ inputs.region }}", inputRef("region", 1)),
		))
	child := action(dirB, []domain.ActionInputDefinition{inputDef("alias1", true, nil), inputDef("alias2", true, nil)},
		plainStep("login", inputRef("alias1", 20), inputRef("alias2", 21)))
	resolution := domain.CompositeActionResolution{
		Actions:     []domain.ActionMetadata{parent, child},
		NestedCalls: []domain.NestedCompositeActionCall{resolvedNestedCall(dirA, 0, dirB)},
	}
	rootFlows := compositeactionflow.Result{Flows: []compositeactionflow.ConfirmedInputFlow{
		rootFlow("caller.yml", "deploy", 0, dirA, "token", "PROD_TOKEN", usageAt(0, "step0")),
		rootFlow("caller.yml", "deploy", 0, dirA, "region", "STAGING_REGION", usageAt(0, "step0")),
	}}
	result, err := Link(context.Background(), rootFlows, resolution)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Flows) != 2 {
		t.Fatalf("expected two independent flows, one per root input, got %#v", result.Flows)
	}
	byAlias := map[string]ConfirmedNestedInputFlow{}
	for _, f := range result.Flows {
		byAlias[f.ChildInputName] = f
	}
	if byAlias["alias1"].ParentInputName != "token" || byAlias["alias2"].ParentInputName != "region" {
		t.Fatalf("aliases not correctly attributed to their source parent input: %#v", result.Flows)
	}
}

// 25. multiple nested call steps.
func TestLinkMultipleNestedCallSteps(t *testing.T) {
	parent := action(dirA, []domain.ActionInputDefinition{inputDef("token", true, nil)},
		nestedUsesStep("stepB", "./"+dirB, withBinding("credential", "${{ inputs.token }}", inputRef("token", 1))),
		nestedUsesStep("stepC", "./"+dirC, withBinding("credential", "${{ inputs.token }}", inputRef("token", 1))),
	)
	childB := action(dirB, []domain.ActionInputDefinition{inputDef("credential", true, nil)}, plainStep("login", inputRef("credential", 20)))
	childC := action(dirC, []domain.ActionInputDefinition{inputDef("credential", true, nil)}, plainStep("login", inputRef("credential", 20)))
	resolution := domain.CompositeActionResolution{
		Actions: []domain.ActionMetadata{parent, childB, childC},
		NestedCalls: []domain.NestedCompositeActionCall{
			resolvedNestedCall(dirA, 0, dirB),
			resolvedNestedCall(dirA, 1, dirC),
		},
	}
	rootFlows := compositeactionflow.Result{Flows: []compositeactionflow.ConfirmedInputFlow{
		rootFlow("caller.yml", "deploy", 0, dirA, "token", "PROD_TOKEN", usageAt(0, "stepB"), usageAt(1, "stepC")),
	}}
	result, err := Link(context.Background(), rootFlows, resolution)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Flows) != 2 {
		t.Fatalf("expected two flows, one per nested call step, got %#v", result.Flows)
	}
	children := map[string]bool{}
	for _, f := range result.Flows {
		children[f.ChildCanonicalDirectory] = true
	}
	if !children[dirB] || !children[dirC] {
		t.Fatalf("expected both B and C reached, got %#v", result.Flows)
	}
}

// 26. same workflow calls the root action twice.
func TestLinkSameWorkflowCallsRootActionTwice(t *testing.T) {
	parent := action(dirA, []domain.ActionInputDefinition{inputDef("token", true, nil)},
		nestedUsesStep("step0", "./"+dirB, withBinding("credential", "${{ inputs.token }}", inputRef("token", 1))))
	child := action(dirB, []domain.ActionInputDefinition{inputDef("credential", true, nil)}, plainStep("login", inputRef("credential", 20)))
	resolution := domain.CompositeActionResolution{
		Actions:     []domain.ActionMetadata{parent, child},
		NestedCalls: []domain.NestedCompositeActionCall{resolvedNestedCall(dirA, 0, dirB)},
	}
	rootFlows := compositeactionflow.Result{Flows: []compositeactionflow.ConfirmedInputFlow{
		rootFlow("caller.yml", "deploy", 0, dirA, "token", "PROD_TOKEN", usageAt(0, "step0")),
		rootFlow("caller.yml", "deploy", 1, dirA, "token", "STAGING_TOKEN", usageAt(0, "step0")),
	}}
	result, err := Link(context.Background(), rootFlows, resolution)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Flows) != 2 {
		t.Fatalf("expected two separated flows, got %#v", result.Flows)
	}
	bySecret := map[string]ConfirmedNestedInputFlow{}
	for _, f := range result.Flows {
		bySecret[f.RootSourceSecret] = f
	}
	if bySecret["PROD_TOKEN"].RootCallerStepIndex != 0 || bySecret["STAGING_TOKEN"].RootCallerStepIndex != 1 {
		t.Fatalf("flows not correctly attributed to their root call site: %#v", result.Flows)
	}
}

// 27. two root workflows call the same action.
func TestLinkTwoRootWorkflowsCallSameAction(t *testing.T) {
	parent := action(dirA, []domain.ActionInputDefinition{inputDef("token", true, nil)},
		nestedUsesStep("step0", "./"+dirB, withBinding("credential", "${{ inputs.token }}", inputRef("token", 1))))
	child := action(dirB, []domain.ActionInputDefinition{inputDef("credential", true, nil)}, plainStep("login", inputRef("credential", 20)))
	resolution := domain.CompositeActionResolution{
		Actions:     []domain.ActionMetadata{parent, child},
		NestedCalls: []domain.NestedCompositeActionCall{resolvedNestedCall(dirA, 0, dirB)},
	}
	rootFlows := compositeactionflow.Result{Flows: []compositeactionflow.ConfirmedInputFlow{
		rootFlow("a.yml", "deploy", 0, dirA, "token", "PROD_TOKEN", usageAt(0, "step0")),
		rootFlow("b.yml", "deploy", 0, dirA, "token", "PROD_TOKEN", usageAt(0, "step0")),
	}}
	result, err := Link(context.Background(), rootFlows, resolution)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Flows) != 2 {
		t.Fatalf("expected two separated flows (one per workflow), got %#v", result.Flows)
	}
	if result.Flows[0].RootCallerWorkflow == result.Flows[1].RootCallerWorkflow {
		t.Fatalf("flows must be attributed to distinct root workflows: %#v", result.Flows)
	}
}

// 28. A and C both call B.
func TestLinkAAndCBothCallB(t *testing.T) {
	parentA := action(dirA, []domain.ActionInputDefinition{inputDef("token", true, nil)},
		nestedUsesStep("step0", "./"+dirB, withBinding("credential", "${{ inputs.token }}", inputRef("token", 1))))
	parentC := action(dirC, []domain.ActionInputDefinition{inputDef("token", true, nil)},
		nestedUsesStep("step0", "./"+dirB, withBinding("credential", "${{ inputs.token }}", inputRef("token", 1))))
	child := action(dirB, []domain.ActionInputDefinition{inputDef("credential", true, nil)}, plainStep("login", inputRef("credential", 20)))
	resolution := domain.CompositeActionResolution{
		Actions: []domain.ActionMetadata{parentA, parentC, child},
		NestedCalls: []domain.NestedCompositeActionCall{
			resolvedNestedCall(dirA, 0, dirB),
			resolvedNestedCall(dirC, 0, dirB),
		},
	}
	rootFlows := compositeactionflow.Result{Flows: []compositeactionflow.ConfirmedInputFlow{
		rootFlow("caller.yml", "deploy", 0, dirA, "token", "PROD_TOKEN", usageAt(0, "step0")),
		rootFlow("caller.yml", "deploy", 1, dirC, "token", "PROD_TOKEN", usageAt(0, "step0")),
	}}
	result, err := Link(context.Background(), rootFlows, resolution)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Flows) != 2 {
		t.Fatalf("expected two independent flows, one via A and one via C, got %#v", result.Flows)
	}
	parents := map[string]bool{}
	for _, f := range result.Flows {
		parents[f.ParentCanonicalDirectory] = true
	}
	if !parents[dirA] || !parents[dirC] {
		t.Fatalf("expected both A and C recorded as immediate parents of B: %#v", result.Flows)
	}
}

// 29. diamond paths (A->B->D and A->C->D) stay distinct.
func TestLinkDiamondPathsStayDistinct(t *testing.T) {
	parentA := action(dirA, []domain.ActionInputDefinition{inputDef("token", true, nil)},
		nestedUsesStep("stepB", "./"+dirB, withBinding("credential", "${{ inputs.token }}", inputRef("token", 1))),
		nestedUsesStep("stepC", "./"+dirC, withBinding("credential", "${{ inputs.token }}", inputRef("token", 1))),
	)
	childB := action(dirB, []domain.ActionInputDefinition{inputDef("credential", true, nil)},
		nestedUsesStep("stepD", "./"+dirD, withBinding("secret", "${{ inputs.credential }}", inputRef("credential", 1))))
	childC := action(dirC, []domain.ActionInputDefinition{inputDef("credential", true, nil)},
		nestedUsesStep("stepD", "./"+dirD, withBinding("secret", "${{ inputs.credential }}", inputRef("credential", 1))))
	childD := action(dirD, []domain.ActionInputDefinition{inputDef("secret", true, nil)}, plainStep("login", inputRef("secret", 20)))
	resolution := domain.CompositeActionResolution{
		Actions: []domain.ActionMetadata{parentA, childB, childC, childD},
		NestedCalls: []domain.NestedCompositeActionCall{
			resolvedNestedCall(dirA, 0, dirB),
			resolvedNestedCall(dirA, 1, dirC),
			resolvedNestedCall(dirB, 0, dirD),
			resolvedNestedCall(dirC, 0, dirD),
		},
	}
	rootFlows := compositeactionflow.Result{Flows: []compositeactionflow.ConfirmedInputFlow{
		rootFlow("caller.yml", "deploy", 0, dirA, "token", "PROD_TOKEN", usageAt(0, "stepB"), usageAt(1, "stepC")),
	}}
	result, err := Link(context.Background(), rootFlows, resolution)
	if err != nil {
		t.Fatal(err)
	}
	var toD []ConfirmedNestedInputFlow
	for _, f := range result.Flows {
		if f.ChildCanonicalDirectory == dirD {
			toD = append(toD, f)
		}
	}
	if len(toD) != 2 {
		t.Fatalf("expected two distinct flows reaching D (one via B, one via C), got %#v", toD)
	}
	if toD[0].ParentCanonicalDirectory == toD[1].ParentCanonicalDirectory {
		t.Fatalf("both diamond branches reaching D must have distinct immediate parents: %#v", toD)
	}
	if reflect.DeepEqual(toD[0].CallPath, toD[1].CallPath) {
		t.Fatalf("both diamond branches reaching D must have distinct call paths: %#v", toD)
	}
}

// 30. same alias name at every level.
func TestLinkSameAliasNameAtEveryLevel(t *testing.T) {
	parent := action(dirA, []domain.ActionInputDefinition{inputDef("token", true, nil)},
		nestedUsesStep("step0", "./"+dirB, withBinding("token", "${{ inputs.token }}", inputRef("token", 1))))
	child := action(dirB, []domain.ActionInputDefinition{inputDef("token", true, nil)},
		nestedUsesStep("step0", "./"+dirC, withBinding("token", "${{ inputs.token }}", inputRef("token", 1))))
	grandchild := action(dirC, []domain.ActionInputDefinition{inputDef("token", true, nil)}, plainStep("login", inputRef("token", 20)))
	resolution := domain.CompositeActionResolution{
		Actions: []domain.ActionMetadata{parent, child, grandchild},
		NestedCalls: []domain.NestedCompositeActionCall{
			resolvedNestedCall(dirA, 0, dirB),
			resolvedNestedCall(dirB, 0, dirC),
		},
	}
	rootFlows := compositeactionflow.Result{Flows: []compositeactionflow.ConfirmedInputFlow{
		rootFlow("caller.yml", "deploy", 0, dirA, "token", "PROD_TOKEN", usageAt(0, "step0")),
	}}
	result, err := Link(context.Background(), rootFlows, resolution)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Flows) != 2 {
		t.Fatalf("expected two chained flows (A->B, B->C), got %#v", result.Flows)
	}
	for _, f := range result.Flows {
		if f.ChildInputName != "token" || f.ParentInputName != "token" {
			t.Fatalf("same alias name at every level must resolve correctly, got %#v", f)
		}
	}
}

// 31. source secret and all aliases share the same name.
func TestLinkSourceSecretAndAliasesSameName(t *testing.T) {
	parent := action(dirA, []domain.ActionInputDefinition{inputDef("TOKEN", true, nil)},
		nestedUsesStep("step0", "./"+dirB, withBinding("TOKEN", "${{ inputs.TOKEN }}", inputRef("TOKEN", 1))))
	child := action(dirB, []domain.ActionInputDefinition{inputDef("TOKEN", true, nil)}, plainStep("login", inputRef("TOKEN", 20)))
	resolution := domain.CompositeActionResolution{
		Actions:     []domain.ActionMetadata{parent, child},
		NestedCalls: []domain.NestedCompositeActionCall{resolvedNestedCall(dirA, 0, dirB)},
	}
	rootFlows := compositeactionflow.Result{Flows: []compositeactionflow.ConfirmedInputFlow{
		rootFlow("caller.yml", "deploy", 0, dirA, "TOKEN", "TOKEN", usageAt(0, "step0")),
	}}
	result, err := Link(context.Background(), rootFlows, resolution)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Flows) != 1 {
		t.Fatalf("expected one flow, got %#v", result.Flows)
	}
	f := result.Flows[0]
	if f.RootSourceSecret != "TOKEN" || f.RootInputName != "TOKEN" || f.ChildInputName != "TOKEN" {
		t.Fatalf("same-named source secret/input/alias must still resolve correctly, got %#v", f)
	}
}

// 32. direct cycle (A -> A) stops expansion.
func TestLinkDirectCycleStopsExpansion(t *testing.T) {
	parent := action(dirA, []domain.ActionInputDefinition{inputDef("token", true, nil)},
		nestedUsesStep("step0", "./"+dirA, withBinding("token", "${{ inputs.token }}", inputRef("token", 1))))
	resolution := domain.CompositeActionResolution{
		Actions:     []domain.ActionMetadata{parent},
		NestedCalls: []domain.NestedCompositeActionCall{resolvedNestedCall(dirA, 0, dirA)},
	}
	rootFlows := compositeactionflow.Result{Flows: []compositeactionflow.ConfirmedInputFlow{
		rootFlow("caller.yml", "deploy", 0, dirA, "token", "PROD_TOKEN", usageAt(0, "step0")),
	}}
	result, err := Link(context.Background(), rootFlows, resolution)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Flows) != 0 {
		t.Fatalf("a direct self-cycle must never produce a confirmed flow, got %#v", result.Flows)
	}
	if len(result.Diagnostics) != 0 {
		t.Fatalf("CA3B must not emit its own cycle diagnostic (CA3A owns it), got %#v", result.Diagnostics)
	}
}

// 33. indirect cycle (A -> B -> A) stops expansion.
func TestLinkIndirectCycleStopsExpansion(t *testing.T) {
	parent := action(dirA, []domain.ActionInputDefinition{inputDef("token", true, nil)},
		nestedUsesStep("step0", "./"+dirB, withBinding("token", "${{ inputs.token }}", inputRef("token", 1))))
	child := action(dirB, []domain.ActionInputDefinition{inputDef("token", true, nil)},
		nestedUsesStep("step0", "./"+dirA, withBinding("token", "${{ inputs.token }}", inputRef("token", 1))))
	resolution := domain.CompositeActionResolution{
		Actions: []domain.ActionMetadata{parent, child},
		NestedCalls: []domain.NestedCompositeActionCall{
			resolvedNestedCall(dirA, 0, dirB),
			resolvedNestedCall(dirB, 0, dirA),
		},
	}
	rootFlows := compositeactionflow.Result{Flows: []compositeactionflow.ConfirmedInputFlow{
		rootFlow("caller.yml", "deploy", 0, dirA, "token", "PROD_TOKEN", usageAt(0, "step0")),
	}}
	result, err := Link(context.Background(), rootFlows, resolution)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Flows) != 1 {
		t.Fatalf("expected exactly one flow (A->B) before the cycle back to A stops expansion, got %#v", result.Flows)
	}
	if result.Flows[0].ChildCanonicalDirectory != dirB {
		t.Fatalf("expected the single flow to reach B, got %#v", result.Flows[0])
	}
	if len(result.Diagnostics) != 0 {
		t.Fatalf("CA3B must not emit its own cycle diagnostic, got %#v", result.Diagnostics)
	}
}

// 34. longer cycle (A -> B -> C -> A) stops expansion.
func TestLinkLongerCycleStopsExpansion(t *testing.T) {
	parentA := action(dirA, []domain.ActionInputDefinition{inputDef("token", true, nil)},
		nestedUsesStep("step0", "./"+dirB, withBinding("token", "${{ inputs.token }}", inputRef("token", 1))))
	parentB := action(dirB, []domain.ActionInputDefinition{inputDef("token", true, nil)},
		nestedUsesStep("step0", "./"+dirC, withBinding("token", "${{ inputs.token }}", inputRef("token", 1))))
	parentC := action(dirC, []domain.ActionInputDefinition{inputDef("token", true, nil)},
		nestedUsesStep("step0", "./"+dirA, withBinding("token", "${{ inputs.token }}", inputRef("token", 1))))
	resolution := domain.CompositeActionResolution{
		Actions: []domain.ActionMetadata{parentA, parentB, parentC},
		NestedCalls: []domain.NestedCompositeActionCall{
			resolvedNestedCall(dirA, 0, dirB),
			resolvedNestedCall(dirB, 0, dirC),
			resolvedNestedCall(dirC, 0, dirA),
		},
	}
	rootFlows := compositeactionflow.Result{Flows: []compositeactionflow.ConfirmedInputFlow{
		rootFlow("caller.yml", "deploy", 0, dirA, "token", "PROD_TOKEN", usageAt(0, "step0")),
	}}
	result, err := Link(context.Background(), rootFlows, resolution)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Flows) != 2 {
		t.Fatalf("expected exactly two flows (A->B, B->C) before the cycle back to A stops expansion, got %#v", result.Flows)
	}
	if len(result.Diagnostics) != 0 {
		t.Fatalf("CA3B must not emit its own cycle diagnostic, got %#v", result.Diagnostics)
	}
}

// buildChain constructs a length-action chain, each forwarding "token" into
// the next via a nested uses: step, the final link having a plain internal
// usage instead of a further nested call.
func buildChain(length int) (domain.CompositeActionResolution, compositeactionflow.Result) {
	var actions []domain.ActionMetadata
	var nestedCalls []domain.NestedCompositeActionCall
	for i := 0; i < length; i++ {
		dir := fmt.Sprintf(".github/actions/chain%d", i)
		if i == length-1 {
			actions = append(actions, action(dir, []domain.ActionInputDefinition{inputDef("token", true, nil)}, plainStep("login", inputRef("token", 20))))
			continue
		}
		next := fmt.Sprintf(".github/actions/chain%d", i+1)
		actions = append(actions, action(dir, []domain.ActionInputDefinition{inputDef("token", true, nil)},
			nestedUsesStep("step0", "./"+next, withBinding("token", "${{ inputs.token }}", inputRef("token", 1)))))
		nestedCalls = append(nestedCalls, resolvedNestedCall(dir, 0, next))
	}
	resolution := domain.CompositeActionResolution{Actions: actions, NestedCalls: nestedCalls}
	rootFlows := compositeactionflow.Result{Flows: []compositeactionflow.ConfirmedInputFlow{
		rootFlow("caller.yml", "deploy", 0, ".github/actions/chain0", "token", "PROD_TOKEN", usageAt(0, "step0")),
	}}
	return resolution, rootFlows
}

// 35. depth 10 supported: 10 actions on the path, 9 forwarding transitions,
// all reachable including the deepest child's own internal usage.
func TestLinkDepthTenSupported(t *testing.T) {
	resolution, rootFlows := buildChain(10)
	result, err := Link(context.Background(), rootFlows, resolution)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Flows) != 9 {
		t.Fatalf("expected exactly 9 forwarding transitions for a 10-action chain, got %d: %#v", len(result.Flows), result.Flows)
	}
	reachedDeepest := false
	for _, f := range result.Flows {
		if f.ChildCanonicalDirectory == ".github/actions/chain9" {
			reachedDeepest = true
		}
	}
	if !reachedDeepest {
		t.Fatal("expected the chain's 10th (deepest) action to be reached")
	}
}

// 36. attempted depth 11 is stopped: the 10th transition (into the 11th
// action) never produces a flow, while the first 9 transitions still do.
func TestLinkAttemptedDepthElevenStopped(t *testing.T) {
	resolution, rootFlows := buildChain(11)
	result, err := Link(context.Background(), rootFlows, resolution)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Flows) != 9 {
		t.Fatalf("expected exactly 9 forwarding transitions (the 10th must be stopped), got %d: %#v", len(result.Flows), result.Flows)
	}
	for _, f := range result.Flows {
		if f.ChildCanonicalDirectory == ".github/actions/chain10" {
			t.Fatalf("the 11th action must never be reached, got %#v", f)
		}
	}
	if len(result.Diagnostics) != 0 {
		t.Fatalf("CA3B must not emit its own depth diagnostic (CA3A owns it), got %#v", result.Diagnostics)
	}
}

// 37/38/39/40. external, Docker, non-composite (JS/Docker local action), and
// malformed/unresolved nested calls all produce no flow and no diagnostic —
// CA3B only ever expands through resolved_local_composite.
func TestLinkNonResolvedNestedStatusesProduceNoFlow(t *testing.T) {
	statuses := []domain.CompositeActionResolutionStatus{
		domain.CompositeActionOpaqueExternal,
		domain.CompositeActionOpaqueDocker,
		domain.CompositeActionUnsupportedExpression,
		domain.CompositeActionTargetNotComposite,
		domain.CompositeActionRejectedPath,
		domain.CompositeActionMetadataMissing,
		domain.CompositeActionMetadataAmbiguous,
		domain.CompositeActionMalformedMetadata,
	}
	for _, status := range statuses {
		t.Run(string(status), func(t *testing.T) {
			parent := action(dirA, []domain.ActionInputDefinition{inputDef("token", true, nil)},
				nestedUsesStep("step0", "./"+dirB, withBinding("credential", "${{ inputs.token }}", inputRef("token", 1))))
			resolution := domain.CompositeActionResolution{
				Actions:     []domain.ActionMetadata{parent},
				NestedCalls: []domain.NestedCompositeActionCall{nestedCallWithStatus(dirA, 0, dirB, status)},
			}
			rootFlows := compositeactionflow.Result{Flows: []compositeactionflow.ConfirmedInputFlow{
				rootFlow("caller.yml", "deploy", 0, dirA, "token", "PROD_TOKEN", usageAt(0, "step0")),
			}}
			result, err := Link(context.Background(), rootFlows, resolution)
			if err != nil {
				t.Fatal(err)
			}
			if len(result.Flows) != 0 || len(result.Diagnostics) != 0 {
				t.Fatalf("status %s: expected no flow and no diagnostics, got flows=%#v diagnostics=%#v", status, result.Flows, result.Diagnostics)
			}
		})
	}
}

// 41. deterministic output.
func TestLinkDeterministicOutput(t *testing.T) {
	parent := action(dirA, []domain.ActionInputDefinition{inputDef("token", true, nil)},
		nestedUsesStep("step0", "./"+dirB, withBinding("credential", "${{ inputs.token }}", inputRef("token", 1))))
	child := action(dirB, []domain.ActionInputDefinition{inputDef("credential", true, nil)}, plainStep("login", inputRef("credential", 20)))
	resolution := domain.CompositeActionResolution{
		Actions:     []domain.ActionMetadata{parent, child},
		NestedCalls: []domain.NestedCompositeActionCall{resolvedNestedCall(dirA, 0, dirB)},
	}
	rootFlows := compositeactionflow.Result{Flows: []compositeactionflow.ConfirmedInputFlow{
		rootFlow("caller.yml", "deploy", 0, dirA, "token", "PROD_TOKEN", usageAt(0, "step0")),
	}}
	first, err := Link(context.Background(), rootFlows, resolution)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Link(context.Background(), rootFlows, resolution)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("Link is not deterministic:\nfirst=%#v\nsecond=%#v", first, second)
	}
}

// 42. immutable result slices: mutating one Link result's nested slices must
// never affect a separately produced result.
func TestLinkImmutableResultSlices(t *testing.T) {
	parent := action(dirA, []domain.ActionInputDefinition{inputDef("token", true, nil)},
		nestedUsesStep("step0", "./"+dirB, withBinding("credential", "${{ inputs.token }}", inputRef("token", 1))))
	child := action(dirB, []domain.ActionInputDefinition{inputDef("credential", true, nil)}, plainStep("login", inputRef("credential", 20)))
	resolution := domain.CompositeActionResolution{
		Actions:     []domain.ActionMetadata{parent, child},
		NestedCalls: []domain.NestedCompositeActionCall{resolvedNestedCall(dirA, 0, dirB)},
	}
	rootFlows := compositeactionflow.Result{Flows: []compositeactionflow.ConfirmedInputFlow{
		rootFlow("caller.yml", "deploy", 0, dirA, "token", "PROD_TOKEN", usageAt(0, "step0")),
	}}
	first, err := Link(context.Background(), rootFlows, resolution)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Link(context.Background(), rootFlows, resolution)
	if err != nil {
		t.Fatal(err)
	}

	first.Flows[0].CallPath[0].ChildCanonicalDirectory = "MUTATED"
	if second.Flows[0].CallPath[0].ChildCanonicalDirectory == "MUTATED" {
		t.Fatal("mutating one result's CallPath affected a separately linked result")
	}

	first.Flows[0].Usages = append(first.Flows[0].Usages, InputUsage{ActionStepIndex: 99})
	if len(second.Flows[0].Usages) == len(first.Flows[0].Usages) {
		t.Fatal("mutating one result's Usages affected a separately linked result")
	}
}

// 43. cancellation returns empty result and error.
func TestLinkContextCancellationReturnsEmptyResultAndError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, err := Link(ctx, compositeactionflow.Result{}, domain.CompositeActionResolution{})
	if err == nil {
		t.Fatal("expected an error for a canceled context")
	}
	if len(result.Flows) != 0 || len(result.Diagnostics) != 0 {
		t.Fatalf("expected an empty result, got %#v", result)
	}
}

// 44. required-missing diagnostic deduplication: two independently confirmed
// parent inputs both reach the same nested call site; the missing required
// child input must be reported exactly once, not once per sibling alias.
func TestLinkRequiredMissingDiagnosticDeduplication(t *testing.T) {
	parent := action(dirA, []domain.ActionInputDefinition{inputDef("token", true, nil), inputDef("region", true, nil)},
		nestedUsesStep("step0", "./"+dirB,
			withBinding("alias1", "${{ inputs.token }}", inputRef("token", 1)),
			withBinding("alias2", "${{ inputs.region }}", inputRef("region", 1)),
		))
	child := action(dirB, []domain.ActionInputDefinition{
		inputDef("alias1", true, nil), inputDef("alias2", true, nil), inputDef("missing_required", true, nil),
	}, plainStep("login", inputRef("alias1", 20), inputRef("alias2", 21)))
	resolution := domain.CompositeActionResolution{
		Actions:     []domain.ActionMetadata{parent, child},
		NestedCalls: []domain.NestedCompositeActionCall{resolvedNestedCall(dirA, 0, dirB)},
	}
	rootFlows := compositeactionflow.Result{Flows: []compositeactionflow.ConfirmedInputFlow{
		rootFlow("caller.yml", "deploy", 0, dirA, "token", "PROD_TOKEN", usageAt(0, "step0")),
		rootFlow("caller.yml", "deploy", 0, dirA, "region", "STAGING_REGION", usageAt(0, "step0")),
	}}
	result, err := Link(context.Background(), rootFlows, resolution)
	if err != nil {
		t.Fatal(err)
	}
	if count := countDiagnostics(result.Diagnostics, DiagnosticRequiredInputMissing); count != 1 {
		t.Fatalf("expected exactly one required_input_missing diagnostic despite two sibling expansions reaching the same call site, got %d: %#v", count, result.Diagnostics)
	}
}

// sanity: MaxCompositeActionNestingDepth is the constant this package's own
// depth gate is built against (imported, never redeclared).
func TestLinkUsesCompositeActionNestingDepthConstant(t *testing.T) {
	if compositeaction.MaxCompositeActionNestingDepth != 10 {
		t.Fatalf("expected MaxCompositeActionNestingDepth == 10, got %d", compositeaction.MaxCompositeActionNestingDepth)
	}
}
