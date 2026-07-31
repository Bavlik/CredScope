package analysis

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Bavlik/CredScope/internal/domain"
	"github.com/Bavlik/CredScope/internal/reporters"
	"github.com/Bavlik/CredScope/internal/reporters/html"
	"github.com/Bavlik/CredScope/internal/reporters/jsonreport"
	"github.com/Bavlik/CredScope/internal/reporters/sarif"
	"github.com/Bavlik/CredScope/internal/reporters/terminal"
)

// caCanonicalActionWithInput builds a resolved composite action declaring one
// required input and one internal step that reads it via
// ${{ inputs.<name> }} — the minimal shape needed to exercise the real,
// end-to-end analysis.Analyze -> compositeactionflow.Link -> graph.Build
// wiring, as opposed to the isolated per-package unit tests.
func caCanonicalActionWithInput(directory, name, inputName string) domain.ActionMetadata {
	return domain.ActionMetadata{
		Directory: directory, File: directory + "/action.yml", Name: name,
		Inputs: []domain.ActionInputDefinition{{Name: inputName, Required: true, Evidence: caEvidence(directory+"/action.yml", 2, "inputs."+inputName)}},
		Runs: domain.ActionRuns{Using: "composite", Steps: []domain.ActionStep{
			{
				ID: "deploy-step",
				References: []domain.Reference{
					{Kind: domain.ReferenceActionInput, Name: inputName, Evidence: caEvidence(directory+"/action.yml", 5, "runs.steps[0]")},
				},
			},
		}},
		Evidence: caEvidence(directory+"/action.yml", 1, "action"),
	}
}

func caJobWithCallSiteBinding(file, id, uses, inputName, secretName string) domain.WorkflowJob {
	step := domain.WorkflowStep{
		ID:     "call-step",
		Action: &domain.ActionReference{Reference: uses, Local: true, Evidence: caEvidence(file, 3, "uses")},
		With: []domain.ActionCallInputBinding{
			{Name: inputName, Value: "${{ secrets." + secretName + " }}", References: []domain.Reference{
				{Kind: domain.ReferenceSecret, Name: secretName, Evidence: caEvidence(file, 3, "with."+inputName)},
			}, Evidence: caEvidence(file, 3, "with."+inputName)},
		},
		References: []domain.Reference{
			{Kind: domain.ReferenceSecret, Name: secretName, Evidence: caEvidence(file, 3, "with."+inputName)},
		},
	}
	return domain.WorkflowJob{ID: id, Evidence: caEvidence(file, 2, "jobs."+id), Steps: []domain.WorkflowStep{step}}
}

// End-to-end proof that analysis.Analyze wires the pure linker into graph
// construction: a workflow-step `with:` binding whose entire value is
// exactly one static secret reference, targeting a resolved local composite
// action that declares and internally reads the bound input, produces the
// new confirmed binding/usage node chain in the final analyzed graph.
func TestAnalyzeCreatesConfirmedCompositeActionInputFlow(t *testing.T) {
	file := ".github/workflows/caller.yml"
	directory := ".github/actions/deploy"
	parsed := domain.ParsedRepository{
		Workflows: []domain.Workflow{caWorkflow(file, caJobWithCallSiteBinding(file, "build", "./"+directory, "token", "PROD_TOKEN"))},
		CompositeActions: domain.CompositeActionResolution{
			Actions: []domain.ActionMetadata{caCanonicalActionWithInput(directory, "Deploy", "token")},
			Calls:   []domain.CompositeActionCall{caResolvedCall(file, "build", 0, directory)},
		},
	}
	result := analyzeOrFatal(t, parsed)

	var binding, usage *domain.Node
	for i := range result.Graph.Nodes {
		switch result.Graph.Nodes[i].Type {
		case domain.NodeCompositeActionInputBinding:
			binding = &result.Graph.Nodes[i]
		case domain.NodeCompositeActionInputUsage:
			usage = &result.Graph.Nodes[i]
		}
	}
	if binding == nil {
		t.Fatal("expected a NodeCompositeActionInputBinding in the analyzed graph")
	}
	if usage == nil {
		t.Fatal("expected a NodeCompositeActionInputUsage in the analyzed graph")
	}
	if binding.Metadata["source_secret"] != "PROD_TOKEN" || binding.Metadata["input_name"] != "token" {
		t.Fatalf("binding metadata = %#v", binding.Metadata)
	}

	found := false
	for _, edge := range result.Graph.Edges {
		if edge.From == binding.ID && edge.To == usage.ID && edge.Type == domain.EdgeExplicitlyForwardedTo {
			found = true
		}
	}
	if !found {
		t.Fatal("expected binding -> usage EdgeExplicitlyForwardedTo edge in the analyzed graph")
	}
}

// An undeclared caller binding on a resolved local composite call surfaces
// as a deterministic, non-scoring warning end-to-end, and creates no
// confirmed-flow node.
func TestAnalyzeUndeclaredCompositeActionInputProducesWarningNotFlow(t *testing.T) {
	file := ".github/workflows/caller.yml"
	directory := ".github/actions/deploy"
	parsed := domain.ParsedRepository{
		Workflows: []domain.Workflow{caWorkflow(file, caJobWithCallSiteBinding(file, "build", "./"+directory, "mystery", "PROD_TOKEN"))},
		CompositeActions: domain.CompositeActionResolution{
			Actions: []domain.ActionMetadata{caCanonicalActionWithInput(directory, "Deploy", "token")},
			Calls:   []domain.CompositeActionCall{caResolvedCall(file, "build", 0, directory)},
		},
	}
	result := analyzeOrFatal(t, parsed)

	for _, node := range result.Graph.Nodes {
		if node.Type == domain.NodeCompositeActionInputBinding || node.Type == domain.NodeCompositeActionInputUsage {
			t.Fatalf("undeclared input must never produce a confirmed-flow node: %#v", node)
		}
	}
	foundWarning := false
	for _, w := range result.Warnings {
		if strings.Contains(w, "COMPOSITE_ACTION_INPUT_FLOW") && strings.Contains(w, "undeclared_input") {
			foundWarning = true
		}
	}
	if !foundWarning {
		t.Fatalf("expected an undeclared_input warning, got %#v", result.Warnings)
	}
	// The credential's score/severity must be driven entirely by its
	// ordinary generic step-reference exposure, never by the CA2 diagnostic.
	cred := findCredential(result, "PROD_TOKEN")
	if cred == nil {
		t.Fatal("expected PROD_TOKEN credential from the ordinary generic step reference")
	}
}

func caJobWithRawBindingValue(file, id, uses, inputName, rawValue string, refs []domain.Reference) domain.WorkflowJob {
	step := domain.WorkflowStep{
		ID:     "call-step",
		Action: &domain.ActionReference{Reference: uses, Local: true, Evidence: caEvidence(file, 3, "uses")},
		With: []domain.ActionCallInputBinding{
			{Name: inputName, Value: rawValue, References: refs, Evidence: caEvidence(file, 3, "with."+inputName)},
		},
		References: refs,
	}
	return domain.WorkflowJob{ID: id, Evidence: caEvidence(file, 2, "jobs."+id), Steps: []domain.WorkflowStep{step}}
}

// A literal marker embedded in a caller binding's raw value — including one
// that produces an unsupported_secret_expression diagnostic, the one CA2
// code path that must inspect the raw value to decide it is NOT a confirmed
// whole-value secret match — must never surface anywhere in the analyzed
// graph, warnings, or any rendered report format (JSON, SARIF, terminal,
// HTML).
const leakageMarker = "SUPER_SECRET_LITERAL_CA2_DO_NOT_SERIALIZE"

func TestAnalyzeNeverSerializesRawBindingValueOrExpressionText(t *testing.T) {
	file := ".github/workflows/caller.yml"
	directory := ".github/actions/deploy"
	rawValue := leakageMarker + "-${{ secrets.PROD_TOKEN }}"
	refs := []domain.Reference{{Kind: domain.ReferenceSecret, Name: "PROD_TOKEN", Evidence: caEvidence(file, 3, "with.token")}}
	parsed := domain.ParsedRepository{
		Workflows: []domain.Workflow{caWorkflow(file, caJobWithRawBindingValue(file, "build", "./"+directory, "token", rawValue, refs))},
		CompositeActions: domain.CompositeActionResolution{
			Actions: []domain.ActionMetadata{caCanonicalActionWithInput(directory, "Deploy", "token")},
			Calls:   []domain.CompositeActionCall{caResolvedCall(file, "build", 0, directory)},
		},
	}
	result := analyzeOrFatal(t, parsed)

	// The unsupported_secret_expression diagnostic must fire (proves the
	// code path that inspects binding.Value actually ran) and must produce
	// no confirmed-flow node.
	foundDiagnostic := false
	for _, w := range result.Warnings {
		if strings.Contains(w, "unsupported_secret_expression") {
			foundDiagnostic = true
		}
		if strings.Contains(w, leakageMarker) || strings.Contains(w, "${{") {
			t.Fatalf("warning leaked raw binding content: %q", w)
		}
	}
	if !foundDiagnostic {
		t.Fatal("expected an unsupported_secret_expression diagnostic")
	}
	for _, node := range result.Graph.Nodes {
		if node.Type == domain.NodeCompositeActionInputBinding || node.Type == domain.NodeCompositeActionInputUsage {
			t.Fatalf("prefixed marker+secret expression must never produce a confirmed-flow node: %#v", node)
		}
	}

	analysisJSON, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	assertNoLeakage(t, "AnalysisResult JSON", string(analysisJSON))

	input := reporters.Input{Tool: reporters.Tool{Name: "credscope", Version: "test"}, Scan: reporters.Scan{Repository: "test"}, Analysis: result}

	var jsonBuf, sarifBuf, terminalBuf, htmlBuf bytes.Buffer
	if err := jsonreport.New().Render(&jsonBuf, input, reporters.Options{}); err != nil {
		t.Fatal(err)
	}
	if err := sarif.New().Render(&sarifBuf, input, reporters.Options{}); err != nil {
		t.Fatal(err)
	}
	if err := terminal.New().Render(&terminalBuf, input, reporters.Options{}); err != nil {
		t.Fatal(err)
	}
	if err := html.New().Render(&htmlBuf, input, reporters.Options{}); err != nil {
		t.Fatal(err)
	}
	assertNoLeakage(t, "JSON report", jsonBuf.String())
	assertNoLeakage(t, "SARIF report", sarifBuf.String())
	assertNoLeakage(t, "terminal report", terminalBuf.String())
	assertNoLeakage(t, "HTML report", htmlBuf.String())
}

func assertNoLeakage(t *testing.T, label, output string) {
	t.Helper()
	for _, forbidden := range []string{leakageMarker, "${{", "secrets."} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("%s must never contain %q, got: %s", label, forbidden, output)
		}
	}
}

// New CA2 graph node metadata must never contain a caller literal value, an
// input default value, or an internal shell command body — only safe,
// non-secret identifiers (a secret NAME such as PROD_TOKEN remains allowed).
func TestAnalyzeCompositeActionInputFlowMetadataExcludesLiteralsAndDefaults(t *testing.T) {
	file := ".github/workflows/caller.yml"
	directory := ".github/actions/deploy"
	parsed := domain.ParsedRepository{
		Workflows: []domain.Workflow{caWorkflow(file, caJobWithCallSiteBinding(file, "build", "./"+directory, "token", "PROD_TOKEN"))},
		CompositeActions: domain.CompositeActionResolution{
			Actions: []domain.ActionMetadata{caCanonicalActionWithInput(directory, "Deploy", "token")},
			Calls:   []domain.CompositeActionCall{caResolvedCall(file, "build", 0, directory)},
		},
	}
	result := analyzeOrFatal(t, parsed)
	for _, node := range result.Graph.Nodes {
		if node.Type != domain.NodeCompositeActionInputBinding && node.Type != domain.NodeCompositeActionInputUsage {
			continue
		}
		for key, value := range node.Metadata {
			if strings.Contains(value, "${{") || strings.Contains(value, "secrets.") {
				t.Fatalf("metadata key %q leaked expression text: %q", key, value)
			}
		}
	}
}

// Analyze itself remains filesystem-free and propagates context
// cancellation from the pure linker it now invokes.
func TestAnalyzeContextCancellationPropagatesFromCompositeActionFlowLinker(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Analyze(ctx, domain.ParsedRepository{}, Options{})
	if err == nil {
		t.Fatal("expected an error for a canceled context")
	}
}
