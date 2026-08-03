package graph

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/Bavlik/CredScope/internal/compositeactionflow"
	"github.com/Bavlik/CredScope/internal/domain"
	"github.com/Bavlik/CredScope/internal/nestedcompositeactionflow"
)

func nestedInputFlow(rootWorkflow, rootJobID string, rootStepIndex int, rootInputName, rootSecret string,
	callPath []nestedcompositeactionflow.CallPathSegment,
	parentDir, parentInputName string, parentUsageStepIndex int, parentUsageStepID string,
	childDir, childInputName string, usages ...nestedcompositeactionflow.InputUsage,
) nestedcompositeactionflow.ConfirmedNestedInputFlow {
	return nestedcompositeactionflow.ConfirmedNestedInputFlow{
		RootCallerWorkflow: rootWorkflow, RootCallerJobID: rootJobID, RootCallerStepIndex: rootStepIndex,
		RootInputName: rootInputName, RootSourceSecret: rootSecret,
		CallPath:                 append([]nestedcompositeactionflow.CallPathSegment(nil), callPath...),
		ParentCanonicalDirectory: parentDir, ParentInputName: parentInputName,
		ParentUsageStepIndex: parentUsageStepIndex, ParentUsageStepID: parentUsageStepID,
		ChildCanonicalDirectory: childDir, ChildInputName: childInputName,
		BindingEvidence: testEvidence(childDir+"/action.yml", 3, "with."+childInputName),
		Usages:          usages,
	}
}

func nestedInputUsage(stepIndex int, stepID string, line int) nestedcompositeactionflow.InputUsage {
	return nestedcompositeactionflow.InputUsage{ActionStepIndex: stepIndex, ActionStepID: stepID, Evidence: testEvidence(".github/actions/child/action.yml", line, "runs.steps")}
}

func nestedInputDiagnostic(kind nestedcompositeactionflow.DiagnosticKind, rootWorkflow, rootJobID string, rootStepIndex int, parentDir string, parentStepIndex int, childDir, childInputName string) nestedcompositeactionflow.Diagnostic {
	return nestedcompositeactionflow.Diagnostic{
		Kind: kind, RootCallerWorkflow: rootWorkflow, RootCallerJobID: rootJobID, RootCallerStepIndex: rootStepIndex,
		ParentCanonicalDirectory: parentDir, ParentActionStepIndex: parentStepIndex,
		ChildCanonicalDirectory: childDir, ChildInputName: childInputName,
		Evidence: testEvidence(parentDir+"/action.yml", 3, "with."+childInputName),
	}
}

// oneHopScenario builds a minimal, single-level CA3B flow (the target
// example's own shape: deploy -> authenticate) on top of a CA2 root flow
// that already confirmed PROD_TOKEN into deploy's "token" input.
func oneHopScenario() BuildResult {
	root := confirmedFlow("caller.yml", "deploy", 0, "call-step", ".github/actions/deploy", "token", "PROD_TOKEN", usage(0, "authenticate", 10))
	nested := nestedInputFlow("caller.yml", "deploy", 0, "token", "PROD_TOKEN",
		[]nestedcompositeactionflow.CallPathSegment{{ParentCanonicalDirectory: ".github/actions/deploy", ParentActionStepIndex: 0, ChildCanonicalDirectory: ".github/actions/authenticate"}},
		".github/actions/deploy", "token", 0, "authenticate",
		".github/actions/authenticate", "credential", nestedInputUsage(0, "login", 20),
	)
	return BuildWithOptions(domain.ParsedRepository{}, BuildOptions{
		CompositeActionInputFlows:       compositeactionflow.Result{Flows: []compositeactionflow.ConfirmedInputFlow{root}},
		NestedCompositeActionInputFlows: nestedcompositeactionflow.Result{Flows: []nestedcompositeactionflow.ConfirmedNestedInputFlow{nested}},
	})
}

func findByLabel(nodes []domain.Node, kind domain.NodeType, label string) *domain.Node {
	for i := range nodes {
		if nodes[i].Type == kind && nodes[i].Label == label {
			return &nodes[i]
		}
	}
	return nil
}

// 45. exact parent usage -> child binding edge.
func TestNestedInputFlowParentUsageToChildBindingEdge(t *testing.T) {
	built := oneHopScenario()
	parentUsage := findByLabel(built.Graph.Nodes, domain.NodeCompositeActionInputUsage, "authenticate")
	childBinding := findByLabel(built.Graph.Nodes, domain.NodeCompositeActionInputBinding, "credential")
	if parentUsage == nil {
		t.Fatal("expected the CA2 root usage node (label \"authenticate\") to exist")
	}
	if childBinding == nil {
		t.Fatal("expected the CA3B child binding node (label \"credential\") to exist")
	}
	edge := forwardingEdge(built, parentUsage.ID, childBinding.ID)
	if edge == nil {
		t.Fatal("expected parent-usage -> child-binding EdgeExplicitlyForwardedTo edge")
	}
	if edge.EvidenceKind != domain.EvidenceConfirmedDataFlow || edge.Confidence != domain.ConfidenceConfirmed {
		t.Fatalf("unexpected edge shape: %#v", edge)
	}
	if edge.Metadata[compositeActionForwardingEdgeMetadataKey] != compositeActionForwardingEdgeMetadataValue {
		t.Fatalf("expected composite_action_forwarding_edge=true, got %#v", edge.Metadata)
	}
	if edge.Metadata[compositeActionForwardingHopMetadataKey] != compositeActionForwardingHopMetadataValue {
		t.Fatalf("expected composite_action_forwarding_hop=true on the level-crossing edge, got %#v", edge.Metadata)
	}
}

// 46. child binding -> child usage edge.
func TestNestedInputFlowChildBindingToChildUsageEdge(t *testing.T) {
	built := oneHopScenario()
	childBinding := findByLabel(built.Graph.Nodes, domain.NodeCompositeActionInputBinding, "credential")
	childUsage := findByLabel(built.Graph.Nodes, domain.NodeCompositeActionInputUsage, "login")
	if childBinding == nil || childUsage == nil {
		t.Fatalf("expected both child binding and child usage nodes, binding=%v usage=%v", childBinding, childUsage)
	}
	edge := forwardingEdge(built, childBinding.ID, childUsage.ID)
	if edge == nil {
		t.Fatal("expected child-binding -> child-usage EdgeExplicitlyForwardedTo edge")
	}
	if edge.EvidenceKind != domain.EvidenceConfirmedDataFlow || edge.Confidence != domain.ConfidenceConfirmed {
		t.Fatalf("unexpected edge shape: %#v", edge)
	}
	if edge.Metadata[compositeActionForwardingEdgeMetadataKey] != compositeActionForwardingEdgeMetadataValue {
		t.Fatalf("expected composite_action_forwarding_edge=true, got %#v", edge.Metadata)
	}
	if edge.Metadata[compositeActionForwardingHopMetadataKey] == compositeActionForwardingHopMetadataValue {
		t.Fatal("child-binding -> child-usage edge must not consume a composite forwarding hop")
	}
}

// 47. existing NodeTypes reused — no new node type is ever produced by CA3B.
func TestNestedInputFlowReusesExistingNodeTypes(t *testing.T) {
	built := oneHopScenario()
	for _, n := range built.Graph.Nodes {
		switch n.Type {
		case domain.NodeRepository, domain.NodeCredential, domain.NodeCompositeActionInputBinding, domain.NodeCompositeActionInputUsage:
			// allowed — NodeRepository is always created by BuildWithOptions.
		default:
			t.Fatalf("unexpected node type %q produced by a CA3B-only scenario: %#v", n.Type, n)
		}
	}
}

// 48. no canonical NodeCompositeAction ever becomes traversable through a
// CA3B chain.
func TestNestedInputFlowCanonicalActionNeverTraversable(t *testing.T) {
	directory := ".github/actions/deploy"
	wfFile := ".github/workflows/caller.yml"
	workflow := compositeWorkflow(wfFile, compositeJob("build", compositeActionStep("./"+directory)))
	parsed := domain.ParsedRepository{Workflows: []domain.Workflow{workflow}}
	resolution := domain.CompositeActionResolution{
		Actions: []domain.ActionMetadata{canonicalAction(directory, "Deploy"), canonicalAction(".github/actions/authenticate", "Authenticate")},
		Calls:   []domain.CompositeActionCall{resolvedCompositeCall(wfFile, "build", 0, directory)},
		NestedCalls: []domain.NestedCompositeActionCall{{
			ParentCanonicalDirectory: directory, ParentActionStepIndex: 0, CanonicalDirectory: ".github/actions/authenticate",
			Status: domain.CompositeActionResolvedLocalComposite, Evidence: testEvidence(directory+"/action.yml", 3, "runs.steps"),
		}},
	}
	root := confirmedFlow(wfFile, "build", 0, "", directory, "token", "PROD_TOKEN", usage(0, "authenticate", 10))
	nested := nestedInputFlow(wfFile, "build", 0, "token", "PROD_TOKEN",
		[]nestedcompositeactionflow.CallPathSegment{{ParentCanonicalDirectory: directory, ParentActionStepIndex: 0, ChildCanonicalDirectory: ".github/actions/authenticate"}},
		directory, "token", 0, "authenticate", ".github/actions/authenticate", "credential", nestedInputUsage(0, "login", 20),
	)
	built := BuildWithOptions(parsed, BuildOptions{
		CompositeActions:                resolution,
		CompositeActionInputFlows:       compositeactionflow.Result{Flows: []compositeactionflow.ConfirmedInputFlow{root}},
		NestedCompositeActionInputFlows: nestedcompositeactionflow.Result{Flows: []nestedcompositeactionflow.ConfirmedNestedInputFlow{nested}},
	})

	credentialID := credentialIDByLabel(built, "PROD_TOKEN")
	paths := Traverse(built.Graph, credentialID, 12)
	for _, canonical := range nodesByType(built.Graph.Nodes, domain.NodeCompositeAction) {
		if reachesNode(paths, canonical.ID) {
			t.Fatalf("confirmed nested flow traversal must never reach a canonical NodeCompositeAction: %s", canonical.Label)
		}
	}
}

// 49. structural CA1/CA3A edges remain non-traversable alongside CA3B edges.
func TestNestedInputFlowStructuralEdgesStayNonTraversable(t *testing.T) {
	directory := ".github/actions/deploy"
	child := ".github/actions/authenticate"
	resolution := domain.CompositeActionResolution{
		Actions: []domain.ActionMetadata{canonicalAction(directory, "Deploy"), canonicalAction(child, "Authenticate")},
		NestedCalls: []domain.NestedCompositeActionCall{{
			ParentCanonicalDirectory: directory, ParentActionStepIndex: 0, CanonicalDirectory: child,
			Status: domain.CompositeActionResolvedLocalComposite, Evidence: testEvidence(directory+"/action.yml", 3, "runs.steps"),
		}},
	}
	root := confirmedFlow("caller.yml", "deploy", 0, "call-step", directory, "token", "PROD_TOKEN", usage(0, "authenticate", 10))
	nested := nestedInputFlow("caller.yml", "deploy", 0, "token", "PROD_TOKEN",
		[]nestedcompositeactionflow.CallPathSegment{{ParentCanonicalDirectory: directory, ParentActionStepIndex: 0, ChildCanonicalDirectory: child}},
		directory, "token", 0, "authenticate", child, "credential", nestedInputUsage(0, "login", 20),
	)
	built := BuildWithOptions(domain.ParsedRepository{}, BuildOptions{
		CompositeActions:                resolution,
		CompositeActionInputFlows:       compositeactionflow.Result{Flows: []compositeactionflow.ConfirmedInputFlow{root}},
		NestedCompositeActionInputFlows: nestedcompositeactionflow.Result{Flows: []nestedcompositeactionflow.ConfirmedNestedInputFlow{nested}},
	})

	var structuralCount int
	for _, e := range built.Graph.Edges {
		if e.EvidenceKind == domain.EvidenceStructuralCallOnly {
			structuralCount++
		}
	}
	if structuralCount != 1 {
		t.Fatalf("expected exactly one CA3A structural edge to coexist, got %d: %#v", structuralCount, built.Graph.Edges)
	}
	credentialID := credentialIDByLabel(built, "PROD_TOKEN")
	paths := Traverse(built.Graph, credentialID, 12)
	for _, p := range paths {
		for _, e := range p.Edges {
			if e.EvidenceKind == domain.EvidenceStructuralCallOnly {
				t.Fatalf("a structural CA3A edge must never appear inside a traversed path: %#v", e)
			}
		}
	}
}

// 50. different root calls do not share nested nodes.
func TestNestedInputFlowDifferentRootCallsShareNoNestedNodes(t *testing.T) {
	directory := ".github/actions/deploy"
	child := ".github/actions/authenticate"
	prodRoot := confirmedFlow("caller.yml", "deploy", 0, "prod-step", directory, "token", "PROD_TOKEN", usage(0, "authenticate", 10))
	stagingRoot := confirmedFlow("caller.yml", "deploy", 1, "staging-step", directory, "token", "STAGING_TOKEN", usage(0, "authenticate", 10))
	prodNested := nestedInputFlow("caller.yml", "deploy", 0, "token", "PROD_TOKEN",
		[]nestedcompositeactionflow.CallPathSegment{{ParentCanonicalDirectory: directory, ParentActionStepIndex: 0, ChildCanonicalDirectory: child}},
		directory, "token", 0, "authenticate", child, "credential", nestedInputUsage(0, "login", 20))
	stagingNested := nestedInputFlow("caller.yml", "deploy", 1, "token", "STAGING_TOKEN",
		[]nestedcompositeactionflow.CallPathSegment{{ParentCanonicalDirectory: directory, ParentActionStepIndex: 0, ChildCanonicalDirectory: child}},
		directory, "token", 0, "authenticate", child, "credential", nestedInputUsage(0, "login", 20))

	built := BuildWithOptions(domain.ParsedRepository{}, BuildOptions{
		CompositeActionInputFlows:       compositeactionflow.Result{Flows: []compositeactionflow.ConfirmedInputFlow{prodRoot, stagingRoot}},
		NestedCompositeActionInputFlows: nestedcompositeactionflow.Result{Flows: []nestedcompositeactionflow.ConfirmedNestedInputFlow{prodNested, stagingNested}},
	})

	bindings := nodesByType(built.Graph.Nodes, domain.NodeCompositeActionInputBinding)
	usages := nodesByType(built.Graph.Nodes, domain.NodeCompositeActionInputUsage)
	if len(bindings) != 4 { // 2 CA2 root bindings + 2 CA3B child bindings
		t.Fatalf("expected 4 distinct binding nodes, got %d: %#v", len(bindings), bindings)
	}
	if len(usages) != 4 { // 2 CA2 root usages + 2 CA3B child usages
		t.Fatalf("expected 4 distinct usage nodes, got %d: %#v", len(usages), usages)
	}
	prodCredID := credentialIDByLabel(built, "PROD_TOKEN")
	stagingCredID := credentialIDByLabel(built, "STAGING_TOKEN")
	prodPaths := Traverse(built.Graph, prodCredID, 12)
	stagingPaths := Traverse(built.Graph, stagingCredID, 12)
	childCredentialBindings := nodesByType(built.Graph.Nodes, domain.NodeCompositeActionInputBinding)
	var prodChildBindingID, stagingChildBindingID string
	for _, b := range childCredentialBindings {
		if b.Metadata["root_source_secret"] == "PROD_TOKEN" {
			prodChildBindingID = b.ID
		}
		if b.Metadata["root_source_secret"] == "STAGING_TOKEN" {
			stagingChildBindingID = b.ID
		}
	}
	if prodChildBindingID == "" || stagingChildBindingID == "" {
		t.Fatalf("could not locate both child binding nodes: %#v", childCredentialBindings)
	}
	if prodChildBindingID == stagingChildBindingID {
		t.Fatal("PROD and STAGING nested chains must not share the same child binding node")
	}
	if reachesNode(prodPaths, stagingChildBindingID) {
		t.Fatal("PROD_TOKEN traversal must never reach STAGING's nested child binding node")
	}
	if reachesNode(stagingPaths, prodChildBindingID) {
		t.Fatal("STAGING_TOKEN traversal must never reach PROD's nested child binding node")
	}
}

// 51. diamond branches do not share call-specific child nodes.
func TestNestedInputFlowDiamondBranchesShareNoChildNodes(t *testing.T) {
	dirA, dirB, dirC, dirD := ".github/actions/a", ".github/actions/b", ".github/actions/c", ".github/actions/d"
	root := confirmedFlow("caller.yml", "deploy", 0, "call-step", dirA, "token", "PROD_TOKEN", usage(0, "stepB", 10), usage(1, "stepC", 11))
	viaB := nestedInputFlow("caller.yml", "deploy", 0, "token", "PROD_TOKEN",
		[]nestedcompositeactionflow.CallPathSegment{{ParentCanonicalDirectory: dirA, ParentActionStepIndex: 0, ChildCanonicalDirectory: dirB}, {ParentCanonicalDirectory: dirB, ParentActionStepIndex: 0, ChildCanonicalDirectory: dirD}},
		dirB, "token", 0, "stepD", dirD, "secret", nestedInputUsage(0, "login", 20))
	viaC := nestedInputFlow("caller.yml", "deploy", 0, "token", "PROD_TOKEN",
		[]nestedcompositeactionflow.CallPathSegment{{ParentCanonicalDirectory: dirA, ParentActionStepIndex: 1, ChildCanonicalDirectory: dirC}, {ParentCanonicalDirectory: dirC, ParentActionStepIndex: 0, ChildCanonicalDirectory: dirD}},
		dirC, "token", 0, "stepD", dirD, "secret", nestedInputUsage(0, "login", 20))
	intermediateB := nestedInputFlow("caller.yml", "deploy", 0, "token", "PROD_TOKEN",
		[]nestedcompositeactionflow.CallPathSegment{{ParentCanonicalDirectory: dirA, ParentActionStepIndex: 0, ChildCanonicalDirectory: dirB}},
		dirA, "token", 0, "stepB", dirB, "token", nestedInputUsage(0, "stepD", 15))
	intermediateC := nestedInputFlow("caller.yml", "deploy", 0, "token", "PROD_TOKEN",
		[]nestedcompositeactionflow.CallPathSegment{{ParentCanonicalDirectory: dirA, ParentActionStepIndex: 1, ChildCanonicalDirectory: dirC}},
		dirA, "token", 0, "stepC", dirC, "token", nestedInputUsage(0, "stepD", 15))

	built := BuildWithOptions(domain.ParsedRepository{}, BuildOptions{
		CompositeActionInputFlows:       compositeactionflow.Result{Flows: []compositeactionflow.ConfirmedInputFlow{root}},
		NestedCompositeActionInputFlows: nestedcompositeactionflow.Result{Flows: []nestedcompositeactionflow.ConfirmedNestedInputFlow{intermediateB, intermediateC, viaB, viaC}},
	})

	var dBindings []domain.Node
	for _, b := range nodesByType(built.Graph.Nodes, domain.NodeCompositeActionInputBinding) {
		if b.Metadata["child_canonical_directory"] == dirD {
			dBindings = append(dBindings, b)
		}
	}
	if len(dBindings) != 2 {
		t.Fatalf("expected two distinct binding nodes for D (one per diamond branch), got %d: %#v", len(dBindings), dBindings)
	}
	if dBindings[0].ID == dBindings[1].ID {
		t.Fatal("diamond branches must not collapse into one D binding node")
	}
}

// 52. no raw values or expressions in metadata.
func TestNestedInputFlowMetadataNeverLeaksRawValuesOrExpressions(t *testing.T) {
	built := oneHopScenario()
	encoded, err := json.Marshal(built.Graph)
	if err != nil {
		t.Fatal(err)
	}
	serialized := string(encoded)
	for _, forbidden := range []string{"${{", "secrets.", "default", "shell", "run\":"} {
		if strings.Contains(serialized, forbidden) {
			t.Fatalf("serialized graph must never contain %q, got: %s", forbidden, serialized)
		}
	}

	bindingAllowed := map[string]bool{
		"root_caller_workflow": true, "root_caller_job_id": true, "root_caller_step_index": true, "root_caller_step_id": true,
		"root_input_name": true, "root_source_secret": true, "nesting_depth": true, "parent_canonical_directory": true,
		"parent_action_step_index": true, "parent_action_step_id": true, "child_canonical_directory": true,
		"child_input_name": true, "flow_status": true,
	}
	for _, b := range nodesByType(built.Graph.Nodes, domain.NodeCompositeActionInputBinding) {
		if _, isCA2 := b.Metadata["caller_workflow"]; isCA2 {
			continue // this is a CA2-created binding node, covered by its own existing test.
		}
		for key := range b.Metadata {
			if !bindingAllowed[key] {
				t.Fatalf("unexpected nested binding metadata key %q: %#v", key, b.Metadata)
			}
		}
	}
	usageAllowed := map[string]bool{
		"root_caller_workflow": true, "root_caller_job_id": true, "root_caller_step_index": true, "root_input_name": true,
		"nesting_depth": true, "child_canonical_directory": true, "child_input_name": true, "child_usage_step_index": true,
		"child_usage_step_id": true, "flow_status": true,
	}
	for _, u := range nodesByType(built.Graph.Nodes, domain.NodeCompositeActionInputUsage) {
		if u.Metadata["child_canonical_directory"] == "" {
			continue // this is a CA2-created usage node, covered by its own existing test.
		}
		for key := range u.Metadata {
			if !usageAllowed[key] {
				t.Fatalf("unexpected nested usage metadata key %q: %#v", key, u.Metadata)
			}
		}
	}
}

// 53. no findings/score/remediation change — a pure architectural property:
// CA3B diagnostics only ever populate BuildResult.Warnings, never Findings,
// Credentials, or any scoring-relevant structure.
func TestNestedInputFlowDiagnosticsCreateNoFindingOrScoreEffect(t *testing.T) {
	diag := nestedInputDiagnostic(nestedcompositeactionflow.DiagnosticUndeclaredInput, "caller.yml", "deploy", 0, ".github/actions/deploy", 0, ".github/actions/authenticate", "mystery")
	built := BuildWithOptions(domain.ParsedRepository{}, BuildOptions{
		NestedCompositeActionInputFlows: nestedcompositeactionflow.Result{Diagnostics: []nestedcompositeactionflow.Diagnostic{diag}},
	})
	if len(built.Credentials) != 0 {
		t.Fatalf("a diagnostic alone must never create a credential, got %#v", built.Credentials)
	}
	// BuildWithOptions always creates the selected repository root node; the
	// diagnostic itself must create no additional node or edge.
	if len(built.Graph.Nodes) != 1 || built.Graph.Nodes[0].Type != domain.NodeRepository {
		t.Fatalf("a diagnostic alone must create no nodes beyond the repository root, got %#v", built.Graph.Nodes)
	}
	if len(built.Graph.Edges) != 0 {
		t.Fatalf("a diagnostic alone must create no graph edges, got %#v", built.Graph.Edges)
	}
	for _, w := range built.Warnings {
		if strings.Contains(w, "CRD") {
			t.Fatalf("warning must not resemble a CRD rule ID: %q", w)
		}
	}
}

// 54. warnings deterministic.
func TestNestedInputFlowWarningsDeterministic(t *testing.T) {
	diagnostics := []nestedcompositeactionflow.Diagnostic{
		nestedInputDiagnostic(nestedcompositeactionflow.DiagnosticUndeclaredInput, "caller.yml", "deploy", 0, ".github/actions/deploy", 0, ".github/actions/authenticate", "mystery"),
		nestedInputDiagnostic(nestedcompositeactionflow.DiagnosticRequiredInputMissing, "caller.yml", "deploy", 0, ".github/actions/deploy", 0, ".github/actions/authenticate", "credential"),
	}
	options := BuildOptions{NestedCompositeActionInputFlows: nestedcompositeactionflow.Result{Diagnostics: diagnostics}}
	first := BuildWithOptions(domain.ParsedRepository{}, options)
	second := BuildWithOptions(domain.ParsedRepository{}, options)
	if len(first.Warnings) != 2 || len(second.Warnings) != 2 {
		t.Fatalf("expected exactly two warnings each run: first=%v second=%v", first.Warnings, second.Warnings)
	}
	for i := range first.Warnings {
		if first.Warnings[i] != second.Warnings[i] {
			t.Fatalf("warnings not deterministic at index %d: %q vs %q", i, first.Warnings[i], second.Warnings[i])
		}
		if !strings.Contains(first.Warnings[i], "COMPOSITE_ACTION_NESTED_INPUT_FLOW") {
			t.Fatalf("expected COMPOSITE_ACTION_NESTED_INPUT_FLOW warning, got %q", first.Warnings[i])
		}
	}
}

// buildNestedForwardingChain constructs actionCount composite actions
// forwarding "token" one level at a time: chain0 (CA2 root-confirmed) ->
// chain1 -> ... -> chain{actionCount-1} (CA3B levels). Returns the built
// graph, the root credential ID, and the deepest usage node's ID.
func buildNestedForwardingChain(actionCount int) (BuildResult, string, string) {
	dir := func(i int) string { return fmt.Sprintf(".github/actions/chain%d", i) }
	root := confirmedFlow("caller.yml", "deploy", 0, "call-step", dir(0), "token", "PROD_TOKEN", usage(0, "step0", 10))

	var nestedFlows []nestedcompositeactionflow.ConfirmedNestedInputFlow
	var callPath []nestedcompositeactionflow.CallPathSegment
	for i := 0; i < actionCount-1; i++ {
		seg := nestedcompositeactionflow.CallPathSegment{ParentCanonicalDirectory: dir(i), ParentActionStepIndex: 0, ChildCanonicalDirectory: dir(i + 1)}
		callPath = append(append([]nestedcompositeactionflow.CallPathSegment(nil), callPath...), seg)
		flow := nestedInputFlow("caller.yml", "deploy", 0, "token", "PROD_TOKEN", callPath,
			dir(i), "token", 0, "step0", dir(i+1), "token", nestedInputUsage(0, "step0", 10))
		nestedFlows = append(nestedFlows, flow)
	}
	built := BuildWithOptions(domain.ParsedRepository{}, BuildOptions{
		CompositeActionInputFlows:       compositeactionflow.Result{Flows: []compositeactionflow.ConfirmedInputFlow{root}},
		NestedCompositeActionInputFlows: nestedcompositeactionflow.Result{Flows: nestedFlows},
	})

	rootCredID := credentialIDByLabel(built, "PROD_TOKEN")
	var deepestID string
	if actionCount <= 1 {
		for _, u := range nodesByType(built.Graph.Nodes, domain.NodeCompositeActionInputUsage) {
			if u.Metadata["canonical_directory"] == dir(0) {
				deepestID = u.ID
			}
		}
	} else {
		last := nestedFlows[len(nestedFlows)-1]
		deepestID = stableID("node:"+string(domain.NodeCompositeActionInputUsage), nestedUsageNodeKey(last, 0))
	}
	return built, rootCredID, deepestID
}

// 55/56/61. a full, CA3A-supported 10-action confirmed nested chain (9
// forwarding transitions) is fully reachable at the real production
// DefaultMaxDepth of 12 — proving the general-depth exemption works without
// DefaultMaxDepth ever being raised — and the winning EvidencePath retains
// every edge of the chain, none silently dropped.
func TestNestedInputFlowFullTenActionChainReachable(t *testing.T) {
	built, rootCredID, deepestID := buildNestedForwardingChain(10)
	paths := Traverse(built.Graph, rootCredID, DefaultMaxDepth)
	if !reachesNode(paths, deepestID) {
		t.Fatal("a full 10-action confirmed nested chain (9 forwarding transitions) must be reachable at DefaultMaxDepth")
	}
	var winning *domain.EvidencePath
	for i := range paths {
		if paths[i].Nodes[len(paths[i].Nodes)-1].ID == deepestID {
			winning = &paths[i]
		}
	}
	if winning == nil {
		t.Fatal("expected a path terminating at the deepest usage node")
	}
	// CA2 (2 edges) + 9 nested levels x 2 edges each = 20 edges.
	if len(winning.Edges) != 20 {
		t.Fatalf("expected the full path to retain all 20 edges (none dropped despite hop exemption), got %d: %#v", len(winning.Edges), winning.Edges)
	}
}

// 57. the 10th forwarding transition (into an 11th action) is rejected,
// while the 9th transition (into the 10th action) remains reachable.
func TestNestedInputFlowTenthTransitionRejected(t *testing.T) {
	built, rootCredID, deepestID := buildNestedForwardingChain(11)
	ninthDir := ".github/actions/chain9"
	var ninthUsageID string
	for _, u := range nodesByType(built.Graph.Nodes, domain.NodeCompositeActionInputUsage) {
		if u.Metadata["child_canonical_directory"] == ninthDir {
			ninthUsageID = u.ID
		}
	}
	if ninthUsageID == "" {
		t.Fatal("could not locate the 9th-transition usage node")
	}
	paths := Traverse(built.Graph, rootCredID, DefaultMaxDepth)
	if !reachesNode(paths, ninthUsageID) {
		t.Fatal("the 9th forwarding transition (into the 10th action) must remain reachable")
	}
	if reachesNode(paths, deepestID) {
		t.Fatal("the 10th forwarding transition (into an 11th action) must not be traversed")
	}
}

// 58/62. ordinary (untagged) ExplicitlyForwardedTo edges are completely
// unaffected by the composite-forwarding exemption: an unrelated chain
// longer than DefaultMaxDepth still truncates at exactly the same point as
// before this change, and no unrelated edge is ever exempted.
func TestNestedInputFlowOrdinaryChainDepthUnaffected(t *testing.T) {
	const length = DefaultMaxDepth + 3 // deliberately more than DefaultMaxDepth
	nodes := []domain.Node{{ID: "n0", Type: domain.NodeCredential}}
	var edges []domain.Edge
	for i := 1; i <= length; i++ {
		id := fmt.Sprintf("n%d", i)
		nodes = append(nodes, domain.Node{ID: id, Type: domain.NodeCredential})
		edges = append(edges, domain.Edge{
			ID: fmt.Sprintf("e%d", i), From: fmt.Sprintf("n%d", i-1), To: id,
			Type: domain.EdgeExplicitlyForwardedTo, EvidenceKind: domain.EvidenceConfirmedDataFlow, Confidence: domain.ConfidenceConfirmed,
			// No composite_action_forwarding_edge/hop metadata: an ordinary edge.
		})
	}
	g := domain.Graph{Nodes: nodes, Edges: edges}
	paths := Traverse(g, "n0", DefaultMaxDepth)
	if reachesNode(paths, fmt.Sprintf("n%d", length)) {
		t.Fatal("an ordinary (untagged) forwarding chain must still be capped by DefaultMaxDepth exactly as before")
	}
	if !reachesNode(paths, fmt.Sprintf("n%d", DefaultMaxDepth)) {
		t.Fatal("an ordinary forwarding chain must still reach exactly up to DefaultMaxDepth, unchanged")
	}
}

// 59/60. reusable-workflow hops and composite-forwarding hops are counted by
// two fully independent counters: a mixed path exhausting both individually
// (9 reusable-workflow hops, then 9 composite-forwarding hops — 18 edges,
// well past the old DefaultMaxDepth of 12) remains fully reachable, and the
// pre-existing reusable-workflow hop semantics are untouched by this test.
func TestNestedInputFlowMixedHopCountersIndependent(t *testing.T) {
	var nodes []domain.Node
	var edges []domain.Edge
	nodes = append(nodes, domain.Node{ID: "n0", Type: domain.NodeCredential})
	for i := 1; i <= 9; i++ {
		id := fmt.Sprintf("r%d", i)
		nodes = append(nodes, domain.Node{ID: id, Type: domain.NodeCredential})
		from := "n0"
		if i > 1 {
			from = fmt.Sprintf("r%d", i-1)
		}
		edges = append(edges, domain.Edge{
			ID: fmt.Sprintf("re%d", i), From: from, To: id,
			Type: domain.EdgeExplicitlyForwardedTo, EvidenceKind: domain.EvidenceConfirmedDataFlow, Confidence: domain.ConfidenceConfirmed,
			Metadata: map[string]string{reusableWorkflowHopMetadataKey: reusableWorkflowHopMetadataValue},
		})
	}
	for i := 1; i <= 9; i++ {
		id := fmt.Sprintf("c%d", i)
		nodes = append(nodes, domain.Node{ID: id, Type: domain.NodeCredential})
		from := "r9"
		if i > 1 {
			from = fmt.Sprintf("c%d", i-1)
		}
		edges = append(edges, domain.Edge{
			ID: fmt.Sprintf("ce%d", i), From: from, To: id,
			Type: domain.EdgeExplicitlyForwardedTo, EvidenceKind: domain.EvidenceConfirmedDataFlow, Confidence: domain.ConfidenceConfirmed,
			Metadata: map[string]string{compositeActionForwardingEdgeMetadataKey: compositeActionForwardingEdgeMetadataValue, compositeActionForwardingHopMetadataKey: compositeActionForwardingHopMetadataValue},
		})
	}
	g := domain.Graph{Nodes: nodes, Edges: edges}
	paths := Traverse(g, "n0", DefaultMaxDepth)
	if !reachesNode(paths, "r9") {
		t.Fatal("9 reusable-workflow hops must remain reachable (unchanged pre-existing semantics)")
	}
	if !reachesNode(paths, "c9") {
		t.Fatal("9 reusable-workflow hops followed by 9 composite-forwarding hops must remain fully reachable: the two counters are independent and neither consumes the other's budget nor the general depth counter")
	}
}
