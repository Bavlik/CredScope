package graph

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Bavlik/CredScope/internal/compositeactionflow"
	"github.com/Bavlik/CredScope/internal/domain"
)

func flowActionMetadata(directory, name string, inputs []domain.ActionInputDefinition, steps ...domain.ActionStep) domain.ActionMetadata {
	return domain.ActionMetadata{
		Directory: directory, File: directory + "/action.yml", Name: name,
		Inputs: inputs, Runs: domain.ActionRuns{Using: "composite", Steps: steps},
		Evidence: testEvidence(directory+"/action.yml", 1, "action"),
	}
}

func confirmedFlow(callerWorkflow, callerJobID string, callerStepIndex int, callerStepID, directory, inputName, sourceSecret string, usages ...compositeactionflow.InputUsage) compositeactionflow.ConfirmedInputFlow {
	return compositeactionflow.ConfirmedInputFlow{
		CallerWorkflow: callerWorkflow, CallerJobID: callerJobID, CallerStepIndex: callerStepIndex, CallerStepID: callerStepID,
		CanonicalDirectory: directory, InputName: inputName, SourceSecret: sourceSecret,
		BindingEvidence: testEvidence("caller.yml", 3, "with."+inputName),
		Usages:          usages,
	}
}

func usage(stepIndex int, stepID string, line int) compositeactionflow.InputUsage {
	return compositeactionflow.InputUsage{ActionStepIndex: stepIndex, ActionStepID: stepID, Evidence: testEvidence(".github/actions/deploy/action.yml", line, "runs.steps")}
}

func nodesByType(nodes []domain.Node, kind domain.NodeType) []domain.Node {
	var result []domain.Node
	for _, node := range nodes {
		if node.Type == kind {
			result = append(result, node)
		}
	}
	return result
}

// 54/55/56/57/58. a confirmed flow creates one call-specific binding node and
// one call-specific usage node, connected by confirmed, traversable edges,
// preserving the caller's exact input-name alias in both node label and
// metadata.
func TestCompositeActionInputFlowCreatesBindingAndUsageNodes(t *testing.T) {
	flow := confirmedFlow("caller.yml", "deploy", 0, "call-step", ".github/actions/deploy", "token", "PROD_TOKEN", usage(0, "deploy-step", 10))
	built := BuildWithOptions(domain.ParsedRepository{}, BuildOptions{CompositeActionInputFlows: compositeactionflow.Result{Flows: []compositeactionflow.ConfirmedInputFlow{flow}}})

	credentialID := credentialIDByLabel(built, "PROD_TOKEN")
	if credentialID == "" {
		t.Fatal("expected a NodeCredential for PROD_TOKEN")
	}
	bindings := nodesByType(built.Graph.Nodes, domain.NodeCompositeActionInputBinding)
	if len(bindings) != 1 {
		t.Fatalf("expected exactly one binding node, got %#v", bindings)
	}
	binding := bindings[0]
	if binding.Label != "token" {
		t.Fatalf("binding label must be the input name alias, got %q", binding.Label)
	}
	if binding.Metadata["input_name"] != "token" || binding.Metadata["source_secret"] != "PROD_TOKEN" || binding.Metadata["flow_status"] != "confirmed_secret_flow" {
		t.Fatalf("binding metadata = %#v", binding.Metadata)
	}

	usages := nodesByType(built.Graph.Nodes, domain.NodeCompositeActionInputUsage)
	if len(usages) != 1 {
		t.Fatalf("expected exactly one usage node, got %#v", usages)
	}
	usageNode := usages[0]
	if usageNode.Label != "deploy-step" {
		t.Fatalf("usage label = %q", usageNode.Label)
	}

	credentialToBinding := forwardingEdge(built, credentialID, binding.ID)
	if credentialToBinding == nil {
		t.Fatal("expected credential -> binding EdgeExplicitlyForwardedTo edge")
	}
	if credentialToBinding.EvidenceKind != domain.EvidenceConfirmedDataFlow || credentialToBinding.Confidence != domain.ConfidenceConfirmed {
		t.Fatalf("credential -> binding edge = %#v", credentialToBinding)
	}
	bindingToUsage := forwardingEdge(built, binding.ID, usageNode.ID)
	if bindingToUsage == nil {
		t.Fatal("expected binding -> usage EdgeExplicitlyForwardedTo edge")
	}
	if bindingToUsage.EvidenceKind != domain.EvidenceConfirmedDataFlow || bindingToUsage.Confidence != domain.ConfidenceConfirmed {
		t.Fatalf("binding -> usage edge = %#v", bindingToUsage)
	}
}

// 59/60/61/62/63/64. no shared node ever lets one call's credential reach
// another call's binding or usage — even for the same canonical action and
// input name, even for the same secret forwarded to two aliases, even for a
// same-named source secret and input.
func TestCompositeActionInputFlowIsolatesDistinctCalls(t *testing.T) {
	prodFlow := confirmedFlow("caller.yml", "deploy", 0, "prod-step", ".github/actions/deploy", "token", "PROD_TOKEN", usage(0, "deploy-step", 10))
	stagingFlow := confirmedFlow("caller.yml", "deploy", 1, "staging-step", ".github/actions/deploy", "token", "STAGING_TOKEN", usage(0, "deploy-step", 10))
	// Same secret forwarded into two different aliases on a third call.
	tokenAliasFlow := confirmedFlow("caller.yml", "deploy", 2, "alias-step", ".github/actions/deploy", "token", "SHARED_TOKEN", usage(0, "deploy-step", 10))
	passwordAliasFlow := confirmedFlow("caller.yml", "deploy", 2, "alias-step", ".github/actions/deploy", "password", "SHARED_TOKEN", usage(1, "auth-step", 20))
	// Same alias name "token" used against a different canonical action from
	// a fourth, distinct call site (different step index).
	otherActionFlow := confirmedFlow("caller.yml", "deploy", 3, "other-step", ".github/actions/other", "token", "PROD_TOKEN", usage(0, "other-deploy-step", 10))
	// Same-named source secret and input name.
	sameNameFlow := confirmedFlow("caller.yml", "deploy", 4, "same-name-step", ".github/actions/deploy", "TOKEN", "TOKEN", usage(0, "deploy-step", 10))

	built := BuildWithOptions(domain.ParsedRepository{}, BuildOptions{CompositeActionInputFlows: compositeactionflow.Result{Flows: []compositeactionflow.ConfirmedInputFlow{
		prodFlow, stagingFlow, tokenAliasFlow, passwordAliasFlow, otherActionFlow, sameNameFlow,
	}}})

	bindings := nodesByType(built.Graph.Nodes, domain.NodeCompositeActionInputBinding)
	usages := nodesByType(built.Graph.Nodes, domain.NodeCompositeActionInputUsage)
	if len(bindings) != 6 {
		t.Fatalf("expected 6 distinct binding nodes (one per call), got %d: %#v", len(bindings), bindings)
	}
	if len(usages) != 6 {
		t.Fatalf("expected 6 distinct usage nodes (one per call), got %d: %#v", len(usages), usages)
	}
	seenBindingIDs := map[string]bool{}
	for _, b := range bindings {
		if seenBindingIDs[b.ID] {
			t.Fatalf("duplicate binding node ID: %s", b.ID)
		}
		seenBindingIDs[b.ID] = true
	}
	seenUsageIDs := map[string]bool{}
	for _, u := range usages {
		if seenUsageIDs[u.ID] {
			t.Fatalf("duplicate usage node ID: %s", u.ID)
		}
		seenUsageIDs[u.ID] = true
	}

	prodCredID := credentialIDByLabel(built, "PROD_TOKEN")
	stagingCredID := credentialIDByLabel(built, "STAGING_TOKEN")
	prodBindingID := forwardingEdgesFrom(built, prodCredID)
	if len(prodBindingID) == 0 {
		t.Fatal("expected PROD_TOKEN to forward to a binding")
	}
	stagingBindingID := forwardingEdgesFrom(built, stagingCredID)
	if len(stagingBindingID) == 0 {
		t.Fatal("expected STAGING_TOKEN to forward to a binding")
	}
	if prodBindingID[0].To == stagingBindingID[0].To {
		t.Fatal("PROD_TOKEN and STAGING_TOKEN must forward to distinct binding nodes despite sharing the same canonical action and input name")
	}

	// Traversal isolation proof: PROD's traversal must never reach
	// STAGING's binding/usage nodes, and vice versa.
	prodPaths := Traverse(built.Graph, prodCredID, 10)
	if reachesNode(prodPaths, stagingBindingID[0].To) {
		t.Fatal("PROD_TOKEN traversal reached STAGING's binding node")
	}
	stagingPaths := Traverse(built.Graph, stagingCredID, 10)
	if reachesNode(stagingPaths, prodBindingID[0].To) {
		t.Fatal("STAGING_TOKEN traversal reached PROD's binding node")
	}

	// Same secret, two aliases: distinct binding nodes, both reachable from
	// the one shared credential, but never collapsed into one node.
	sharedCredID := credentialIDByLabel(built, "SHARED_TOKEN")
	sharedBindingEdges := forwardingEdgesFrom(built, sharedCredID)
	if len(sharedBindingEdges) != 2 {
		t.Fatalf("expected SHARED_TOKEN to forward to two distinct alias binding nodes, got %d", len(sharedBindingEdges))
	}
	if sharedBindingEdges[0].To == sharedBindingEdges[1].To {
		t.Fatal("two aliases sharing one secret must not collapse into one binding node")
	}

	// Same-named source secret and input: credential, binding, and usage
	// nodes must all have distinct IDs and distinct NodeTypes.
	sameNameCredID := credentialIDByLabel(built, "TOKEN")
	if sameNameCredID == "" {
		t.Fatal("expected a NodeCredential for the same-named TOKEN secret")
	}
	var sameNameBindingID, sameNameUsageID string
	for _, b := range bindings {
		if b.Metadata["source_secret"] == "TOKEN" && b.Metadata["input_name"] == "TOKEN" {
			sameNameBindingID = b.ID
		}
	}
	for _, u := range usages {
		if u.Metadata["input_name"] == "TOKEN" && u.Metadata["action_step_id"] == "deploy-step" && u.Metadata["caller_step_index"] == "4" {
			sameNameUsageID = u.ID
		}
	}
	if sameNameBindingID == "" || sameNameUsageID == "" {
		t.Fatalf("could not locate same-name binding/usage nodes: bindings=%#v usages=%#v", bindings, usages)
	}
	ids := map[string]bool{sameNameCredID: true, sameNameBindingID: true, sameNameUsageID: true}
	if len(ids) != 3 {
		t.Fatalf("same-named source secret and input must still produce three distinct node IDs, got %#v", ids)
	}
}

// 65/66. usage node count exactly mirrors the number of usages the linker
// supplied — one input used by two internal steps produces two usage nodes;
// a single, already-collapsed usage entry produces exactly one.
func TestCompositeActionInputFlowUsageNodeCountMatchesUsages(t *testing.T) {
	twoUsageFlow := confirmedFlow("caller.yml", "deploy", 0, "s", ".github/actions/deploy", "token", "PROD_TOKEN", usage(0, "first", 10), usage(1, "second", 20))
	built := BuildWithOptions(domain.ParsedRepository{}, BuildOptions{CompositeActionInputFlows: compositeactionflow.Result{Flows: []compositeactionflow.ConfirmedInputFlow{twoUsageFlow}}})
	if usages := nodesByType(built.Graph.Nodes, domain.NodeCompositeActionInputUsage); len(usages) != 2 {
		t.Fatalf("expected two usage nodes, got %#v", usages)
	}

	oneUsageFlow := confirmedFlow("caller.yml", "deploy", 0, "s", ".github/actions/deploy", "token", "PROD_TOKEN", usage(0, "first", 10))
	builtOne := BuildWithOptions(domain.ParsedRepository{}, BuildOptions{CompositeActionInputFlows: compositeactionflow.Result{Flows: []compositeactionflow.ConfirmedInputFlow{oneUsageFlow}}})
	if usages := nodesByType(builtOne.Graph.Nodes, domain.NodeCompositeActionInputUsage); len(usages) != 1 {
		t.Fatalf("expected one usage node, got %#v", usages)
	}
}

// 67/68. CA1's structural NodeExternalAction -> NodeCompositeAction edge
// remains excluded from traversal, and no CA2 edge ever points at the
// canonical NodeCompositeAction node at all.
func TestCompositeActionInputFlowNoTraversableEdgeToCanonicalAction(t *testing.T) {
	directory := ".github/actions/deploy"
	wfFile := ".github/workflows/caller.yml"
	workflow := compositeWorkflow(wfFile, compositeJob("build", compositeActionStep("./"+directory)))
	parsed := domain.ParsedRepository{Workflows: []domain.Workflow{workflow}}
	resolution := domain.CompositeActionResolution{
		Actions: []domain.ActionMetadata{canonicalAction(directory, "Deploy")},
		Calls:   []domain.CompositeActionCall{resolvedCompositeCall(wfFile, "build", 0, directory)},
	}
	flow := confirmedFlow(wfFile, "build", 0, "", directory, "token", "PROD_TOKEN", usage(0, "deploy-step", 10))
	built := BuildWithOptions(parsed, BuildOptions{CompositeActions: resolution, CompositeActionInputFlows: compositeactionflow.Result{Flows: []compositeactionflow.ConfirmedInputFlow{flow}}})

	canonical := findNodeByType(built.Graph.Nodes, domain.NodeCompositeAction)
	if canonical == nil {
		t.Fatal("expected canonical NodeCompositeAction from CA1 resolution")
	}
	for _, edge := range built.Graph.Edges {
		if edge.To == canonical.ID {
			if edge.Type != domain.EdgeRunsAction || edge.EvidenceKind != domain.EvidenceStructuralCallOnly {
				t.Fatalf("no non-CA1 edge should point at the canonical action node; found %#v", edge)
			}
		}
		if edge.From == canonical.ID {
			t.Fatalf("canonical action node must never have an outgoing edge; found %#v", edge)
		}
	}

	credentialID := credentialIDByLabel(built, "PROD_TOKEN")
	paths := Traverse(built.Graph, credentialID, 10)
	if reachesNode(paths, canonical.ID) {
		t.Fatal("confirmed secret flow traversal must never reach the canonical composite action node")
	}
}

// 69/70/71/72/73/74/75. every case where the linker itself produces no
// ConfirmedInputFlow (transformed/ambiguous/dynamic secret expressions,
// undeclared input, missing required input, a plain literal binding, or
// github.token) must fabricate no binding/usage node and no NodeCredential:
// the builder only ever sees "zero flows" for any of these reasons, so one
// architectural test proves all of them at the builder layer.
func TestCompositeActionInputFlowEmptyResultCreatesNoNodes(t *testing.T) {
	built := BuildWithOptions(domain.ParsedRepository{}, BuildOptions{CompositeActionInputFlows: compositeactionflow.Result{}})
	if bindings := nodesByType(built.Graph.Nodes, domain.NodeCompositeActionInputBinding); len(bindings) != 0 {
		t.Fatalf("expected no binding nodes, got %#v", bindings)
	}
	if usages := nodesByType(built.Graph.Nodes, domain.NodeCompositeActionInputUsage); len(usages) != 0 {
		t.Fatalf("expected no usage nodes, got %#v", usages)
	}
	if credentials := nodesByType(built.Graph.Nodes, domain.NodeCredential); len(credentials) != 0 {
		t.Fatalf("expected no NodeCredential nodes at all, got %#v", credentials)
	}
}

// 76/77/78. an external action, a docker action, and a target_not_composite
// local action are byte-identical whether or not CA2's zero-value
// CompositeActionInputFlows option is explicitly supplied.
func TestCompositeActionInputFlowExternalDockerTargetNotCompositeUnchanged(t *testing.T) {
	scenarios := map[string]domain.WorkflowStep{
		"external": {Action: &domain.ActionReference{Reference: "actions/checkout@v4", Evidence: testEvidence("caller.yml", 3, "uses")}},
		"docker":   {Action: &domain.ActionReference{Reference: "docker://alpine:3.19", Docker: true, Evidence: testEvidence("caller.yml", 3, "uses")}},
	}
	for name, step := range scenarios {
		t.Run(name, func(t *testing.T) {
			workflow := compositeWorkflow(".github/workflows/caller.yml", compositeJob("build", step))
			parsed := domain.ParsedRepository{Workflows: []domain.Workflow{workflow}}
			withOptions := BuildWithOptions(parsed, BuildOptions{CompositeActionInputFlows: compositeactionflow.Result{}})
			without := Build(parsed)
			withJSON, _ := json.Marshal(withOptions.Graph)
			withoutJSON, _ := json.Marshal(without.Graph)
			if string(withJSON) != string(withoutJSON) {
				t.Fatalf("%s scenario changed by CA2 wiring:\nwith=%s\nwithout=%s", name, withJSON, withoutJSON)
			}
		})
	}

	// target_not_composite: a resolved local reference whose target is not a
	// composite action. No ActionMetadata exists for it in Actions, and its
	// status gates the linker's own matching (proven in the linker's own
	// test suite) — here we only prove the builder's graph is unaffected by
	// the option being present.
	directory := ".github/actions/notcomposite"
	wfFile := ".github/workflows/caller.yml"
	workflow := compositeWorkflow(wfFile, compositeJob("build", compositeActionStep("./"+directory)))
	parsed := domain.ParsedRepository{Workflows: []domain.Workflow{workflow}}
	resolution := domain.CompositeActionResolution{Calls: []domain.CompositeActionCall{{
		CallerWorkflow: wfFile, CallerJobID: "build", CallerStepIndex: 0, CanonicalDirectory: directory,
		Status: domain.CompositeActionTargetNotComposite, Evidence: testEvidence("caller.yml", 3, "uses"),
	}}}
	withOptions := BuildWithOptions(parsed, BuildOptions{CompositeActions: resolution, CompositeActionInputFlows: compositeactionflow.Result{}})
	without := BuildWithOptions(parsed, BuildOptions{CompositeActions: resolution})
	withJSON, _ := json.Marshal(withOptions.Graph)
	withoutJSON, _ := json.Marshal(without.Graph)
	if string(withJSON) != string(withoutJSON) {
		t.Fatalf("target_not_composite scenario changed by CA2 wiring:\nwith=%s\nwithout=%s", withJSON, withoutJSON)
	}
}

// 79. the pre-existing generic workflow-step reference edge (produced by the
// unrelated, unchanged step.References sweep) continues to exist unmodified
// alongside CA2's new alias-aware confirmed binding/usage chain — CA2 adds a
// parallel, more precise path; it never replaces or overwrites the old one.
func TestCompositeActionInputFlowCoexistsWithGenericStepReferenceEdge(t *testing.T) {
	directory := ".github/actions/deploy"
	wfFile := ".github/workflows/caller.yml"
	step := compositeActionStep("./" + directory)
	step.References = []domain.Reference{testReference("PROD_TOKEN", "caller.yml", 4)}
	workflow := compositeWorkflow(wfFile, compositeJob("build", step))
	parsed := domain.ParsedRepository{Workflows: []domain.Workflow{workflow}}
	resolution := domain.CompositeActionResolution{
		Actions: []domain.ActionMetadata{canonicalAction(directory, "Deploy")},
		Calls:   []domain.CompositeActionCall{resolvedCompositeCall(wfFile, "build", 0, directory)},
	}
	flow := confirmedFlow(wfFile, "build", 0, "", directory, "token", "PROD_TOKEN", usage(0, "deploy-step", 10))
	built := BuildWithOptions(parsed, BuildOptions{CompositeActions: resolution, CompositeActionInputFlows: compositeactionflow.Result{Flows: []compositeactionflow.ConfirmedInputFlow{flow}}})

	credentialID := credentialIDByLabel(built, "PROD_TOKEN")
	stepNode := findNodeByType(built.Graph.Nodes, domain.NodeStep)
	if stepNode == nil {
		t.Fatal("expected a NodeStep from ordinary workflow processing")
	}
	oldEdge := forwardingEdge(built, credentialID, stepNode.ID)
	if oldEdge == nil {
		t.Fatal("expected the pre-existing generic step-level credential edge to still exist")
	}

	bindings := nodesByType(built.Graph.Nodes, domain.NodeCompositeActionInputBinding)
	if len(bindings) != 1 {
		t.Fatalf("expected exactly one new binding node, got %#v", bindings)
	}
	newEdge := forwardingEdge(built, credentialID, bindings[0].ID)
	if newEdge == nil {
		t.Fatal("expected the new confirmed credential -> binding edge to also exist")
	}
	if newEdge.ID == oldEdge.ID {
		t.Fatal("the new binding edge must not overwrite or collapse into the old generic step edge")
	}
}

// 84. graph construction is deterministic given identical input.
func TestCompositeActionInputFlowGraphDeterministic(t *testing.T) {
	flow := confirmedFlow("caller.yml", "deploy", 0, "s", ".github/actions/deploy", "token", "PROD_TOKEN", usage(0, "deploy-step", 10))
	first := BuildWithOptions(domain.ParsedRepository{}, BuildOptions{CompositeActionInputFlows: compositeactionflow.Result{Flows: []compositeactionflow.ConfirmedInputFlow{flow}}})
	second := BuildWithOptions(domain.ParsedRepository{}, BuildOptions{CompositeActionInputFlows: compositeactionflow.Result{Flows: []compositeactionflow.ConfirmedInputFlow{flow}}})
	firstJSON, _ := json.Marshal(first.Graph)
	secondJSON, _ := json.Marshal(second.Graph)
	if string(firstJSON) != string(secondJSON) {
		t.Fatal("graph construction is not deterministic")
	}
}

// 85/86/87. no raw binding value, no secret value, no input default, and no
// command body ever reaches node metadata or evidence — only an allowlisted
// set of safe, non-secret metadata keys is ever present on either new node
// type.
func TestCompositeActionInputFlowMetadataNeverLeaksSensitiveContent(t *testing.T) {
	flow := confirmedFlow("caller.yml", "deploy", 0, "s", ".github/actions/deploy", "token", "PROD_TOKEN", usage(0, "deploy-step", 10))
	built := BuildWithOptions(domain.ParsedRepository{}, BuildOptions{CompositeActionInputFlows: compositeactionflow.Result{Flows: []compositeactionflow.ConfirmedInputFlow{flow}}})

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
		"caller_workflow": true, "caller_job_id": true, "caller_step_index": true, "caller_step_id": true,
		"input_name": true, "canonical_directory": true, "source_secret": true, "flow_status": true,
	}
	for _, binding := range nodesByType(built.Graph.Nodes, domain.NodeCompositeActionInputBinding) {
		for key := range binding.Metadata {
			if !bindingAllowed[key] {
				t.Fatalf("unexpected binding metadata key %q: %#v", key, binding.Metadata)
			}
		}
	}
	usageAllowed := map[string]bool{
		"caller_workflow": true, "caller_job_id": true, "caller_step_index": true, "input_name": true,
		"canonical_directory": true, "action_step_index": true, "action_step_id": true, "evidence_field": true,
		"flow_status": true,
	}
	for _, usageNode := range nodesByType(built.Graph.Nodes, domain.NodeCompositeActionInputUsage) {
		for key := range usageNode.Metadata {
			if !usageAllowed[key] {
				t.Fatalf("unexpected usage metadata key %q: %#v", key, usageNode.Metadata)
			}
		}
	}
}
