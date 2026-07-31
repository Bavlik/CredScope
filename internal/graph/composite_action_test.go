package graph

import (
	"encoding/json"
	"testing"

	"github.com/Bavlik/CredScope/internal/domain"
)

func compositeActionStep(uses string) domain.WorkflowStep {
	return domain.WorkflowStep{Action: &domain.ActionReference{Reference: uses, Local: true, Evidence: testEvidence("caller.yml", 3, "uses")}}
}

func compositeJob(id string, steps ...domain.WorkflowStep) domain.WorkflowJob {
	return domain.WorkflowJob{ID: id, Evidence: testEvidence("caller.yml", 2, "jobs."+id), Steps: steps}
}

func compositeWorkflow(file string, jobs ...domain.WorkflowJob) domain.Workflow {
	return domain.Workflow{Name: file, File: file, Evidence: testEvidence(file, 1, "workflow"), Jobs: jobs}
}

func canonicalAction(directory, name string, steps ...domain.ActionStep) domain.ActionMetadata {
	return domain.ActionMetadata{
		Directory: directory,
		File:      directory + "/action.yml",
		Name:      name,
		Runs:      domain.ActionRuns{Using: "composite", Steps: steps},
		Evidence:  testEvidence(directory+"/action.yml", 1, "action"),
	}
}

func resolvedCompositeCall(workflow, jobID string, stepIndex int, directory string) domain.CompositeActionCall {
	return domain.CompositeActionCall{
		CallerWorkflow: workflow, CallerJobID: jobID, CallerStepIndex: stepIndex,
		RawReference: "./" + directory, CanonicalDirectory: directory, MetadataFile: "action.yml",
		Status: domain.CompositeActionResolvedLocalComposite, Evidence: testEvidence("caller.yml", 3, "uses"),
	}
}

func findNodeByType(nodes []domain.Node, kind domain.NodeType) *domain.Node {
	for i := range nodes {
		if nodes[i].Type == kind {
			return &nodes[i]
		}
	}
	return nil
}

// 39/40. resolved composite creates a canonical NodeCompositeAction whose ID
// depends only on canonical directory, not on which metadata filename was
// selected.
func TestBuildResolvedCompositeCreatesCanonicalNodeByDirectoryOnly(t *testing.T) {
	directory := ".github/actions/deploy"
	wfFile := ".github/workflows/caller.yml"
	workflow := compositeWorkflow(wfFile, compositeJob("build", compositeActionStep("./"+directory)))
	parsed := domain.ParsedRepository{Workflows: []domain.Workflow{workflow}}

	first := BuildWithOptions(parsed, BuildOptions{CompositeActions: domain.CompositeActionResolution{
		Actions: []domain.ActionMetadata{canonicalAction(directory, "Deploy")},
		Calls:   []domain.CompositeActionCall{resolvedCompositeCall(wfFile, "build", 0, directory)},
	}})
	canonical := findNodeByType(first.Graph.Nodes, domain.NodeCompositeAction)
	if canonical == nil {
		t.Fatal("NodeCompositeAction not created")
	}
	if canonical.Label != "Deploy" || canonical.Metadata["directory"] != directory {
		t.Fatalf("canonical node = %#v", canonical)
	}

	differentFile := canonicalAction(directory, "Deploy")
	differentFile.File = directory + "/action.yaml"
	second := BuildWithOptions(parsed, BuildOptions{CompositeActions: domain.CompositeActionResolution{
		Actions: []domain.ActionMetadata{differentFile},
		Calls:   []domain.CompositeActionCall{resolvedCompositeCall(wfFile, "build", 0, directory)},
	}})
	canonicalAgain := findNodeByType(second.Graph.Nodes, domain.NodeCompositeAction)
	if canonicalAgain == nil || canonicalAgain.ID != canonical.ID {
		t.Fatalf("canonical node ID must depend only on directory: first=%q second=%#v", canonical.ID, canonicalAgain)
	}
}

// 41/42/43. resolved call preserves the existing NodeExternalAction call
// site and its existing step edge unchanged, and adds a call-site ->
// canonical EdgeRunsAction/EvidenceStructuralCallOnly edge.
func TestBuildResolvedCompositePreservesCallSiteAndAddsStructuralEdge(t *testing.T) {
	directory := ".github/actions/deploy"
	wfFile := ".github/workflows/caller.yml"
	workflow := compositeWorkflow(wfFile, compositeJob("build", compositeActionStep("./"+directory)))
	parsed := domain.ParsedRepository{Workflows: []domain.Workflow{workflow}}
	resolution := domain.CompositeActionResolution{
		Actions: []domain.ActionMetadata{canonicalAction(directory, "Deploy")},
		Calls:   []domain.CompositeActionCall{resolvedCompositeCall(wfFile, "build", 0, directory)},
	}

	withResolution := BuildWithOptions(parsed, BuildOptions{CompositeActions: resolution})
	withoutResolution := Build(parsed)

	callSiteWith := findNodeByType(withResolution.Graph.Nodes, domain.NodeExternalAction)
	callSiteWithout := findNodeByType(withoutResolution.Graph.Nodes, domain.NodeExternalAction)
	if callSiteWith == nil || callSiteWithout == nil || callSiteWith.ID != callSiteWithout.ID {
		t.Fatalf("call-site node ID must be unchanged by composite resolution: with=%#v without=%#v", callSiteWith, callSiteWithout)
	}

	canonical := findNodeByType(withResolution.Graph.Nodes, domain.NodeCompositeAction)
	if canonical == nil {
		t.Fatal("canonical node not found")
	}

	var structural *domain.Edge
	var stepToCallSite *domain.Edge
	for i := range withResolution.Graph.Edges {
		edge := &withResolution.Graph.Edges[i]
		if edge.From == callSiteWith.ID && edge.To == canonical.ID {
			structural = edge
		}
		if edge.To == callSiteWith.ID && edge.Type == domain.EdgeRunsAction {
			stepToCallSite = edge
		}
	}
	if structural == nil {
		t.Fatal("call-site -> canonical structural edge not found")
	}
	if structural.Type != domain.EdgeRunsAction || structural.EvidenceKind != domain.EvidenceStructuralCallOnly {
		t.Fatalf("structural edge = %#v", structural)
	}
	if stepToCallSite == nil || stepToCallSite.EvidenceKind != domain.EvidenceExposureContext {
		t.Fatalf("existing step -> call-site edge must remain EvidenceExposureContext: %#v", stepToCallSite)
	}
}

// 44/45. the structural edge is excluded from traversal, so a credential
// reaching the call site cannot traverse into the canonical action.
func TestTraversalDoesNotWalkCompositeStructuralEdge(t *testing.T) {
	nodes := []domain.Node{
		{ID: "cred", Type: domain.NodeCredential},
		{ID: "step", Type: domain.NodeStep},
		{ID: "callsite", Type: domain.NodeExternalAction},
		{ID: "canonical", Type: domain.NodeCompositeAction},
	}
	edges := []domain.Edge{
		{ID: "cred-step", From: "cred", To: "step", Type: domain.EdgeReferencedByProcess, EvidenceKind: domain.EvidenceConfirmedDataFlow, Confidence: domain.ConfidenceConfirmed},
		{ID: "step-callsite", From: "step", To: "callsite", Type: domain.EdgeRunsAction, EvidenceKind: domain.EvidenceExposureContext, Confidence: domain.ConfidenceConfirmed},
		{ID: "callsite-canonical", From: "callsite", To: "canonical", Type: domain.EdgeRunsAction, EvidenceKind: domain.EvidenceStructuralCallOnly, Confidence: domain.ConfidenceConfirmed},
	}
	paths := Traverse(domain.Graph{Nodes: nodes, Edges: edges}, "cred", 8)
	for _, path := range paths {
		for _, node := range path.Nodes {
			if node.ID == "canonical" {
				t.Fatalf("structural_call_only edge must not be walked: credential must not traverse into canonical composite action: %+v", path)
			}
		}
	}
}

// 46. no credential forwarding edges are added by composite resolution: the
// only edges touching the canonical node are the one structural edge.
func TestBuildResolvedCompositeAddsNoCredentialEdges(t *testing.T) {
	directory := ".github/actions/deploy"
	wfFile := ".github/workflows/caller.yml"
	workflow := compositeWorkflow(wfFile, compositeJob("build", compositeActionStep("./"+directory)))
	parsed := domain.ParsedRepository{Workflows: []domain.Workflow{workflow}}
	resolution := domain.CompositeActionResolution{
		Actions: []domain.ActionMetadata{canonicalAction(directory, "Deploy")},
		Calls:   []domain.CompositeActionCall{resolvedCompositeCall(wfFile, "build", 0, directory)},
	}
	built := BuildWithOptions(parsed, BuildOptions{CompositeActions: resolution})
	canonical := findNodeByType(built.Graph.Nodes, domain.NodeCompositeAction)
	if canonical == nil {
		t.Fatal("canonical node not found")
	}
	for _, edge := range built.Graph.Edges {
		if edge.To == canonical.ID || edge.From == canonical.ID {
			if edge.Type != domain.EdgeRunsAction || edge.EvidenceKind != domain.EvidenceStructuralCallOnly {
				t.Fatalf("unexpected non-structural edge touching canonical node: %#v", edge)
			}
		}
	}
}

// 47. no action-internal step nodes are created, even when the resolved
// action's own metadata declares internal composite steps.
func TestBuildResolvedCompositeCreatesNoInternalStepNodes(t *testing.T) {
	directory := ".github/actions/deploy"
	wfFile := ".github/workflows/caller.yml"
	workflow := compositeWorkflow(wfFile, compositeJob("build", compositeActionStep("./"+directory)))
	parsed := domain.ParsedRepository{Workflows: []domain.Workflow{workflow}}
	action := canonicalAction(directory, "Deploy",
		domain.ActionStep{Run: &domain.ShellCommand{RedactedText: "<redacted>"}, Evidence: testEvidence(directory+"/action.yml", 5, "runs.steps[0]")},
		domain.ActionStep{Run: &domain.ShellCommand{RedactedText: "<redacted>"}, Evidence: testEvidence(directory+"/action.yml", 6, "runs.steps[1]")},
	)
	resolution := domain.CompositeActionResolution{
		Actions: []domain.ActionMetadata{action},
		Calls:   []domain.CompositeActionCall{resolvedCompositeCall(wfFile, "build", 0, directory)},
	}
	built := BuildWithOptions(parsed, BuildOptions{CompositeActions: resolution})
	stepNodeCount := 0
	for _, node := range built.Graph.Nodes {
		if node.Type == domain.NodeStep {
			stepNodeCount++
		}
	}
	if stepNodeCount != 1 {
		t.Fatalf("expected exactly one NodeStep (the caller's own step), got %d", stepNodeCount)
	}
	canonical := findNodeByType(built.Graph.Nodes, domain.NodeCompositeAction)
	if canonical == nil || canonical.Metadata["step_count"] != "2" {
		t.Fatalf("canonical node must record step_count as metadata only, not nodes: %#v", canonical)
	}
}

// 48. same action called twice (two steps in the same workflow) -> one
// canonical node, two call-site nodes.
func TestBuildSameActionCalledTwiceOneCanonicalTwoCallSites(t *testing.T) {
	directory := "tools/action"
	wfFile := ".github/workflows/caller.yml"
	workflow := compositeWorkflow(wfFile,
		compositeJob("first", compositeActionStep("./"+directory)),
		compositeJob("second", compositeActionStep("./"+directory)),
	)
	parsed := domain.ParsedRepository{Workflows: []domain.Workflow{workflow}}
	resolution := domain.CompositeActionResolution{
		Actions: []domain.ActionMetadata{canonicalAction(directory, "Shared")},
		Calls: []domain.CompositeActionCall{
			resolvedCompositeCall(wfFile, "first", 0, directory),
			resolvedCompositeCall(wfFile, "second", 0, directory),
		},
	}
	built := BuildWithOptions(parsed, BuildOptions{CompositeActions: resolution})

	canonicalCount, callSiteCount := 0, 0
	for _, node := range built.Graph.Nodes {
		if node.Type == domain.NodeCompositeAction {
			canonicalCount++
		}
		if node.Type == domain.NodeExternalAction {
			callSiteCount++
		}
	}
	if canonicalCount != 1 {
		t.Fatalf("canonical node count = %d, want 1", canonicalCount)
	}
	if callSiteCount != 2 {
		t.Fatalf("call-site node count = %d, want 2", callSiteCount)
	}
}

// 49. the same action called from two different workflows -> one canonical
// node, two call-site nodes.
func TestBuildTwoWorkflowsCallingSameActionOneCanonicalTwoCallSites(t *testing.T) {
	directory := "tools/action"
	wfA := ".github/workflows/a.yml"
	wfB := ".github/workflows/b.yml"
	parsed := domain.ParsedRepository{Workflows: []domain.Workflow{
		compositeWorkflow(wfA, compositeJob("build", compositeActionStep("./"+directory))),
		compositeWorkflow(wfB, compositeJob("build", compositeActionStep("./"+directory))),
	}}
	resolution := domain.CompositeActionResolution{
		Actions: []domain.ActionMetadata{canonicalAction(directory, "Shared")},
		Calls: []domain.CompositeActionCall{
			resolvedCompositeCall(wfA, "build", 0, directory),
			resolvedCompositeCall(wfB, "build", 0, directory),
		},
	}
	built := BuildWithOptions(parsed, BuildOptions{CompositeActions: resolution})

	canonicalCount, callSiteCount := 0, 0
	for _, node := range built.Graph.Nodes {
		if node.Type == domain.NodeCompositeAction {
			canonicalCount++
		}
		if node.Type == domain.NodeExternalAction {
			callSiteCount++
		}
	}
	if canonicalCount != 1 {
		t.Fatalf("canonical node count = %d, want 1", canonicalCount)
	}
	if callSiteCount != 2 {
		t.Fatalf("call-site node count = %d, want 2", callSiteCount)
	}
}

// 51. the call-site node carries additive, machine-readable resolution
// metadata without overwriting any pre-existing key.
func TestBuildCallSiteHasResolutionStatusMetadata(t *testing.T) {
	directory := ".github/actions/deploy"
	wfFile := ".github/workflows/caller.yml"
	workflow := compositeWorkflow(wfFile, compositeJob("build", compositeActionStep("./"+directory)))
	parsed := domain.ParsedRepository{Workflows: []domain.Workflow{workflow}}
	resolution := domain.CompositeActionResolution{
		Actions: []domain.ActionMetadata{canonicalAction(directory, "Deploy")},
		Calls:   []domain.CompositeActionCall{resolvedCompositeCall(wfFile, "build", 0, directory)},
	}
	built := BuildWithOptions(parsed, BuildOptions{CompositeActions: resolution})
	callSite := findNodeByType(built.Graph.Nodes, domain.NodeExternalAction)
	if callSite == nil {
		t.Fatal("call-site node not found")
	}
	if callSite.Metadata["resolution_status"] != string(domain.CompositeActionResolvedLocalComposite) {
		t.Fatalf("resolution_status = %q", callSite.Metadata["resolution_status"])
	}
	if callSite.Metadata["raw_reference"] != "./"+directory {
		t.Fatalf("raw_reference = %q", callSite.Metadata["raw_reference"])
	}
	if callSite.Metadata["caller_workflow"] != wfFile || callSite.Metadata["caller_job_id"] != "build" || callSite.Metadata["caller_step_index"] != "0" {
		t.Fatalf("caller metadata = %#v", callSite.Metadata)
	}
	if callSite.Metadata["canonical_directory"] != directory || callSite.Metadata["metadata_file"] != "action.yml" {
		t.Fatalf("resolved metadata = %#v", callSite.Metadata)
	}
	// Pre-existing keys must remain exactly as actionMetadata() already set them.
	if callSite.Metadata["local"] != "true" {
		t.Fatalf("existing 'local' metadata must not be overwritten: %#v", callSite.Metadata)
	}
}

// 52/53/54/55. missing, malformed, ambiguous, and rejected-path calls leave
// the existing call-site node visible, create no canonical node, and each
// produces a warning.
func TestBuildUnresolvedLocalStatusesRemainVisibleWithWarning(t *testing.T) {
	directory := ".github/actions/deploy"
	wfFile := ".github/workflows/caller.yml"
	for _, status := range []domain.CompositeActionResolutionStatus{
		domain.CompositeActionMetadataMissing,
		domain.CompositeActionMalformedMetadata,
		domain.CompositeActionMetadataAmbiguous,
		domain.CompositeActionRejectedPath,
	} {
		t.Run(string(status), func(t *testing.T) {
			workflow := compositeWorkflow(wfFile, compositeJob("build", compositeActionStep("./"+directory)))
			parsed := domain.ParsedRepository{Workflows: []domain.Workflow{workflow}}
			call := domain.CompositeActionCall{
				CallerWorkflow: wfFile, CallerJobID: "build", CallerStepIndex: 0,
				RawReference: "./" + directory, Status: status, Evidence: testEvidence(wfFile, 3, "uses"),
			}
			if status != domain.CompositeActionRejectedPath {
				call.CanonicalDirectory = directory
			}
			built := BuildWithOptions(parsed, BuildOptions{CompositeActions: domain.CompositeActionResolution{Calls: []domain.CompositeActionCall{call}}})

			if findNodeByType(built.Graph.Nodes, domain.NodeExternalAction) == nil {
				t.Fatal("call-site node must remain visible")
			}
			if findNodeByType(built.Graph.Nodes, domain.NodeCompositeAction) != nil {
				t.Fatal("no canonical node expected for this status")
			}
			if len(built.Warnings) == 0 {
				t.Fatal("expected a warning for this status")
			}
		})
	}
}

// 56/57/58. external, docker, and target-not-composite call sites are
// completely unchanged from pre-CA1 behavior, and produce no warning.
func TestBuildOpaqueAndTargetNotCompositeStatusesUnchangedNoWarning(t *testing.T) {
	wfFile := ".github/workflows/caller.yml"
	cases := []struct {
		name   string
		status domain.CompositeActionResolutionStatus
		raw    string
	}{
		{"external", domain.CompositeActionOpaqueExternal, "actions/checkout@v4"},
		{"docker", domain.CompositeActionOpaqueDocker, "docker://alpine:3"},
		{"target_not_composite", domain.CompositeActionTargetNotComposite, "./.github/actions/deploy"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			step := domain.WorkflowStep{Action: &domain.ActionReference{Reference: tc.raw, Evidence: testEvidence(wfFile, 3, "uses")}}
			workflow := compositeWorkflow(wfFile, compositeJob("build", step))
			parsed := domain.ParsedRepository{Workflows: []domain.Workflow{workflow}}
			call := domain.CompositeActionCall{
				CallerWorkflow: wfFile, CallerJobID: "build", CallerStepIndex: 0,
				RawReference: tc.raw, Status: tc.status, Evidence: testEvidence(wfFile, 3, "uses"),
			}
			if tc.status == domain.CompositeActionTargetNotComposite {
				call.CanonicalDirectory = ".github/actions/deploy"
				call.MetadataFile = "action.yml"
			}
			withResolution := BuildWithOptions(parsed, BuildOptions{CompositeActions: domain.CompositeActionResolution{Calls: []domain.CompositeActionCall{call}}})
			withoutResolution := Build(parsed)

			withNode := findNodeByType(withResolution.Graph.Nodes, domain.NodeExternalAction)
			withoutNode := findNodeByType(withoutResolution.Graph.Nodes, domain.NodeExternalAction)
			if withNode == nil || withoutNode == nil || withNode.ID != withoutNode.ID {
				t.Fatalf("call-site node ID changed: with=%#v without=%#v", withNode, withoutNode)
			}
			for _, key := range []string{"local", "third_party", "mutable", "owner", "repository", "revision", "pinned_sha", "artifact_kind", "docker"} {
				if withNode.Metadata[key] != withoutNode.Metadata[key] {
					t.Fatalf("existing metadata key %q changed: with=%q without=%q", key, withNode.Metadata[key], withoutNode.Metadata[key])
				}
			}
			if findNodeByType(withResolution.Graph.Nodes, domain.NodeCompositeAction) != nil {
				t.Fatal("no canonical node expected for this status")
			}
			if len(withResolution.Warnings) != 0 {
				t.Fatalf("no warning expected for status %s, got %v", tc.status, withResolution.Warnings)
			}
		})
	}
}

// 59. graph output is byte-identical across repeated builds from the same input.
func TestBuildCompositeActionGraphByteIdenticalAcrossRuns(t *testing.T) {
	directory := ".github/actions/deploy"
	wfFile := ".github/workflows/caller.yml"
	workflow := compositeWorkflow(wfFile, compositeJob("build", compositeActionStep("./"+directory)))
	parsed := domain.ParsedRepository{Workflows: []domain.Workflow{workflow}}
	resolution := domain.CompositeActionResolution{
		Actions: []domain.ActionMetadata{canonicalAction(directory, "Deploy")},
		Calls:   []domain.CompositeActionCall{resolvedCompositeCall(wfFile, "build", 0, directory)},
	}
	first := BuildWithOptions(parsed, BuildOptions{CompositeActions: resolution})
	second := BuildWithOptions(parsed, BuildOptions{CompositeActions: resolution})
	firstJSON, err := json.Marshal(first.Graph)
	if err != nil {
		t.Fatal(err)
	}
	secondJSON, err := json.Marshal(second.Graph)
	if err != nil {
		t.Fatal(err)
	}
	if string(firstJSON) != string(secondJSON) {
		t.Fatal("graph not byte-identical across runs")
	}
}

// BuildWithOptions must not mutate its CompositeActions input.
func TestBuildDoesNotMutateCompositeActionsInput(t *testing.T) {
	directory := ".github/actions/deploy"
	wfFile := ".github/workflows/caller.yml"
	workflow := compositeWorkflow(wfFile, compositeJob("build", compositeActionStep("./"+directory)))
	parsed := domain.ParsedRepository{Workflows: []domain.Workflow{workflow}}
	resolution := domain.CompositeActionResolution{
		Actions: []domain.ActionMetadata{canonicalAction(directory, "Deploy")},
		Calls:   []domain.CompositeActionCall{resolvedCompositeCall(wfFile, "build", 0, directory)},
	}
	before, err := json.Marshal(resolution)
	if err != nil {
		t.Fatal(err)
	}
	_ = BuildWithOptions(parsed, BuildOptions{CompositeActions: resolution})
	after, err := json.Marshal(resolution)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("BuildWithOptions mutated its CompositeActions input")
	}
}
