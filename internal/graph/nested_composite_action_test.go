package graph

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Bavlik/CredScope/internal/domain"
)

func nestedCall(parentDirectory string, parentStepIndex int, status domain.CompositeActionResolutionStatus, childDirectory string) domain.NestedCompositeActionCall {
	return domain.NestedCompositeActionCall{
		ParentCanonicalDirectory: parentDirectory, ParentMetadataFile: "action.yml", ParentActionStepIndex: parentStepIndex,
		RawReference: "./" + childDirectory, CanonicalDirectory: childDirectory, MetadataFile: "action.yml",
		Status: status, Evidence: testEvidence(parentDirectory+"/action.yml", 3+parentStepIndex, "runs.steps"),
	}
}

func resolvedNestedCall(parentDirectory string, parentStepIndex int, childDirectory string) domain.NestedCompositeActionCall {
	return nestedCall(parentDirectory, parentStepIndex, domain.CompositeActionResolvedLocalComposite, childDirectory)
}

// 43/44/45. resolved parent structurally links to resolved child using
// EdgeRunsAction + EvidenceStructuralCallOnly.
func TestNestedCompositeActionStructuralEdge(t *testing.T) {
	resolution := domain.CompositeActionResolution{
		Actions:     []domain.ActionMetadata{canonicalAction("a", "A"), canonicalAction("b", "B")},
		NestedCalls: []domain.NestedCompositeActionCall{resolvedNestedCall("a", 0, "b")},
	}
	built := BuildWithOptions(domain.ParsedRepository{}, BuildOptions{CompositeActions: resolution})

	parent := findNodeByType(built.Graph.Nodes, domain.NodeCompositeAction)
	if parent == nil {
		t.Fatal("expected at least one NodeCompositeAction")
	}
	nodes := nodesByType(built.Graph.Nodes, domain.NodeCompositeAction)
	if len(nodes) != 2 {
		t.Fatalf("expected exactly two canonical action nodes (A and B), got %#v", nodes)
	}
	var aID, bID string
	for _, n := range nodes {
		if n.Label == "A" {
			aID = n.ID
		}
		if n.Label == "B" {
			bID = n.ID
		}
	}
	if aID == "" || bID == "" {
		t.Fatalf("expected both A and B nodes present: %#v", nodes)
	}
	var structural *domain.Edge
	for i := range built.Graph.Edges {
		e := &built.Graph.Edges[i]
		if e.From == aID && e.To == bID {
			structural = e
		}
	}
	if structural == nil {
		t.Fatal("expected structural A -> B edge")
	}
	if structural.Type != domain.EdgeRunsAction {
		t.Fatalf("expected EdgeRunsAction, got %s", structural.Type)
	}
	if structural.EvidenceKind != domain.EvidenceStructuralCallOnly {
		t.Fatalf("expected EvidenceStructuralCallOnly, got %s", structural.EvidenceKind)
	}
}

// 46. structural nested edge is excluded from traversal.
func TestNestedCompositeActionStructuralEdgeExcludedFromTraversal(t *testing.T) {
	resolution := domain.CompositeActionResolution{
		Actions:     []domain.ActionMetadata{canonicalAction("a", "A"), canonicalAction("b", "B")},
		NestedCalls: []domain.NestedCompositeActionCall{resolvedNestedCall("a", 0, "b")},
	}
	built := BuildWithOptions(domain.ParsedRepository{}, BuildOptions{CompositeActions: resolution})
	nodes := nodesByType(built.Graph.Nodes, domain.NodeCompositeAction)
	var aID string
	for _, n := range nodes {
		if n.Label == "A" {
			aID = n.ID
		}
	}
	paths := Traverse(built.Graph, aID, 8)
	if len(paths) != 0 {
		t.Fatalf("structural nested edge must not be traversable, got paths: %#v", paths)
	}
}

// 47. two parent steps calling the same child preserve distinct edges/evidence.
func TestNestedCompositeActionTwoParentStepsDistinctEdges(t *testing.T) {
	resolution := domain.CompositeActionResolution{
		Actions: []domain.ActionMetadata{canonicalAction("a", "A"), canonicalAction("b", "B")},
		NestedCalls: []domain.NestedCompositeActionCall{
			resolvedNestedCall("a", 0, "b"),
			resolvedNestedCall("a", 1, "b"),
		},
	}
	built := BuildWithOptions(domain.ParsedRepository{}, BuildOptions{CompositeActions: resolution})
	nodes := nodesByType(built.Graph.Nodes, domain.NodeCompositeAction)
	var aID, bID string
	for _, n := range nodes {
		if n.Label == "A" {
			aID = n.ID
		}
		if n.Label == "B" {
			bID = n.ID
		}
	}
	var edges []domain.Edge
	for _, e := range built.Graph.Edges {
		if e.From == aID && e.To == bID {
			edges = append(edges, e)
		}
	}
	if len(edges) != 2 {
		t.Fatalf("expected two distinct edges for two parent steps calling the same child, got %d: %#v", len(edges), edges)
	}
	if edges[0].ID == edges[1].ID {
		t.Fatal("edges must have distinct IDs")
	}
}

// 48. diamond graph remains finite.
func TestNestedCompositeActionDiamondFinite(t *testing.T) {
	resolution := domain.CompositeActionResolution{
		Actions: []domain.ActionMetadata{canonicalAction("a", "A"), canonicalAction("b", "B"), canonicalAction("c", "C"), canonicalAction("d", "D")},
		NestedCalls: []domain.NestedCompositeActionCall{
			resolvedNestedCall("a", 0, "b"),
			resolvedNestedCall("a", 1, "c"),
			resolvedNestedCall("b", 0, "d"),
			resolvedNestedCall("c", 0, "d"),
		},
	}
	built := BuildWithOptions(domain.ParsedRepository{}, BuildOptions{CompositeActions: resolution})
	nodes := nodesByType(built.Graph.Nodes, domain.NodeCompositeAction)
	if len(nodes) != 4 {
		t.Fatalf("expected exactly 4 canonical nodes (A,B,C,D), got %d: %#v", len(nodes), nodes)
	}
	if len(built.Graph.Edges) != 4 {
		t.Fatalf("expected exactly 4 structural edges, got %d: %#v", len(built.Graph.Edges), built.Graph.Edges)
	}
}

// 49. cycle graph remains finite.
func TestNestedCompositeActionCycleFinite(t *testing.T) {
	resolution := domain.CompositeActionResolution{
		Actions: []domain.ActionMetadata{canonicalAction("a", "A"), canonicalAction("b", "B")},
		NestedCalls: []domain.NestedCompositeActionCall{
			resolvedNestedCall("a", 0, "b"),
			resolvedNestedCall("b", 0, "a"),
		},
	}
	built := BuildWithOptions(domain.ParsedRepository{}, BuildOptions{CompositeActions: resolution})
	nodes := nodesByType(built.Graph.Nodes, domain.NodeCompositeAction)
	if len(nodes) != 2 {
		t.Fatalf("expected exactly 2 canonical nodes despite the cycle, got %d: %#v", len(nodes), nodes)
	}
	if len(built.Graph.Edges) != 2 {
		t.Fatalf("expected exactly 2 structural edges (A->B, B->A), got %d: %#v", len(built.Graph.Edges), built.Graph.Edges)
	}
}

// 50/51/52/53. unresolved/external/Docker/target_not_composite child creates
// no structural child edge, and no fabricated child node (54).
func TestNestedCompositeActionNonResolvedStatusesCreateNoChildEdgeOrNode(t *testing.T) {
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
			resolution := domain.CompositeActionResolution{
				Actions:     []domain.ActionMetadata{canonicalAction("a", "A")}, // only the parent resolves
				NestedCalls: []domain.NestedCompositeActionCall{nestedCall("a", 0, status, "b")},
			}
			built := BuildWithOptions(domain.ParsedRepository{}, BuildOptions{CompositeActions: resolution})
			nodes := nodesByType(built.Graph.Nodes, domain.NodeCompositeAction)
			if len(nodes) != 1 {
				t.Fatalf("status %s: expected only the parent's NodeCompositeAction (no fabricated child), got %#v", status, nodes)
			}
			if len(built.Graph.Edges) != 0 {
				t.Fatalf("status %s: expected no structural child edge, got %#v", status, built.Graph.Edges)
			}
		})
	}
}

// 55. nested resolution warning is deterministic.
func TestNestedCompositeActionResolutionWarningDeterministic(t *testing.T) {
	resolution := domain.CompositeActionResolution{
		Actions:     []domain.ActionMetadata{canonicalAction("a", "A")},
		NestedCalls: []domain.NestedCompositeActionCall{nestedCall("a", 0, domain.CompositeActionMetadataMissing, "b")},
	}
	first := BuildWithOptions(domain.ParsedRepository{}, BuildOptions{CompositeActions: resolution})
	second := BuildWithOptions(domain.ParsedRepository{}, BuildOptions{CompositeActions: resolution})
	if len(first.Warnings) != 1 || len(second.Warnings) != 1 {
		t.Fatalf("expected exactly one warning each run: first=%v second=%v", first.Warnings, second.Warnings)
	}
	if first.Warnings[0] != second.Warnings[0] {
		t.Fatalf("warning text not deterministic: %q vs %q", first.Warnings[0], second.Warnings[0])
	}
	if !strings.Contains(first.Warnings[0], "COMPOSITE_ACTION_NESTED_RESOLUTION") {
		t.Fatalf("expected COMPOSITE_ACTION_NESTED_RESOLUTION warning, got %q", first.Warnings[0])
	}
}

// 56. cycle warning is deterministic; 57. depth warning is deterministic.
func TestNestedCompositeActionCycleAndDepthWarningsDeterministic(t *testing.T) {
	diagnostics := []domain.NestedCompositeActionDiagnostic{
		{Kind: domain.NestedCompositeActionDiagnosticCycle, RootCanonicalDirectory: "a", Path: []string{"a", "b", "a"}, Evidence: testEvidence("a/action.yml", 3, "runs.steps")},
		{Kind: domain.NestedCompositeActionDiagnosticDepthExceeded, RootCanonicalDirectory: "a", Path: []string{"a", "b", "c"}, Depth: 11, Limit: 10, Evidence: testEvidence("a/action.yml", 3, "runs.steps")},
	}
	resolution := domain.CompositeActionResolution{Diagnostics: diagnostics}
	first := BuildWithOptions(domain.ParsedRepository{}, BuildOptions{CompositeActions: resolution})
	second := BuildWithOptions(domain.ParsedRepository{}, BuildOptions{CompositeActions: resolution})
	if len(first.Warnings) != 2 || len(second.Warnings) != 2 {
		t.Fatalf("expected exactly two warnings each run: first=%v second=%v", first.Warnings, second.Warnings)
	}
	for i := range first.Warnings {
		if first.Warnings[i] != second.Warnings[i] {
			t.Fatalf("warnings not deterministic at index %d: %q vs %q", i, first.Warnings[i], second.Warnings[i])
		}
	}
	foundCycle, foundDepth := false, false
	for _, w := range first.Warnings {
		if strings.Contains(w, "COMPOSITE_ACTION_NESTING_CYCLE") {
			foundCycle = true
		}
		if strings.Contains(w, "COMPOSITE_ACTION_NESTING_DEPTH") {
			foundDepth = true
			if !strings.Contains(w, "11") || !strings.Contains(w, "10") {
				t.Fatalf("depth warning must include both attempted (11) and configured max (10): %q", w)
			}
		}
	}
	if !foundCycle || !foundDepth {
		t.Fatalf("expected both cycle and depth warnings, got %v", first.Warnings)
	}
}

// 58/59. cycle/depth warnings create no finding and no score change — a
// pure architectural property: these diagnostics only ever populate
// BuildResult.Warnings (plain strings), never Findings, Credentials, or any
// scoring-relevant structure.
func TestNestedCompositeActionCycleDepthWarningsCreateNoFindingOrScoreEffect(t *testing.T) {
	diagnostics := []domain.NestedCompositeActionDiagnostic{
		{Kind: domain.NestedCompositeActionDiagnosticCycle, RootCanonicalDirectory: "a", Path: []string{"a", "a"}, Evidence: testEvidence("a/action.yml", 3, "runs.steps")},
	}
	resolution := domain.CompositeActionResolution{Diagnostics: diagnostics}
	built := BuildWithOptions(domain.ParsedRepository{}, BuildOptions{CompositeActions: resolution})
	if len(built.Credentials) != 0 {
		t.Fatalf("cycle diagnostic must not create any credential, got %#v", built.Credentials)
	}
	// BuildWithOptions always creates the selected repository root node.
	// The diagnostic itself must not create any additional feature node or edge.
	if len(built.Graph.Nodes) != 1 || built.Graph.Nodes[0].Type != domain.NodeRepository {
		t.Fatalf("cycle diagnostic must create no nodes beyond the repository root, got %#v", built.Graph.Nodes)
	}
	if len(built.Graph.Edges) != 0 {
		t.Fatalf("cycle diagnostic alone must create no graph edges, got %#v", built.Graph.Edges)
	}
	for _, w := range built.Warnings {
		if strings.Contains(w, "CRD") {
			t.Fatalf("warning must not resemble a CRD rule ID: %q", w)
		}
	}
}

// 62. no nested confirmed input forwarding is created — CA3A is purely
// structural; nothing in this package produces a
// NodeCompositeActionInputBinding/Usage from nested resolution data alone.
func TestNestedCompositeActionCreatesNoConfirmedInputForwarding(t *testing.T) {
	resolution := domain.CompositeActionResolution{
		Actions:     []domain.ActionMetadata{canonicalAction("a", "A"), canonicalAction("b", "B")},
		NestedCalls: []domain.NestedCompositeActionCall{resolvedNestedCall("a", 0, "b")},
	}
	built := BuildWithOptions(domain.ParsedRepository{}, BuildOptions{CompositeActions: resolution})
	if len(nodesByType(built.Graph.Nodes, domain.NodeCompositeActionInputBinding)) != 0 {
		t.Fatal("CA3A must never create a NodeCompositeActionInputBinding")
	}
	if len(nodesByType(built.Graph.Nodes, domain.NodeCompositeActionInputUsage)) != 0 {
		t.Fatal("CA3A must never create a NodeCompositeActionInputUsage")
	}
	if len(nodesByType(built.Graph.Nodes, domain.NodeCredential)) != 0 {
		t.Fatal("CA3A must never create a NodeCredential")
	}
}

// 63. graph deterministic.
func TestNestedCompositeActionGraphDeterministic(t *testing.T) {
	resolution := domain.CompositeActionResolution{
		Actions: []domain.ActionMetadata{canonicalAction("a", "A"), canonicalAction("b", "B"), canonicalAction("c", "C")},
		NestedCalls: []domain.NestedCompositeActionCall{
			resolvedNestedCall("a", 0, "b"),
			resolvedNestedCall("a", 1, "c"),
			nestedCall("b", 0, domain.CompositeActionMetadataMissing, "missing"),
		},
	}
	first := BuildWithOptions(domain.ParsedRepository{}, BuildOptions{CompositeActions: resolution})
	second := BuildWithOptions(domain.ParsedRepository{}, BuildOptions{CompositeActions: resolution})
	firstJSON, err := json.Marshal(first.Graph)
	if err != nil {
		t.Fatal(err)
	}
	secondJSON, err := json.Marshal(second.Graph)
	if err != nil {
		t.Fatal(err)
	}
	if string(firstJSON) != string(secondJSON) {
		t.Fatal("graph construction is not deterministic")
	}
	if len(first.Warnings) != len(second.Warnings) {
		t.Fatal("warnings are not deterministic in count")
	}
}

// Metadata safety: no raw values, expressions, defaults, or command bodies
// ever appear in nested structural edge metadata.
func TestNestedCompositeActionEdgeMetadataSafe(t *testing.T) {
	resolution := domain.CompositeActionResolution{
		Actions:     []domain.ActionMetadata{canonicalAction("a", "A"), canonicalAction("b", "B")},
		NestedCalls: []domain.NestedCompositeActionCall{resolvedNestedCall("a", 0, "b")},
	}
	built := BuildWithOptions(domain.ParsedRepository{}, BuildOptions{CompositeActions: resolution})
	allowed := map[string]bool{
		"parent_canonical_directory": true, "parent_metadata_file": true, "parent_action_step_index": true,
		"parent_action_step_id": true, "raw_reference": true, "canonical_directory": true,
		"metadata_file": true, "resolution_status": true,
	}
	for _, edge := range built.Graph.Edges {
		for key, value := range edge.Metadata {
			if !allowed[key] {
				t.Fatalf("unexpected nested edge metadata key %q: %#v", key, edge.Metadata)
			}
			if strings.Contains(value, "${{") {
				t.Fatalf("nested edge metadata must never contain expression text: %q=%q", key, value)
			}
		}
	}
}
