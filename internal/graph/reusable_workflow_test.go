package graph

import (
	"testing"

	"github.com/Bavlik/CredScope/internal/domain"
	"github.com/Bavlik/CredScope/internal/reusableworkflow"
)

func reusableJob(id, uses string) domain.WorkflowJob {
	file := ".github/workflows/caller.yml"
	return domain.WorkflowJob{
		ID:               id,
		Evidence:         testEvidence(file, 2, "jobs."+id),
		ReusableWorkflow: &domain.ActionReference{Reference: uses, Local: true, Evidence: testEvidence(file, 2, "jobs."+id+".uses")},
	}
}

func TestBuildResolvedCallCreatesStructuralEdgeAndClearsUnresolved(t *testing.T) {
	caller := domain.Workflow{Name: "caller", File: ".github/workflows/caller.yml", Evidence: testEvidence(".github/workflows/caller.yml", 1, "workflow"), Jobs: []domain.WorkflowJob{reusableJob("call", "./.github/workflows/callee.yml")}}
	callee := domain.Workflow{Name: "callee", File: ".github/workflows/callee.yml", Evidence: testEvidence(".github/workflows/callee.yml", 1, "workflow"), Triggers: []domain.WorkflowTrigger{{Name: "workflow_call", Evidence: testEvidence(".github/workflows/callee.yml", 1, "on")}}}
	parsed := domain.ParsedRepository{Workflows: []domain.Workflow{caller, callee}}
	resolved := reusableworkflow.Result{DirectCalls: []reusableworkflow.DirectCall{
		{CallerWorkflow: caller.File, CallerJobID: "call", RawUses: "./.github/workflows/callee.yml", NormalizedTarget: callee.File, Status: reusableworkflow.StatusResolvedLocal, TargetWorkflow: callee.File},
	}}

	built := BuildWithOptions(parsed, BuildOptions{ReusableWorkflows: resolved})

	var reusableNode *domain.Node
	for i := range built.Graph.Nodes {
		if built.Graph.Nodes[i].Type == domain.NodeReusableWorkflow {
			reusableNode = &built.Graph.Nodes[i]
		}
	}
	if reusableNode == nil {
		t.Fatal("reusable workflow node not created")
	}
	if reusableNode.Metadata["unresolved"] != "false" {
		t.Fatalf("resolved call must clear unresolved metadata: %#v", reusableNode.Metadata)
	}

	calleeID := workflowNodeID(callee.File, callee.Name)
	var structuralEdge *domain.Edge
	for i := range built.Graph.Edges {
		e := built.Graph.Edges[i]
		if e.From == reusableNode.ID && e.To == calleeID {
			structuralEdge = &built.Graph.Edges[i]
		}
	}
	if structuralEdge == nil {
		t.Fatal("structural call edge from call-site node to callee workflow node not found")
	}
	if structuralEdge.Type != domain.EdgeCallsWorkflow || structuralEdge.EvidenceKind != domain.EvidenceStructuralCallOnly {
		t.Fatalf("structural edge = %#v", structuralEdge)
	}
}

func TestBuildUnresolvedCallPreservesLegacyRepresentation(t *testing.T) {
	caller := domain.Workflow{Name: "caller", File: ".github/workflows/caller.yml", Evidence: testEvidence(".github/workflows/caller.yml", 1, "workflow"), Jobs: []domain.WorkflowJob{reusableJob("call", "./.github/workflows/missing.yml")}}
	parsed := domain.ParsedRepository{Workflows: []domain.Workflow{caller}}

	// Zero-value BuildOptions (no resolver Result) must behave exactly as
	// before the resolver existed: every reusable call renders unresolved.
	built := Build(parsed)

	var reusableNode *domain.Node
	for i := range built.Graph.Nodes {
		if built.Graph.Nodes[i].Type == domain.NodeReusableWorkflow {
			reusableNode = &built.Graph.Nodes[i]
		}
	}
	if reusableNode == nil {
		t.Fatal("reusable workflow node not created")
	}
	if reusableNode.Metadata["unresolved"] != "true" {
		t.Fatalf("call must remain unresolved without a resolver Result: %#v", reusableNode.Metadata)
	}
	for _, edge := range built.Graph.Edges {
		if edge.EvidenceKind == domain.EvidenceStructuralCallOnly {
			t.Fatalf("no structural_call_only edge expected for an unresolved call: %#v", edge)
		}
	}
}

func TestBuildMultipleCallersDoNotDuplicateCalleeNode(t *testing.T) {
	callee := domain.Workflow{Name: "callee", File: ".github/workflows/callee.yml", Evidence: testEvidence(".github/workflows/callee.yml", 1, "workflow"), Triggers: []domain.WorkflowTrigger{{Name: "workflow_call", Evidence: testEvidence(".github/workflows/callee.yml", 1, "on")}}}
	callerA := domain.Workflow{Name: "caller-a", File: ".github/workflows/caller-a.yml", Evidence: testEvidence(".github/workflows/caller-a.yml", 1, "workflow"), Jobs: []domain.WorkflowJob{reusableJob("call", "./.github/workflows/callee.yml")}}
	callerB := domain.Workflow{Name: "caller-b", File: ".github/workflows/caller-b.yml", Evidence: testEvidence(".github/workflows/caller-b.yml", 1, "workflow"), Jobs: []domain.WorkflowJob{reusableJob("call", "./.github/workflows/callee.yml")}}
	parsed := domain.ParsedRepository{Workflows: []domain.Workflow{callerA, callerB, callee}}
	resolved := reusableworkflow.Result{DirectCalls: []reusableworkflow.DirectCall{
		{CallerWorkflow: callerA.File, CallerJobID: "call", TargetWorkflow: callee.File, Status: reusableworkflow.StatusResolvedLocal},
		{CallerWorkflow: callerB.File, CallerJobID: "call", TargetWorkflow: callee.File, Status: reusableworkflow.StatusResolvedLocal},
	}}

	built := BuildWithOptions(parsed, BuildOptions{ReusableWorkflows: resolved})

	calleeCount := 0
	calleeID := workflowNodeID(callee.File, callee.Name)
	for _, node := range built.Graph.Nodes {
		if node.Type == domain.NodeWorkflow && node.ID == calleeID {
			calleeCount++
		}
	}
	if calleeCount != 1 {
		t.Fatalf("callee node duplicated: count = %d", calleeCount)
	}
	structuralEdges := 0
	for _, edge := range built.Graph.Edges {
		if edge.To == calleeID && edge.EvidenceKind == domain.EvidenceStructuralCallOnly {
			structuralEdges++
		}
	}
	if structuralEdges != 2 {
		t.Fatalf("expected two structural call edges into shared callee, got %d", structuralEdges)
	}
}

func TestTraversalDoesNotWalkStructuralCallOnlyEdge(t *testing.T) {
	nodes := []domain.Node{
		{ID: "cred", Type: domain.NodeCredential},
		{ID: "job", Type: domain.NodeJob},
		{ID: "callsite", Type: domain.NodeReusableWorkflow},
		{ID: "callee", Type: domain.NodeWorkflow},
	}
	edges := []domain.Edge{
		{ID: "cred-job", From: "cred", To: "job", Type: domain.EdgeConfiguredIn, EvidenceKind: domain.EvidenceExposureContext, Confidence: domain.ConfidenceConfirmed},
		{ID: "job-callsite", From: "job", To: "callsite", Type: domain.EdgeCallsWorkflow, EvidenceKind: domain.EvidenceExposureContext, Confidence: domain.ConfidenceConfirmed},
		{ID: "callsite-callee", From: "callsite", To: "callee", Type: domain.EdgeCallsWorkflow, EvidenceKind: domain.EvidenceStructuralCallOnly, Confidence: domain.ConfidenceConfirmed},
	}
	paths := Traverse(domain.Graph{Nodes: nodes, Edges: edges}, "cred", 8)
	for _, path := range paths {
		for _, node := range path.Nodes {
			if node.ID == "callee" {
				t.Fatalf("structural_call_only edge must not be walked into credential evidence paths: %+v", path)
			}
		}
	}
}
