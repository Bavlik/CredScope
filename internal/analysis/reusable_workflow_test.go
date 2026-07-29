package analysis

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/Bavlik/CredScope/internal/domain"
)

func rwEvidence(path string, line int, field string) domain.Evidence {
	return domain.Evidence{Location: domain.Location{Path: path, Line: line}, Field: field, Source: "test", Confidence: domain.ConfidenceConfirmed}
}

func rwReference(name, path string, line int) domain.Reference {
	return domain.Reference{Kind: domain.ReferenceSecret, Name: name, Expression: "${{ secrets." + name + " }}", Evidence: rwEvidence(path, line, "secret")}
}

func rwWorkflow(file string, triggers []string, jobs ...domain.WorkflowJob) domain.Workflow {
	var trig []domain.WorkflowTrigger
	for _, t := range triggers {
		trig = append(trig, domain.WorkflowTrigger{Name: t, Evidence: rwEvidence(file, 1, "on")})
	}
	return domain.Workflow{Name: file, File: file, Triggers: trig, Jobs: jobs, Evidence: rwEvidence(file, 1, "workflow")}
}

func rwCallerJob(file, id, uses string, credentialNames ...string) domain.WorkflowJob {
	var refs []domain.Reference
	for _, name := range credentialNames {
		refs = append(refs, rwReference(name, file, 3))
	}
	return domain.WorkflowJob{
		ID:               id,
		Evidence:         rwEvidence(file, 2, "jobs."+id),
		ReusableWorkflow: &domain.ActionReference{Reference: uses, Local: true, Evidence: rwEvidence(file, 2, "jobs."+id+".uses")},
		References:       refs,
	}
}

func rwPlainJob(file, id string, credentialNames ...string) domain.WorkflowJob {
	var refs []domain.Reference
	for _, name := range credentialNames {
		refs = append(refs, rwReference(name, file, 3))
	}
	return domain.WorkflowJob{ID: id, Evidence: rwEvidence(file, 2, "jobs."+id), References: refs}
}

func rwPermissiveJob(file, id string) domain.WorkflowJob {
	return domain.WorkflowJob{
		ID:       id,
		Evidence: rwEvidence(file, 2, "jobs."+id),
		Permissions: []domain.Permission{
			{Scope: "contents", Level: "write-all", Evidence: rwEvidence(file, 3, "jobs."+id+".permissions")},
		},
	}
}

func analyzeOrFatal(t *testing.T, parsed domain.ParsedRepository) domain.AnalysisResult {
	t.Helper()
	result, err := Analyze(context.Background(), parsed, Options{})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func workflowNodeIDByFile(result domain.AnalysisResult, file string) string {
	for _, node := range result.Graph.Nodes {
		if node.Type == domain.NodeWorkflow && node.Metadata["file"] == file {
			return node.ID
		}
	}
	return ""
}

func structuralCallEdgesTo(result domain.AnalysisResult, targetID string) []domain.Edge {
	var edges []domain.Edge
	for _, edge := range result.Graph.Edges {
		if edge.To == targetID && edge.Type == domain.EdgeCallsWorkflow && edge.EvidenceKind == domain.EvidenceStructuralCallOnly {
			edges = append(edges, edge)
		}
	}
	return edges
}

func TestAnalyzeResolvesLocalReusableCallThroughRealPipeline(t *testing.T) {
	parsed := domain.ParsedRepository{Workflows: []domain.Workflow{
		rwWorkflow(".github/workflows/caller.yml", []string{"push"}, rwCallerJob(".github/workflows/caller.yml", "call", "./.github/workflows/callee.yml", "CALLER_TOKEN")),
		rwWorkflow(".github/workflows/callee.yml", []string{"workflow_call"}, rwPlainJob(".github/workflows/callee.yml", "build")),
	}}
	result := analyzeOrFatal(t, parsed)

	credential := findCredential(result, "CALLER_TOKEN")
	if credential == nil {
		t.Fatalf("credential not analyzed; labels = %v", credentialLabels(result))
	}
	if hasRule(credential.MatchedRules, "CRD501") {
		t.Fatalf("CRD501 must not fire for a resolved local call: %#v", credential.MatchedRules)
	}

	calleeID := workflowNodeIDByFile(result, ".github/workflows/callee.yml")
	if calleeID == "" {
		t.Fatal("callee workflow node not found in graph")
	}
	if edges := structuralCallEdgesTo(result, calleeID); len(edges) != 1 {
		t.Fatalf("expected exactly one structural_call_only edge to callee, got %#v", edges)
	}
}

func TestAnalyzeExternalReusableCallStillFiresCRD501(t *testing.T) {
	job := domain.WorkflowJob{
		ID:       "call-external",
		Evidence: rwEvidence(".github/workflows/caller.yml", 2, "jobs.call-external"),
		ReusableWorkflow: &domain.ActionReference{
			Reference: "octo/repo/.github/workflows/x.yml@v1", ThirdParty: true,
			Evidence: rwEvidence(".github/workflows/caller.yml", 2, "jobs.call-external.uses"),
		},
		References: []domain.Reference{rwReference("EXTERNAL_TOKEN", ".github/workflows/caller.yml", 3)},
	}
	parsed := domain.ParsedRepository{Workflows: []domain.Workflow{
		rwWorkflow(".github/workflows/caller.yml", []string{"push"}, job),
	}}
	result := analyzeOrFatal(t, parsed)

	credential := findCredential(result, "EXTERNAL_TOKEN")
	if credential == nil {
		t.Fatalf("credential not analyzed; labels = %v", credentialLabels(result))
	}
	if !hasRule(credential.MatchedRules, "CRD501") {
		t.Fatalf("CRD501 must still fire for an external (unresolved) call: %#v", credential.MatchedRules)
	}
}

func TestAnalyzeResolvedCallDoesNotExposeCalleeSecretOrPullRequestTargetReach(t *testing.T) {
	caller := rwWorkflow(".github/workflows/caller.yml", []string{"pull_request_target"},
		rwCallerJob(".github/workflows/caller.yml", "call", "./.github/workflows/callee.yml", "CALLER_TOKEN"))
	callee := rwWorkflow(".github/workflows/callee.yml", []string{"workflow_call"},
		rwPlainJob(".github/workflows/callee.yml", "build", "CALLEE_SECRET"))
	result := analyzeOrFatal(t, domain.ParsedRepository{Workflows: []domain.Workflow{caller, callee}})

	callerCred := findCredential(result, "CALLER_TOKEN")
	calleeCred := findCredential(result, "CALLEE_SECRET")
	if callerCred == nil || calleeCred == nil {
		t.Fatalf("credentials missing; labels = %v", credentialLabels(result))
	}
	for _, path := range callerCred.EvidencePaths {
		for _, node := range path.Nodes {
			if node.ID == calleeCred.Credential.ID {
				t.Fatalf("caller credential must not reach callee's secret: %#v", path)
			}
		}
	}
	if hasRule(calleeCred.MatchedRules, "CRD104") {
		t.Fatalf("callee secret must not inherit caller's pull_request_target trigger: %#v", calleeCred.MatchedRules)
	}
}

func TestAnalyzeNoPermissionEscalationClaimFromResolvedCall(t *testing.T) {
	caller := rwWorkflow(".github/workflows/caller.yml", []string{"push"},
		rwCallerJob(".github/workflows/caller.yml", "call", "./.github/workflows/callee.yml", "CALLER_TOKEN"))
	callee := rwWorkflow(".github/workflows/callee.yml", []string{"workflow_call"}, rwPermissiveJob(".github/workflows/callee.yml", "build"))
	result := analyzeOrFatal(t, domain.ParsedRepository{Workflows: []domain.Workflow{caller, callee}})

	credential := findCredential(result, "CALLER_TOKEN")
	if credential == nil {
		t.Fatalf("credential missing; labels = %v", credentialLabels(result))
	}
	if hasRule(credential.MatchedRules, "CRD201") || hasRule(credential.MatchedRules, "CRD202") {
		t.Fatalf("callee's write-all permission must not become a claim against the caller's credential: %#v", credential.MatchedRules)
	}
}

func TestAnalyzeMultipleCallersReuseCanonicalCalleeNode(t *testing.T) {
	callerA := rwWorkflow(".github/workflows/caller-a.yml", []string{"push"}, rwCallerJob(".github/workflows/caller-a.yml", "call", "./.github/workflows/callee.yml", "TOKEN_A"))
	callerB := rwWorkflow(".github/workflows/caller-b.yml", []string{"push"}, rwCallerJob(".github/workflows/caller-b.yml", "call", "./.github/workflows/callee.yml", "TOKEN_B"))
	callee := rwWorkflow(".github/workflows/callee.yml", []string{"workflow_call"}, rwPlainJob(".github/workflows/callee.yml", "build"))
	result := analyzeOrFatal(t, domain.ParsedRepository{Workflows: []domain.Workflow{callerA, callerB, callee}})

	count := 0
	var calleeID string
	for _, node := range result.Graph.Nodes {
		if node.Type == domain.NodeWorkflow && node.Metadata["file"] == ".github/workflows/callee.yml" {
			count++
			calleeID = node.ID
		}
	}
	if count != 1 {
		t.Fatalf("expected exactly one canonical callee node, found %d", count)
	}
	if edges := structuralCallEdgesTo(result, calleeID); len(edges) != 2 {
		t.Fatalf("expected two structural_call_only edges (one per caller), got %#v", edges)
	}
}

func TestAnalyzeNestedReusableCallsAreDeterministic(t *testing.T) {
	a := rwWorkflow(".github/workflows/a.yml", []string{"push"}, rwCallerJob(".github/workflows/a.yml", "call", "./.github/workflows/b.yml", "TOKEN_A"))
	b := rwWorkflow(".github/workflows/b.yml", []string{"workflow_call"}, rwCallerJob(".github/workflows/b.yml", "call", "./.github/workflows/c.yml"))
	c := rwWorkflow(".github/workflows/c.yml", []string{"workflow_call"}, rwPlainJob(".github/workflows/c.yml", "build"))
	parsed := domain.ParsedRepository{Workflows: []domain.Workflow{a, b, c}}

	first := analyzeOrFatal(t, parsed)
	second := analyzeOrFatal(t, parsed)
	firstJSON, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	secondJSON, err := json.Marshal(second)
	if err != nil {
		t.Fatal(err)
	}
	if string(firstJSON) != string(secondJSON) {
		t.Fatal("nested reusable call analysis is not deterministic")
	}

	bID := workflowNodeIDByFile(first, ".github/workflows/b.yml")
	cID := workflowNodeIDByFile(first, ".github/workflows/c.yml")
	if len(structuralCallEdgesTo(first, bID)) != 1 || len(structuralCallEdgesTo(first, cID)) != 1 {
		t.Fatalf("expected one structural edge into each nested callee: b=%v c=%v", structuralCallEdgesTo(first, bID), structuralCallEdgesTo(first, cID))
	}
}

func TestAnalyzeDoesNotMutateInputRepository(t *testing.T) {
	parsed := domain.ParsedRepository{Workflows: []domain.Workflow{
		rwWorkflow(".github/workflows/caller.yml", []string{"push"}, rwCallerJob(".github/workflows/caller.yml", "call", "./.github/workflows/callee.yml", "CALLER_TOKEN")),
		rwWorkflow(".github/workflows/callee.yml", []string{"workflow_call"}, rwPlainJob(".github/workflows/callee.yml", "build")),
	}}
	before, err := json.Marshal(parsed)
	if err != nil {
		t.Fatal(err)
	}
	beforeCopy := domain.ParsedRepository{Workflows: append([]domain.Workflow(nil), parsed.Workflows...)}

	analyzeOrFatal(t, parsed)

	after, err := json.Marshal(parsed)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("Analyze mutated its input ParsedRepository (JSON diverged)")
	}
	if !reflect.DeepEqual(beforeCopy.Workflows, parsed.Workflows) {
		t.Fatal("Analyze mutated its input ParsedRepository (DeepEqual diverged)")
	}
}

func TestAnalyzeRepositoryWithoutReusableCallsHasNoReusableWorkflowArtifacts(t *testing.T) {
	parsed := domain.ParsedRepository{Workflows: []domain.Workflow{
		rwWorkflow(".github/workflows/plain.yml", []string{"push"}, rwPlainJob(".github/workflows/plain.yml", "build", "PLAIN_TOKEN")),
	}}
	first := analyzeOrFatal(t, parsed)
	second := analyzeOrFatal(t, parsed)
	firstJSON, _ := json.Marshal(first)
	secondJSON, _ := json.Marshal(second)
	if string(firstJSON) != string(secondJSON) {
		t.Fatal("plain repository analysis is not deterministic")
	}
	for _, node := range first.Graph.Nodes {
		if node.Type == domain.NodeReusableWorkflow {
			t.Fatalf("no NodeReusableWorkflow expected without any uses: %#v", node)
		}
	}
	for _, edge := range first.Graph.Edges {
		if edge.EvidenceKind == domain.EvidenceStructuralCallOnly {
			t.Fatalf("no structural_call_only edge expected without any reusable call: %#v", edge)
		}
	}
}

func TestAnalyzeSelfReferentialResolvedCallDoesNotProduceMalformedGraph(t *testing.T) {
	file := ".github/workflows/selfcall.yml"
	job := rwCallerJob(file, "call", "./"+file, "SELF_TOKEN")
	parsed := domain.ParsedRepository{Workflows: []domain.Workflow{rwWorkflow(file, []string{"push", "workflow_call"}, job)}}
	result := analyzeOrFatal(t, parsed)

	seen := make(map[string]bool, len(result.Graph.Edges))
	for _, edge := range result.Graph.Edges {
		if edge.ID == "" || seen[edge.ID] {
			t.Fatalf("malformed or duplicate edge ID %q from self-referential resolved call", edge.ID)
		}
		seen[edge.ID] = true
	}
	credential := findCredential(result, "SELF_TOKEN")
	if credential == nil {
		t.Fatalf("credential missing; labels = %v", credentialLabels(result))
	}
	if hasRule(credential.MatchedRules, "CRD501") {
		t.Fatalf("self-referential resolved call must not fire CRD501: %#v", credential.MatchedRules)
	}
}
