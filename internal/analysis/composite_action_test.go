package analysis

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Bavlik/CredScope/internal/domain"
)

func caEvidence(path string, line int, field string) domain.Evidence {
	return domain.Evidence{Location: domain.Location{Path: path, Line: line}, Field: field, Source: "test", Confidence: domain.ConfidenceConfirmed}
}

func caWorkflow(file string, jobs ...domain.WorkflowJob) domain.Workflow {
	return domain.Workflow{Name: file, File: file, Jobs: jobs, Evidence: caEvidence(file, 1, "workflow")}
}

func caJobWithCompositeStep(file, id, uses, credentialName string) domain.WorkflowJob {
	step := domain.WorkflowStep{
		Action: &domain.ActionReference{Reference: uses, Local: true, Evidence: caEvidence(file, 3, "uses")},
		References: []domain.Reference{
			{Kind: domain.ReferenceSecret, Name: credentialName, Expression: "${{ secrets." + credentialName + " }}", Evidence: caEvidence(file, 3, "secret")},
		},
	}
	return domain.WorkflowJob{ID: id, Evidence: caEvidence(file, 2, "jobs."+id), Steps: []domain.WorkflowStep{step}}
}

func caCanonicalAction(directory, name string) domain.ActionMetadata {
	return domain.ActionMetadata{
		Directory: directory, File: directory + "/action.yml", Name: name,
		Runs: domain.ActionRuns{Using: "composite"}, Evidence: caEvidence(directory+"/action.yml", 1, "action"),
	}
}

func caResolvedCall(workflow, jobID string, stepIndex int, directory string) domain.CompositeActionCall {
	return domain.CompositeActionCall{
		CallerWorkflow: workflow, CallerJobID: jobID, CallerStepIndex: stepIndex,
		RawReference: "./" + directory, CanonicalDirectory: directory, MetadataFile: "action.yml",
		Status: domain.CompositeActionResolvedLocalComposite, Evidence: caEvidence(workflow, 3, "uses"),
	}
}

// CA3A end-to-end: a nested composite-action structural resolution passed
// through ParsedRepository.CompositeActions.NestedCalls produces a
// parent->child structural edge in the analyzed graph, and does not change
// the top-level credential's score/rules/remediation (CA1/CA2 regression
// proof) compared to the identical repository without any nested data.
func TestAnalyzeNestedCompositeActionStructuralEdgeDoesNotChangeScoreRuleOrRemediation(t *testing.T) {
	file := ".github/workflows/caller.yml"
	directory := ".github/actions/deploy"
	nestedDirectory := ".github/actions/authenticate"
	workflows := []domain.Workflow{caWorkflow(file, caJobWithCompositeStep(file, "build", "./"+directory, "DEPLOY_TOKEN"))}

	withoutNested := analyzeOrFatal(t, domain.ParsedRepository{
		Workflows: workflows,
		CompositeActions: domain.CompositeActionResolution{
			Actions: []domain.ActionMetadata{caCanonicalAction(directory, "Deploy")},
			Calls:   []domain.CompositeActionCall{caResolvedCall(file, "build", 0, directory)},
		},
	})
	withNested := analyzeOrFatal(t, domain.ParsedRepository{
		Workflows: workflows,
		CompositeActions: domain.CompositeActionResolution{
			Actions: []domain.ActionMetadata{caCanonicalAction(directory, "Deploy"), caCanonicalAction(nestedDirectory, "Authenticate")},
			Calls:   []domain.CompositeActionCall{caResolvedCall(file, "build", 0, directory)},
			NestedCalls: []domain.NestedCompositeActionCall{{
				ParentCanonicalDirectory: directory, ParentMetadataFile: "action.yml", ParentActionStepIndex: 0,
				RawReference: "./" + nestedDirectory, CanonicalDirectory: nestedDirectory, MetadataFile: "action.yml",
				Status: domain.CompositeActionResolvedLocalComposite, Evidence: caEvidence(directory+"/action.yml", 5, "runs.steps"),
			}},
		},
	})

	foundStructuralEdge := false
	for _, node := range withNested.Graph.Nodes {
		if node.Type == domain.NodeCompositeAction && node.Label == "Authenticate" {
			foundStructuralEdge = true
		}
	}
	if !foundStructuralEdge {
		t.Fatal("expected the nested Authenticate canonical action node in the analyzed graph")
	}

	credWithout := findCredential(withoutNested, "DEPLOY_TOKEN")
	credWith := findCredential(withNested, "DEPLOY_TOKEN")
	if credWithout == nil || credWith == nil {
		t.Fatalf("credential missing: without=%v with=%v", credentialLabels(withoutNested), credentialLabels(withNested))
	}
	if credWith.Score != credWithout.Score || credWith.Severity != credWithout.Severity {
		t.Fatalf("nested structural resolution changed score/severity: without=%+v with=%+v", credWithout, credWith)
	}
	if !stringSlicesEqual(ruleIDs(credWithout.MatchedRules), ruleIDs(credWith.MatchedRules)) {
		t.Fatalf("nested structural resolution changed matched rules: without=%v with=%v", ruleIDs(credWithout.MatchedRules), ruleIDs(credWith.MatchedRules))
	}
	if len(credWith.RemediationIDs) != len(credWithout.RemediationIDs) {
		t.Fatalf("nested structural resolution changed remediation: without=%v with=%v", credWithout.RemediationIDs, credWith.RemediationIDs)
	}
}

// 66. analysis passes CompositeActions into graph construction: a resolved
// local composite action produces a NodeCompositeAction in the analyzed graph.
func TestAnalyzePassesCompositeActionsIntoGraph(t *testing.T) {
	file := ".github/workflows/caller.yml"
	directory := ".github/actions/deploy"
	parsed := domain.ParsedRepository{
		Workflows: []domain.Workflow{caWorkflow(file, caJobWithCompositeStep(file, "build", "./"+directory, "DEPLOY_TOKEN"))},
		CompositeActions: domain.CompositeActionResolution{
			Actions: []domain.ActionMetadata{caCanonicalAction(directory, "Deploy")},
			Calls:   []domain.CompositeActionCall{caResolvedCall(file, "build", 0, directory)},
		},
	}
	result := analyzeOrFatal(t, parsed)
	found := false
	for _, node := range result.Graph.Nodes {
		if node.Type == domain.NodeCompositeAction {
			found = true
		}
	}
	if !found {
		t.Fatal("expected NodeCompositeAction in analyzed graph")
	}
}

// 62/63/64. resolving a composite action must not change a credential's
// score, severity, matched rules, or remediation compared to the identical
// repository analyzed without any composite-action resolution.
func TestAnalyzeCompositeActionResolutionDoesNotChangeScoreRuleOrRemediation(t *testing.T) {
	file := ".github/workflows/caller.yml"
	directory := ".github/actions/deploy"
	workflows := []domain.Workflow{caWorkflow(file, caJobWithCompositeStep(file, "build", "./"+directory, "DEPLOY_TOKEN"))}

	withoutResolution := analyzeOrFatal(t, domain.ParsedRepository{Workflows: workflows})
	withResolution := analyzeOrFatal(t, domain.ParsedRepository{
		Workflows: workflows,
		CompositeActions: domain.CompositeActionResolution{
			Actions: []domain.ActionMetadata{caCanonicalAction(directory, "Deploy")},
			Calls:   []domain.CompositeActionCall{caResolvedCall(file, "build", 0, directory)},
		},
	})

	credWithout := findCredential(withoutResolution, "DEPLOY_TOKEN")
	credWith := findCredential(withResolution, "DEPLOY_TOKEN")
	if credWithout == nil || credWith == nil {
		t.Fatalf("credential missing: without=%v with=%v", credentialLabels(withoutResolution), credentialLabels(withResolution))
	}
	if credWith.Score != credWithout.Score || credWith.Severity != credWithout.Severity {
		t.Fatalf("score/severity changed: without=%+v with=%+v", credWithout, credWith)
	}
	if !stringSlicesEqual(ruleIDs(credWithout.MatchedRules), ruleIDs(credWith.MatchedRules)) {
		t.Fatalf("matched rules changed: without=%v with=%v", ruleIDs(credWithout.MatchedRules), ruleIDs(credWith.MatchedRules))
	}
	if len(credWith.RemediationIDs) != len(credWithout.RemediationIDs) {
		t.Fatalf("remediation changed: without=%v with=%v", credWithout.RemediationIDs, credWith.RemediationIDs)
	}
}

func ruleIDs(matches []domain.RuleMatch) []string {
	ids := make([]string, 0, len(matches))
	for _, m := range matches {
		ids = append(ids, m.RuleID)
	}
	return ids
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// 72. one malformed composite-action call must not prevent a sibling call
// in the same job from resolving.
func TestAnalyzeMalformedCompositeCallDoesNotBlockOtherCalls(t *testing.T) {
	file := ".github/workflows/caller.yml"
	goodDir := ".github/actions/deploy"
	badDir := ".github/actions/broken"
	job := domain.WorkflowJob{ID: "build", Evidence: caEvidence(file, 2, "jobs.build"), Steps: []domain.WorkflowStep{
		{Action: &domain.ActionReference{Reference: "./" + goodDir, Local: true, Evidence: caEvidence(file, 3, "uses")}},
		{Action: &domain.ActionReference{Reference: "./" + badDir, Local: true, Evidence: caEvidence(file, 4, "uses")}},
	}}
	parsed := domain.ParsedRepository{
		Workflows: []domain.Workflow{caWorkflow(file, job)},
		CompositeActions: domain.CompositeActionResolution{
			Actions: []domain.ActionMetadata{caCanonicalAction(goodDir, "Deploy")},
			Calls: []domain.CompositeActionCall{
				caResolvedCall(file, "build", 0, goodDir),
				{CallerWorkflow: file, CallerJobID: "build", CallerStepIndex: 1, RawReference: "./" + badDir, Status: domain.CompositeActionMalformedMetadata, CanonicalDirectory: badDir, MetadataFile: "action.yml", Evidence: caEvidence(file, 4, "uses")},
			},
		},
	}
	result := analyzeOrFatal(t, parsed)
	canonicalCount := 0
	for _, node := range result.Graph.Nodes {
		if node.Type == domain.NodeCompositeAction {
			canonicalCount++
		}
	}
	if canonicalCount != 1 {
		t.Fatalf("expected exactly one canonical node despite one malformed sibling call, got %d", canonicalCount)
	}
	foundWarning := false
	for _, w := range result.Warnings {
		if strings.Contains(w, "COMPOSITE_ACTION_RESOLUTION") {
			foundWarning = true
		}
	}
	if !foundWarning {
		t.Fatal("expected a composite-action resolution warning for the malformed call")
	}
}

// Determinism with composite-action resolution present.
func TestAnalyzeCompositeActionDeterministic(t *testing.T) {
	file := ".github/workflows/caller.yml"
	directory := ".github/actions/deploy"
	parsed := domain.ParsedRepository{
		Workflows: []domain.Workflow{caWorkflow(file, caJobWithCompositeStep(file, "build", "./"+directory, "DEPLOY_TOKEN"))},
		CompositeActions: domain.CompositeActionResolution{
			Actions: []domain.ActionMetadata{caCanonicalAction(directory, "Deploy")},
			Calls:   []domain.CompositeActionCall{caResolvedCall(file, "build", 0, directory)},
		},
	}
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
		t.Fatal("composite action analysis is not deterministic")
	}
}
