package graph

import (
	"encoding/json"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/Bavlik/CredScope/internal/domain"
	"github.com/Bavlik/CredScope/internal/reusableworkflow"
)

func inheritJob(file, id, uses string) domain.WorkflowJob {
	inheritEvidence := testEvidence(file, 3, "jobs."+id+".secrets")
	return domain.WorkflowJob{
		ID:                             id,
		Evidence:                       testEvidence(file, 2, "jobs."+id),
		ReusableWorkflow:               &domain.ActionReference{Reference: uses, Local: true, Evidence: testEvidence(file, 2, "jobs."+id+".uses")},
		ReusableSecretsInherit:         true,
		ReusableSecretsInheritEvidence: &inheritEvidence,
	}
}

func plainReusableJob(file, id, uses string) domain.WorkflowJob {
	return domain.WorkflowJob{
		ID:               id,
		Evidence:         testEvidence(file, 2, "jobs."+id),
		ReusableWorkflow: &domain.ActionReference{Reference: uses, Local: true, Evidence: testEvidence(file, 2, "jobs."+id+".uses")},
	}
}

func inheritDiagnostics(warnings []string) []string {
	var result []string
	for _, w := range warnings {
		if strings.HasPrefix(w, reusableSecretsInheritDiagnosticCode+":") {
			result = append(result, w)
		}
	}
	return result
}

func forwardingEdgeCount(built BuildResult) int {
	count := 0
	for _, e := range built.Graph.Edges {
		if e.Type == domain.EdgeExplicitlyForwardedTo {
			count++
		}
	}
	return count
}

func TestInheritResolvedLocalCallEmitsExactlyOneDiagnostic(t *testing.T) {
	caller := domain.Workflow{Name: callerFile, File: callerFile, Evidence: testEvidence(callerFile, 1, "workflow"), Jobs: []domain.WorkflowJob{
		inheritJob(callerFile, "call", "./.github/workflows/callee.yml"),
	}}
	callee := calleeWorkflow(calleeFile, nil)
	parsed := domain.ParsedRepository{Workflows: []domain.Workflow{caller, callee}}
	built := BuildWithOptions(parsed, BuildOptions{ReusableWorkflows: resolvedLocalResult([3]string{callerFile, "call", calleeFile})})

	diags := inheritDiagnostics(built.Warnings)
	if len(diags) != 1 {
		t.Fatalf("expected exactly one inherit diagnostic, got %d: %#v", len(diags), diags)
	}
	d := diags[0]
	for _, want := range []string{callerFile, "call", calleeFile, "resolved_local", callerFile + ":3"} {
		if !strings.Contains(d, want) {
			t.Fatalf("diagnostic missing %q: %s", want, d)
		}
	}
}

func TestInheritAbsentEmitsNoInheritDiagnostic(t *testing.T) {
	caller := domain.Workflow{Name: callerFile, File: callerFile, Evidence: testEvidence(callerFile, 1, "workflow"), Jobs: []domain.WorkflowJob{
		plainReusableJob(callerFile, "call", "./.github/workflows/callee.yml"),
	}}
	callee := calleeWorkflow(calleeFile, nil)
	parsed := domain.ParsedRepository{Workflows: []domain.Workflow{caller, callee}}
	built := BuildWithOptions(parsed, BuildOptions{ReusableWorkflows: resolvedLocalResult([3]string{callerFile, "call", calleeFile})})

	if diags := inheritDiagnostics(built.Warnings); len(diags) != 0 {
		t.Fatalf("expected no inherit diagnostic without inherit: %#v", diags)
	}
}

func TestInheritTogglingChangesOnlyDiagnosticsNotGraph(t *testing.T) {
	callee := calleeWorkflow(calleeFile, nil)
	resolved := resolvedLocalResult([3]string{callerFile, "call", calleeFile})

	without := domain.Workflow{Name: callerFile, File: callerFile, Evidence: testEvidence(callerFile, 1, "workflow"), Jobs: []domain.WorkflowJob{
		plainReusableJob(callerFile, "call", "./.github/workflows/callee.yml"),
	}}
	with := domain.Workflow{Name: callerFile, File: callerFile, Evidence: testEvidence(callerFile, 1, "workflow"), Jobs: []domain.WorkflowJob{
		inheritJob(callerFile, "call", "./.github/workflows/callee.yml"),
	}}

	builtWithout := BuildWithOptions(domain.ParsedRepository{Workflows: []domain.Workflow{without, callee}}, BuildOptions{ReusableWorkflows: resolved})
	builtWith := BuildWithOptions(domain.ParsedRepository{Workflows: []domain.Workflow{with, callee}}, BuildOptions{ReusableWorkflows: resolved})

	if !reflect.DeepEqual(builtWithout.Graph.Nodes, builtWith.Graph.Nodes) {
		t.Fatal("adding inherit must not change graph nodes")
	}
	if !reflect.DeepEqual(builtWithout.Graph.Edges, builtWith.Graph.Edges) {
		t.Fatal("adding inherit must not change graph edges")
	}
	if len(inheritDiagnostics(builtWithout.Warnings)) != 0 {
		t.Fatal("no-inherit build must have no inherit diagnostics")
	}
	if len(inheritDiagnostics(builtWith.Warnings)) != 1 {
		t.Fatal("inherit build must have exactly one inherit diagnostic")
	}
}

func TestInheritSameSecretNameNoForwardingEdge(t *testing.T) {
	callerJob := inheritJob(callerFile, "call", "./.github/workflows/callee.yml")
	callerJob.References = []domain.Reference{testReference("TOKEN", callerFile, 9)}
	caller := domain.Workflow{Name: callerFile, File: callerFile, Evidence: testEvidence(callerFile, 1, "workflow"), Jobs: []domain.WorkflowJob{callerJob}, References: callerJob.References}
	calleeJob := domain.WorkflowJob{ID: "use", Evidence: testEvidence(calleeFile, 2, "jobs.use"), References: []domain.Reference{testReference("TOKEN", calleeFile, 3)}}
	callee := domain.Workflow{
		Name: calleeFile, File: calleeFile, Evidence: testEvidence(calleeFile, 1, "workflow"),
		Triggers: []domain.WorkflowTrigger{{Name: "workflow_call", Evidence: testEvidence(calleeFile, 1, "on")}},
		Jobs:     []domain.WorkflowJob{calleeJob}, References: calleeJob.References,
	}
	parsed := domain.ParsedRepository{Workflows: []domain.Workflow{caller, callee}}
	built := BuildWithOptions(parsed, BuildOptions{ReusableWorkflows: resolvedLocalResult([3]string{callerFile, "call", calleeFile})})

	if count := forwardingEdgeCount(built); count != 0 {
		t.Fatalf("same-name caller/callee usage must not create a forwarding edge under inherit: %d edges", count)
	}
}

func TestInheritTwoUnrelatedWorkflowsSameNameUnchanged(t *testing.T) {
	fileA := ".github/workflows/a.yml"
	fileB := ".github/workflows/b.yml"
	a := domain.Workflow{Name: fileA, File: fileA, Evidence: testEvidence(fileA, 1, "workflow"), Jobs: []domain.WorkflowJob{
		{ID: "job", Evidence: testEvidence(fileA, 2, "jobs.job"), References: []domain.Reference{testReference("DEPLOY_TOKEN", fileA, 3)}},
	}, References: []domain.Reference{testReference("DEPLOY_TOKEN", fileA, 3)}}
	b := domain.Workflow{Name: fileB, File: fileB, Evidence: testEvidence(fileB, 1, "workflow"), Jobs: []domain.WorkflowJob{
		{ID: "job", Evidence: testEvidence(fileB, 2, "jobs.job"), References: []domain.Reference{testReference("DEPLOY_TOKEN", fileB, 3)}},
	}, References: []domain.Reference{testReference("DEPLOY_TOKEN", fileB, 3)}}
	parsed := domain.ParsedRepository{Workflows: []domain.Workflow{a, b}}

	before := BuildWithOptions(parsed, BuildOptions{})
	// Building with this pass present must produce byte-identical output for
	// unrelated workflows with no reusable-workflow relationship at all.
	after := BuildWithOptions(parsed, BuildOptions{})
	if !reflect.DeepEqual(before, after) {
		t.Fatal("unrelated same-name workflows must remain unaffected by inherit diagnostic logic")
	}
	if diags := inheritDiagnostics(before.Warnings); len(diags) != 0 {
		t.Fatalf("no reusable-workflow relationship exists; expected zero inherit diagnostics: %#v", diags)
	}
}

func TestInheritNoPassToGrandchildCreatesNoPath(t *testing.T) {
	fileA := ".github/workflows/a.yml"
	fileB := ".github/workflows/b.yml"
	fileC := ".github/workflows/c.yml"
	a := domain.Workflow{Name: fileA, File: fileA, Evidence: testEvidence(fileA, 1, "workflow"), Jobs: []domain.WorkflowJob{
		inheritJob(fileA, "call", "./.github/workflows/b.yml"),
	}}
	b := domain.Workflow{
		Name: fileB, File: fileB, Evidence: testEvidence(fileB, 1, "workflow"),
		Triggers: []domain.WorkflowTrigger{{Name: "workflow_call", Evidence: testEvidence(fileB, 1, "on")}},
		Jobs:     []domain.WorkflowJob{plainReusableJob(fileB, "call", "./.github/workflows/c.yml")},
	}
	c := calleeWorkflow(fileC, nil)
	parsed := domain.ParsedRepository{Workflows: []domain.Workflow{a, b, c}}
	built := BuildWithOptions(parsed, BuildOptions{ReusableWorkflows: resolvedLocalResult(
		[3]string{fileA, "call", fileB},
		[3]string{fileB, "call", fileC},
	)})

	if count := forwardingEdgeCount(built); count != 0 {
		t.Fatalf("no credential path must be invented across an inherit-then-no-pass chain: %d edges", count)
	}
	if diags := inheritDiagnostics(built.Warnings); len(diags) != 1 {
		t.Fatalf("expected exactly one inherit diagnostic (A's call only), got %#v", diags)
	}
}

func TestInheritNestedABCTwoDiagnosticsNoInventedChain(t *testing.T) {
	fileA := ".github/workflows/a.yml"
	fileB := ".github/workflows/b.yml"
	fileC := ".github/workflows/c.yml"
	a := domain.Workflow{Name: fileA, File: fileA, Evidence: testEvidence(fileA, 1, "workflow"), Jobs: []domain.WorkflowJob{
		inheritJob(fileA, "call", "./.github/workflows/b.yml"),
	}}
	b := domain.Workflow{
		Name: fileB, File: fileB, Evidence: testEvidence(fileB, 1, "workflow"),
		Triggers: []domain.WorkflowTrigger{{Name: "workflow_call", Evidence: testEvidence(fileB, 1, "on")}},
		Jobs:     []domain.WorkflowJob{inheritJob(fileB, "call", "./.github/workflows/c.yml")},
	}
	c := calleeWorkflow(fileC, nil)
	parsed := domain.ParsedRepository{Workflows: []domain.Workflow{a, b, c}}
	built := BuildWithOptions(parsed, BuildOptions{ReusableWorkflows: resolvedLocalResult(
		[3]string{fileA, "call", fileB},
		[3]string{fileB, "call", fileC},
	)})

	diags := inheritDiagnostics(built.Warnings)
	if len(diags) != 2 {
		t.Fatalf("expected two inherit diagnostics (A->B, B->C), got %d: %#v", len(diags), diags)
	}
	if count := forwardingEdgeCount(built); count != 0 {
		t.Fatalf("nested inherit must not invent a credential chain: %d edges", count)
	}
}

func TestInheritGitleaksNameCollisionNoInheritFlow(t *testing.T) {
	caller := domain.Workflow{Name: callerFile, File: callerFile, Evidence: testEvidence(callerFile, 1, "workflow"), Jobs: []domain.WorkflowJob{
		inheritJob(callerFile, "call", "./.github/workflows/callee.yml"),
	}}
	callee := calleeWorkflow(calleeFile, []string{})
	finding := domain.Finding{
		ID: "finding-1", RuleID: "demo", Source: "test",
		Credential: domain.CredentialIdentity{Label: "DEPLOY_TOKEN", Fingerprint: "sha256:abc"},
		Location:   domain.Location{Path: callerFile, Line: 10},
	}
	parsed := domain.ParsedRepository{Workflows: []domain.Workflow{caller, callee}, Findings: []domain.Finding{finding}}
	built := BuildWithOptions(parsed, BuildOptions{ReusableWorkflows: resolvedLocalResult([3]string{callerFile, "call", calleeFile})})

	if count := forwardingEdgeCount(built); count != 0 {
		t.Fatalf("Gitleaks finding must not create an inherit-specific forwarding edge: %d edges", count)
	}
	for _, d := range inheritDiagnostics(built.Warnings) {
		if strings.Contains(d, "DEPLOY_TOKEN") {
			t.Fatalf("inherit diagnostic must never name a specific secret: %s", d)
		}
	}
}

func TestInheritGitHubTokenNoInheritSpecificFlow(t *testing.T) {
	callerJob := inheritJob(callerFile, "call", "./.github/workflows/callee.yml")
	callerJob.References = []domain.Reference{testReference("GITHUB_TOKEN", callerFile, 9)}
	caller := domain.Workflow{Name: callerFile, File: callerFile, Evidence: testEvidence(callerFile, 1, "workflow"), Jobs: []domain.WorkflowJob{callerJob}}
	calleeJob := domain.WorkflowJob{ID: "use", Evidence: testEvidence(calleeFile, 2, "jobs.use"), References: []domain.Reference{testReference("GITHUB_TOKEN", calleeFile, 3)}}
	callee := domain.Workflow{
		Name: calleeFile, File: calleeFile, Evidence: testEvidence(calleeFile, 1, "workflow"),
		Triggers: []domain.WorkflowTrigger{{Name: "workflow_call", Evidence: testEvidence(calleeFile, 1, "on")}},
		Jobs:     []domain.WorkflowJob{calleeJob},
	}
	parsed := domain.ParsedRepository{Workflows: []domain.Workflow{caller, callee}}
	built := BuildWithOptions(parsed, BuildOptions{ReusableWorkflows: resolvedLocalResult([3]string{callerFile, "call", calleeFile})})

	if count := forwardingEdgeCount(built); count != 0 {
		t.Fatalf("GITHUB_TOKEN must not produce an inherit-specific forwarding edge: %d edges", count)
	}
	for _, d := range inheritDiagnostics(built.Warnings) {
		if strings.Contains(d, "GITHUB_TOKEN") {
			t.Fatalf("inherit diagnostic must never attribute GITHUB_TOKEN specifically: %s", d)
		}
	}
}

func TestInheritEnvironmentJobNoConfirmedEdge(t *testing.T) {
	caller := domain.Workflow{Name: callerFile, File: callerFile, Evidence: testEvidence(callerFile, 1, "workflow"), Jobs: []domain.WorkflowJob{
		inheritJob(callerFile, "call", "./.github/workflows/callee.yml"),
	}}
	calleeJob := domain.WorkflowJob{
		ID: "deploy", Evidence: testEvidence(calleeFile, 2, "jobs.deploy"),
		EnvironmentName: "production",
		References:      []domain.Reference{testReference("TOKEN", calleeFile, 3)},
	}
	callee := domain.Workflow{
		Name: calleeFile, File: calleeFile, Evidence: testEvidence(calleeFile, 1, "workflow"),
		Triggers: []domain.WorkflowTrigger{{Name: "workflow_call", Evidence: testEvidence(calleeFile, 1, "on")}},
		Jobs:     []domain.WorkflowJob{calleeJob},
	}
	parsed := domain.ParsedRepository{Workflows: []domain.Workflow{caller, callee}}
	built := BuildWithOptions(parsed, BuildOptions{ReusableWorkflows: resolvedLocalResult([3]string{callerFile, "call", calleeFile})})

	if count := forwardingEdgeCount(built); count != 0 {
		t.Fatalf("an environment-scoped callee job must not receive any inherited confirmed edge: %d edges", count)
	}
}

func TestInheritTwoCallerJobsTwoIndependentDiagnostics(t *testing.T) {
	caller := domain.Workflow{Name: callerFile, File: callerFile, Evidence: testEvidence(callerFile, 1, "workflow"), Jobs: []domain.WorkflowJob{
		inheritJob(callerFile, "call-1", "./.github/workflows/callee.yml"),
		inheritJob(callerFile, "call-2", "./.github/workflows/callee.yml"),
	}}
	callee := calleeWorkflow(calleeFile, nil)
	parsed := domain.ParsedRepository{Workflows: []domain.Workflow{caller, callee}}
	built := BuildWithOptions(parsed, BuildOptions{ReusableWorkflows: resolvedLocalResult(
		[3]string{callerFile, "call-1", calleeFile},
		[3]string{callerFile, "call-2", calleeFile},
	)})

	diags := inheritDiagnostics(built.Warnings)
	if len(diags) != 2 {
		t.Fatalf("expected two independent diagnostics, got %d: %#v", len(diags), diags)
	}
	if diags[0] == diags[1] {
		t.Fatal("two distinct jobs must not collapse into one diagnostic")
	}
}

func TestInheritTwoCallerWorkflowsCallScopedIdentity(t *testing.T) {
	callerAFile := ".github/workflows/caller-a.yml"
	callerBFile := ".github/workflows/caller-b.yml"
	callerA := domain.Workflow{Name: callerAFile, File: callerAFile, Evidence: testEvidence(callerAFile, 1, "workflow"), Jobs: []domain.WorkflowJob{
		inheritJob(callerAFile, "call", "./.github/workflows/callee.yml"),
	}}
	callerB := domain.Workflow{Name: callerBFile, File: callerBFile, Evidence: testEvidence(callerBFile, 1, "workflow"), Jobs: []domain.WorkflowJob{
		inheritJob(callerBFile, "call", "./.github/workflows/callee.yml"),
	}}
	callee := calleeWorkflow(calleeFile, nil)
	parsed := domain.ParsedRepository{Workflows: []domain.Workflow{callerA, callerB, callee}}
	built := BuildWithOptions(parsed, BuildOptions{ReusableWorkflows: resolvedLocalResult(
		[3]string{callerAFile, "call", calleeFile},
		[3]string{callerBFile, "call", calleeFile},
	)})

	diags := inheritDiagnostics(built.Warnings)
	if len(diags) != 2 {
		t.Fatalf("expected two call-scoped diagnostics, got %d: %#v", len(diags), diags)
	}
	foundA, foundB := false, false
	for _, d := range diags {
		if strings.Contains(d, callerAFile) {
			foundA = true
		}
		if strings.Contains(d, callerBFile) {
			foundB = true
		}
	}
	if !foundA || !foundB {
		t.Fatalf("both callers must be independently identified: %#v", diags)
	}
}

func TestInheritExternalRecordsOpaqueExternalStatus(t *testing.T) {
	caller := domain.Workflow{Name: callerFile, File: callerFile, Evidence: testEvidence(callerFile, 1, "workflow"), Jobs: []domain.WorkflowJob{
		inheritJob(callerFile, "call", "octo/repo/.github/workflows/deploy.yml@v1"),
	}}
	parsed := domain.ParsedRepository{Workflows: []domain.Workflow{caller}}
	built := BuildWithOptions(parsed, BuildOptions{ReusableWorkflows: reusableworkflow.Result{DirectCalls: []reusableworkflow.DirectCall{
		{CallerWorkflow: callerFile, CallerJobID: "call", Status: reusableworkflow.StatusOpaqueExternal},
	}}})

	diags := inheritDiagnostics(built.Warnings)
	if len(diags) != 1 || !strings.Contains(diags[0], "opaque_external") {
		t.Fatalf("expected one diagnostic recording opaque_external, got %#v", diags)
	}
	if count := forwardingEdgeCount(built); count != 0 {
		t.Fatalf("external call must not create any forwarding edge: %d", count)
	}
}

func TestInheritMissingTargetRecordsTargetMissingStatus(t *testing.T) {
	caller := domain.Workflow{Name: callerFile, File: callerFile, Evidence: testEvidence(callerFile, 1, "workflow"), Jobs: []domain.WorkflowJob{
		inheritJob(callerFile, "call", "./.github/workflows/missing.yml"),
	}}
	parsed := domain.ParsedRepository{Workflows: []domain.Workflow{caller}}
	built := BuildWithOptions(parsed, BuildOptions{ReusableWorkflows: reusableworkflow.Result{DirectCalls: []reusableworkflow.DirectCall{
		{CallerWorkflow: callerFile, CallerJobID: "call", Status: reusableworkflow.StatusTargetMissing},
	}}})

	diags := inheritDiagnostics(built.Warnings)
	if len(diags) != 1 || !strings.Contains(diags[0], "target_missing") {
		t.Fatalf("expected one diagnostic recording target_missing, got %#v", diags)
	}
}

func TestInheritUnsupportedExpressionRecordsStatus(t *testing.T) {
	caller := domain.Workflow{Name: callerFile, File: callerFile, Evidence: testEvidence(callerFile, 1, "workflow"), Jobs: []domain.WorkflowJob{
		inheritJob(callerFile, "call", "${{ github.repository }}/.github/workflows/deploy.yml@main"),
	}}
	parsed := domain.ParsedRepository{Workflows: []domain.Workflow{caller}}
	built := BuildWithOptions(parsed, BuildOptions{ReusableWorkflows: reusableworkflow.Result{DirectCalls: []reusableworkflow.DirectCall{
		{CallerWorkflow: callerFile, CallerJobID: "call", Status: reusableworkflow.StatusUnsupportedExpression},
	}}})

	diags := inheritDiagnostics(built.Warnings)
	if len(diags) != 1 || !strings.Contains(diags[0], "unsupported_expression") {
		t.Fatalf("expected one diagnostic recording unsupported_expression, got %#v", diags)
	}
}

func TestInheritCycleTerminatesOneDiagnosticPerDeclaration(t *testing.T) {
	file := ".github/workflows/self.yml"
	job := inheritJob(file, "call", "./"+file)
	workflow := domain.Workflow{
		Name: file, File: file, Evidence: testEvidence(file, 1, "workflow"),
		Triggers: []domain.WorkflowTrigger{{Name: "push", Evidence: testEvidence(file, 1, "on")}, {Name: "workflow_call", Evidence: testEvidence(file, 1, "on")}},
		Jobs:     []domain.WorkflowJob{job},
	}
	parsed := domain.ParsedRepository{Workflows: []domain.Workflow{workflow}}
	built := BuildWithOptions(parsed, BuildOptions{ReusableWorkflows: resolvedLocalResult([3]string{file, "call", file})})

	diags := inheritDiagnostics(built.Warnings)
	if len(diags) != 1 {
		t.Fatalf("self-cycle must still produce exactly one diagnostic per declaration, got %#v", diags)
	}
	if count := forwardingEdgeCount(built); count != 0 {
		t.Fatalf("self-cycle inherit must not create any forwarding edge: %d", count)
	}
}

func TestInheritManyHopsNoRecursionNoInventedFlow(t *testing.T) {
	const hops = 12 // deliberately spans both sides of the 9-hop resolver cap
	var workflows []domain.Workflow
	var calls []reusableworkflow.DirectCall
	for i := 1; i <= hops; i++ {
		file := ".github/workflows/chain-" + strconv.Itoa(i) + ".yml"
		triggers := []domain.WorkflowTrigger{{Name: "push", Evidence: testEvidence(file, 1, "on")}}
		if i > 1 {
			triggers = []domain.WorkflowTrigger{{Name: "workflow_call", Evidence: testEvidence(file, 1, "on")}}
		}
		var jobs []domain.WorkflowJob
		if i < hops {
			next := ".github/workflows/chain-" + strconv.Itoa(i+1) + ".yml"
			jobs = append(jobs, inheritJob(file, "call", "./"+next))
			calls = append(calls, reusableworkflow.DirectCall{CallerWorkflow: file, CallerJobID: "call", TargetWorkflow: next, Status: reusableworkflow.StatusResolvedLocal})
		}
		workflows = append(workflows, domain.Workflow{Name: file, File: file, Evidence: testEvidence(file, 1, "workflow"), Triggers: triggers, Jobs: jobs})
	}
	parsed := domain.ParsedRepository{Workflows: workflows}
	built := BuildWithOptions(parsed, BuildOptions{ReusableWorkflows: reusableworkflow.Result{DirectCalls: calls}})

	diags := inheritDiagnostics(built.Warnings)
	if len(diags) != hops-1 {
		t.Fatalf("expected one diagnostic per inherit declaration (%d), got %d", hops-1, len(diags))
	}
	if count := forwardingEdgeCount(built); count != 0 {
		t.Fatalf("long inherit chain must not invent any forwarding edge: %d", count)
	}
}

func TestInheritDiagnosticOrderingDeterministic(t *testing.T) {
	callerAFile := ".github/workflows/caller-a.yml"
	callerBFile := ".github/workflows/caller-b.yml"
	callerB := domain.Workflow{Name: callerBFile, File: callerBFile, Evidence: testEvidence(callerBFile, 1, "workflow"), Jobs: []domain.WorkflowJob{
		inheritJob(callerBFile, "call", "./.github/workflows/callee.yml"),
	}}
	callerA := domain.Workflow{Name: callerAFile, File: callerAFile, Evidence: testEvidence(callerAFile, 1, "workflow"), Jobs: []domain.WorkflowJob{
		inheritJob(callerAFile, "call", "./.github/workflows/callee.yml"),
	}}
	callee := calleeWorkflow(calleeFile, nil)
	parsed := domain.ParsedRepository{Workflows: []domain.Workflow{callerB, callerA, callee}}
	options := BuildOptions{ReusableWorkflows: resolvedLocalResult(
		[3]string{callerAFile, "call", calleeFile},
		[3]string{callerBFile, "call", calleeFile},
	)}

	first := BuildWithOptions(parsed, options)
	second := BuildWithOptions(parsed, options)
	firstJSON, err := json.Marshal(first.Warnings)
	if err != nil {
		t.Fatal(err)
	}
	secondJSON, err := json.Marshal(second.Warnings)
	if err != nil {
		t.Fatal(err)
	}
	if string(firstJSON) != string(secondJSON) {
		t.Fatal("diagnostic ordering is not deterministic across repeated builds")
	}
	for i := 1; i < len(first.Warnings); i++ {
		if first.Warnings[i-1] > first.Warnings[i] {
			t.Fatal("warnings are not sorted")
		}
	}
}
