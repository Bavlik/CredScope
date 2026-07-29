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

func callerJobWithSecrets(file, id, uses string, secrets ...domain.ReusableWorkflowSecret) domain.WorkflowJob {
	return domain.WorkflowJob{
		ID:                      id,
		Evidence:                testEvidence(file, 2, "jobs."+id),
		ReusableWorkflow:        &domain.ActionReference{Reference: uses, Local: true, Evidence: testEvidence(file, 2, "jobs."+id+".uses")},
		ReusableWorkflowSecrets: secrets,
	}
}

func secretBinding(alias, file string, line int, refs ...domain.Reference) domain.ReusableWorkflowSecret {
	return domain.ReusableWorkflowSecret{Name: alias, References: refs, Evidence: testEvidence(file, line, "jobs.call.secrets."+alias)}
}

func contextRef(name, path string, line int) domain.Reference {
	return domain.Reference{Kind: domain.ReferenceGitHubContext, Name: name, Expression: "${{ " + name + " }}", Evidence: testEvidence(path, line, "context")}
}

func calleeUsageJob(file, id, aliasName string) domain.WorkflowJob {
	return domain.WorkflowJob{ID: id, Evidence: testEvidence(file, 2, "jobs."+id), References: []domain.Reference{testReference(aliasName, file, 3)}}
}

func calleeWorkflow(file string, aliases []string, extraJobs ...domain.WorkflowJob) domain.Workflow {
	var defs []domain.ReusableWorkflowSecretDefinition
	var refs []domain.Reference
	jobs := append([]domain.WorkflowJob{}, extraJobs...)
	for i, alias := range aliases {
		defs = append(defs, domain.ReusableWorkflowSecretDefinition{Name: alias, Required: true, Evidence: testEvidence(file, 2, "on.workflow_call.secrets."+alias)})
		job := calleeUsageJob(file, "use", alias)
		if i > 0 {
			job.ID = job.ID + strconv.Itoa(i)
		}
		refs = append(refs, job.References...)
		jobs = append(jobs, job)
	}
	for _, j := range extraJobs {
		refs = append(refs, j.References...)
	}
	return domain.Workflow{
		Name: file, File: file, Evidence: testEvidence(file, 1, "workflow"),
		Triggers:     []domain.WorkflowTrigger{{Name: "workflow_call", Evidence: testEvidence(file, 1, "on")}},
		WorkflowCall: &domain.ReusableWorkflowContract{Secrets: defs, Evidence: testEvidence(file, 1, "on.workflow_call")},
		Jobs:         jobs,
		References:   refs,
	}
}

func resolvedLocalResult(pairs ...[3]string) reusableworkflow.Result {
	var calls []reusableworkflow.DirectCall
	for _, p := range pairs {
		calls = append(calls, reusableworkflow.DirectCall{CallerWorkflow: p[0], CallerJobID: p[1], TargetWorkflow: p[2], Status: reusableworkflow.StatusResolvedLocal})
	}
	return reusableworkflow.Result{DirectCalls: calls}
}

func credentialIDByLabel(built BuildResult, label string) string {
	for _, c := range built.Credentials {
		if c.Label == label {
			return c.ID
		}
	}
	return ""
}

func forwardingEdge(built BuildResult, fromID, toID string) *domain.Edge {
	for i := range built.Graph.Edges {
		e := &built.Graph.Edges[i]
		if e.From == fromID && e.To == toID && e.Type == domain.EdgeExplicitlyForwardedTo {
			return e
		}
	}
	return nil
}

func forwardingEdgesFrom(built BuildResult, fromID string) []domain.Edge {
	var result []domain.Edge
	for _, e := range built.Graph.Edges {
		if e.From == fromID && e.Type == domain.EdgeExplicitlyForwardedTo {
			result = append(result, e)
		}
	}
	return result
}

func forwardingEdgesTo(built BuildResult, toID string) []domain.Edge {
	var result []domain.Edge
	for _, e := range built.Graph.Edges {
		if e.To == toID && e.Type == domain.EdgeExplicitlyForwardedTo {
			result = append(result, e)
		}
	}
	return result
}

const callerFile = ".github/workflows/caller.yml"
const calleeFile = ".github/workflows/callee.yml"

func TestForwardOneExplicitAliasDeclaredInContract(t *testing.T) {
	caller := domain.Workflow{Name: callerFile, File: callerFile, Evidence: testEvidence(callerFile, 1, "workflow"), Jobs: []domain.WorkflowJob{
		callerJobWithSecrets(callerFile, "call", "./.github/workflows/callee.yml", secretBinding("deployment_token", callerFile, 3, testReference("PROD_TOKEN", callerFile, 3))),
	}}
	callee := calleeWorkflow(calleeFile, []string{"deployment_token"})
	parsed := domain.ParsedRepository{Workflows: []domain.Workflow{caller, callee}}
	built := BuildWithOptions(parsed, BuildOptions{ReusableWorkflows: resolvedLocalResult([3]string{callerFile, "call", calleeFile})})

	prodID := credentialIDByLabel(built, "PROD_TOKEN")
	aliasID := credentialIDByLabel(built, "deployment_token")
	if prodID == "" || aliasID == "" {
		t.Fatalf("expected both credentials; PROD_TOKEN=%q deployment_token=%q", prodID, aliasID)
	}
	edge := forwardingEdge(built, prodID, aliasID)
	if edge == nil {
		t.Fatal("expected forwarding edge PROD_TOKEN -> deployment_token")
	}
	if edge.Confidence != domain.ConfidenceConfirmed || edge.EvidenceKind != domain.EvidenceConfirmedDataFlow {
		t.Fatalf("edge confidence/evidence kind = %#v", edge)
	}
	if edge.ID == "" {
		t.Fatal("edge missing stable ID")
	}
	foundCaller, foundCallee := false, false
	for _, ev := range edge.Evidence {
		if ev.Type == "reusable_secret_forwarding_caller" {
			foundCaller = true
		}
		if ev.Type == "reusable_secret_forwarding_callee_usage" {
			foundCallee = true
		}
	}
	if !foundCaller || !foundCallee {
		t.Fatalf("expected both caller and callee usage evidence: %#v", edge.Evidence)
	}
	wantMetadata := map[string]string{
		"caller_workflow": callerFile, "caller_job_id": "call", "target_workflow": calleeFile,
		"callee_alias": "deployment_token", "source_secret": "PROD_TOKEN", "reusable_workflow_hop": "true",
	}
	if !reflect.DeepEqual(edge.Metadata, wantMetadata) {
		t.Fatalf("edge metadata = %#v, want %#v", edge.Metadata, wantMetadata)
	}
}

func TestForwardUndeclaredAliasProducesNoEdgeButWarning(t *testing.T) {
	caller := domain.Workflow{Name: callerFile, File: callerFile, Evidence: testEvidence(callerFile, 1, "workflow"), Jobs: []domain.WorkflowJob{
		callerJobWithSecrets(callerFile, "call", "./.github/workflows/callee.yml", secretBinding("not_declared", callerFile, 3, testReference("PROD_TOKEN", callerFile, 3))),
	}}
	callee := calleeWorkflow(calleeFile, []string{"deployment_token"})
	parsed := domain.ParsedRepository{Workflows: []domain.Workflow{caller, callee}}
	built := BuildWithOptions(parsed, BuildOptions{ReusableWorkflows: resolvedLocalResult([3]string{callerFile, "call", calleeFile})})

	prodID := credentialIDByLabel(built, "PROD_TOKEN")
	if edges := forwardingEdgesFrom(built, prodID); len(edges) != 0 {
		t.Fatalf("undeclared alias must not create a forwarding edge: %#v", edges)
	}
	found := false
	for _, w := range built.Warnings {
		if strings.Contains(w, "not_declared") && strings.Contains(w, callerFile) && strings.Contains(w, calleeFile) {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected deterministic warning for undeclared alias: %#v", built.Warnings)
	}
}

func TestForwardCallerSecretUsedElsewhereAndForwarded(t *testing.T) {
	callerJob := callerJobWithSecrets(callerFile, "call", "./.github/workflows/callee.yml", secretBinding("deployment_token", callerFile, 3, testReference("PROD_TOKEN", callerFile, 3)))
	callerJob.References = []domain.Reference{testReference("PROD_TOKEN", callerFile, 9)}
	caller := domain.Workflow{Name: callerFile, File: callerFile, Evidence: testEvidence(callerFile, 1, "workflow"), Jobs: []domain.WorkflowJob{callerJob}, References: []domain.Reference{testReference("PROD_TOKEN", callerFile, 9)}}
	callee := calleeWorkflow(calleeFile, []string{"deployment_token"})
	parsed := domain.ParsedRepository{Workflows: []domain.Workflow{caller, callee}}
	built := BuildWithOptions(parsed, BuildOptions{ReusableWorkflows: resolvedLocalResult([3]string{callerFile, "call", calleeFile})})

	count := 0
	for _, c := range built.Credentials {
		if c.Label == "PROD_TOKEN" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("PROD_TOKEN must remain a single reused credential node, got %d", count)
	}
	prodID := credentialIDByLabel(built, "PROD_TOKEN")
	aliasID := credentialIDByLabel(built, "deployment_token")
	if forwardingEdge(built, prodID, aliasID) == nil {
		t.Fatal("expected forwarding edge even though PROD_TOKEN is also used elsewhere")
	}
}

func TestForwardTwoAliasesFromTwoSourceSecrets(t *testing.T) {
	caller := domain.Workflow{Name: callerFile, File: callerFile, Evidence: testEvidence(callerFile, 1, "workflow"), Jobs: []domain.WorkflowJob{
		callerJobWithSecrets(callerFile, "call", "./.github/workflows/callee.yml",
			secretBinding("token_a", callerFile, 3, testReference("SECRET_A", callerFile, 3)),
			secretBinding("token_b", callerFile, 4, testReference("SECRET_B", callerFile, 4)),
		),
	}}
	callee := calleeWorkflow(calleeFile, []string{"token_a", "token_b"})
	parsed := domain.ParsedRepository{Workflows: []domain.Workflow{caller, callee}}
	built := BuildWithOptions(parsed, BuildOptions{ReusableWorkflows: resolvedLocalResult([3]string{callerFile, "call", calleeFile})})

	if forwardingEdge(built, credentialIDByLabel(built, "SECRET_A"), credentialIDByLabel(built, "token_a")) == nil {
		t.Fatal("missing SECRET_A -> token_a edge")
	}
	if forwardingEdge(built, credentialIDByLabel(built, "SECRET_B"), credentialIDByLabel(built, "token_b")) == nil {
		t.Fatal("missing SECRET_B -> token_b edge")
	}
}

func TestForwardTwoAliasesFromOneSourceSecret(t *testing.T) {
	caller := domain.Workflow{Name: callerFile, File: callerFile, Evidence: testEvidence(callerFile, 1, "workflow"), Jobs: []domain.WorkflowJob{
		callerJobWithSecrets(callerFile, "call", "./.github/workflows/callee.yml",
			secretBinding("token_a", callerFile, 3, testReference("PROD_TOKEN", callerFile, 3)),
			secretBinding("token_b", callerFile, 4, testReference("PROD_TOKEN", callerFile, 4)),
		),
	}}
	callee := calleeWorkflow(calleeFile, []string{"token_a", "token_b"})
	parsed := domain.ParsedRepository{Workflows: []domain.Workflow{caller, callee}}
	built := BuildWithOptions(parsed, BuildOptions{ReusableWorkflows: resolvedLocalResult([3]string{callerFile, "call", calleeFile})})

	prodID := credentialIDByLabel(built, "PROD_TOKEN")
	edges := forwardingEdgesFrom(built, prodID)
	if len(edges) != 2 {
		t.Fatalf("expected two edges from the single source secret, got %#v", edges)
	}
	aliases := make(map[string]bool, 2)
	for _, e := range edges {
		aliases[e.Metadata["callee_alias"]] = true
	}
	if !aliases["token_a"] || !aliases["token_b"] {
		t.Fatalf("both distinct aliases must be identified as separate relationships in metadata: %#v", aliases)
	}
}

func TestForwardTwoCallersDifferentSecretsSameAlias(t *testing.T) {
	callerAFile := ".github/workflows/caller-a.yml"
	callerBFile := ".github/workflows/caller-b.yml"
	callerA := domain.Workflow{Name: callerAFile, File: callerAFile, Evidence: testEvidence(callerAFile, 1, "workflow"), Jobs: []domain.WorkflowJob{
		callerJobWithSecrets(callerAFile, "call", "./.github/workflows/callee.yml", secretBinding("deployment_token", callerAFile, 3, testReference("SECRET_A", callerAFile, 3))),
	}}
	callerB := domain.Workflow{Name: callerBFile, File: callerBFile, Evidence: testEvidence(callerBFile, 1, "workflow"), Jobs: []domain.WorkflowJob{
		callerJobWithSecrets(callerBFile, "call", "./.github/workflows/callee.yml", secretBinding("deployment_token", callerBFile, 3, testReference("SECRET_B", callerBFile, 3))),
	}}
	callee := calleeWorkflow(calleeFile, []string{"deployment_token"})
	parsed := domain.ParsedRepository{Workflows: []domain.Workflow{callerA, callerB, callee}}
	built := BuildWithOptions(parsed, BuildOptions{ReusableWorkflows: resolvedLocalResult(
		[3]string{callerAFile, "call", calleeFile},
		[3]string{callerBFile, "call", calleeFile},
	)})

	aliasID := credentialIDByLabel(built, "deployment_token")
	edges := forwardingEdgesTo(built, aliasID)
	if len(edges) != 2 {
		t.Fatalf("expected two callers forwarding into the same alias, got %#v", edges)
	}
	if forwardingEdge(built, credentialIDByLabel(built, "SECRET_A"), aliasID) == nil || forwardingEdge(built, credentialIDByLabel(built, "SECRET_B"), aliasID) == nil {
		t.Fatal("both distinct source secrets must reach the shared alias")
	}
	// No caller evidence must be attributed to the other caller's call.
	edgeA := forwardingEdge(built, credentialIDByLabel(built, "SECRET_A"), aliasID)
	edgeB := forwardingEdge(built, credentialIDByLabel(built, "SECRET_B"), aliasID)
	if edgeA.Metadata["caller_workflow"] != callerAFile || edgeA.Metadata["source_secret"] != "SECRET_A" {
		t.Fatalf("caller A's edge metadata incorrect: %#v", edgeA.Metadata)
	}
	if edgeB.Metadata["caller_workflow"] != callerBFile || edgeB.Metadata["source_secret"] != "SECRET_B" {
		t.Fatalf("caller B's edge metadata incorrect: %#v", edgeB.Metadata)
	}
	for _, ev := range edgeA.Evidence {
		if strings.Contains(ev.Location.Path, callerBFile) {
			t.Fatalf("caller A's edge must not carry caller B's evidence: %#v", edgeA.Evidence)
		}
	}
	for _, ev := range edgeB.Evidence {
		if strings.Contains(ev.Location.Path, callerAFile) {
			t.Fatalf("caller B's edge must not carry caller A's evidence: %#v", edgeB.Evidence)
		}
	}
}

func TestForwardSameCallerInvokesSameCalleeFromTwoJobs(t *testing.T) {
	caller := domain.Workflow{Name: callerFile, File: callerFile, Evidence: testEvidence(callerFile, 1, "workflow"), Jobs: []domain.WorkflowJob{
		callerJobWithSecrets(callerFile, "call-1", "./.github/workflows/callee.yml", secretBinding("deployment_token", callerFile, 3, testReference("PROD_TOKEN", callerFile, 3))),
		callerJobWithSecrets(callerFile, "call-2", "./.github/workflows/callee.yml", secretBinding("deployment_token", callerFile, 4, testReference("PROD_TOKEN", callerFile, 4))),
	}}
	callee := calleeWorkflow(calleeFile, []string{"deployment_token"})
	parsed := domain.ParsedRepository{Workflows: []domain.Workflow{caller, callee}}
	built := BuildWithOptions(parsed, BuildOptions{ReusableWorkflows: resolvedLocalResult(
		[3]string{callerFile, "call-1", calleeFile},
		[3]string{callerFile, "call-2", calleeFile},
	)})

	prodID := credentialIDByLabel(built, "PROD_TOKEN")
	aliasID := credentialIDByLabel(built, "deployment_token")
	if forwardingEdge(built, prodID, aliasID) == nil {
		t.Fatal("expected forwarding edge from two jobs invoking the same callee")
	}
	// Both jobs carry distinct evidence (different job IDs, different source
	// lines), so both are preserved as distinct, individually stable-ID'd
	// edges rather than one job's evidence silently overwriting the other's.
	var matching []domain.Edge
	for _, e := range built.Graph.Edges {
		if e.From == prodID && e.To == aliasID && e.Type == domain.EdgeExplicitlyForwardedTo {
			matching = append(matching, e)
		}
	}
	if len(matching) != 2 {
		t.Fatalf("expected one forwarding edge per job, found %d: %#v", len(matching), matching)
	}
	if matching[0].ID == matching[1].ID {
		t.Fatal("the two jobs' edges must have distinct stable IDs")
	}
	seenJobIDs := make(map[string]bool, 2)
	for _, e := range matching {
		seenJobIDs[e.Metadata["caller_job_id"]] = true
		if e.Metadata["caller_workflow"] != callerFile || e.Metadata["target_workflow"] != calleeFile || e.Metadata["callee_alias"] != "deployment_token" || e.Metadata["source_secret"] != "PROD_TOKEN" {
			t.Fatalf("edge metadata missing/incorrect call identity: %#v", e.Metadata)
		}
	}
	if !seenJobIDs["call-1"] || !seenJobIDs["call-2"] {
		t.Fatalf("both call-1 and call-2 must be individually identified in edge metadata: %#v", seenJobIDs)
	}
}

func TestForwardNestedChainABC(t *testing.T) {
	fileA := ".github/workflows/a.yml"
	fileB := ".github/workflows/b.yml"
	fileC := ".github/workflows/c.yml"

	a := domain.Workflow{Name: fileA, File: fileA, Evidence: testEvidence(fileA, 1, "workflow"), Jobs: []domain.WorkflowJob{
		callerJobWithSecrets(fileA, "call", "./.github/workflows/b.yml", secretBinding("middle_token", fileA, 3, testReference("ROOT_TOKEN", fileA, 3))),
	}}
	bJob := callerJobWithSecrets(fileB, "call", "./.github/workflows/c.yml", secretBinding("final_token", fileB, 3, testReference("middle_token", fileB, 3)))
	b := domain.Workflow{
		Name: fileB, File: fileB, Evidence: testEvidence(fileB, 1, "workflow"),
		Triggers:     []domain.WorkflowTrigger{{Name: "workflow_call", Evidence: testEvidence(fileB, 1, "on")}},
		WorkflowCall: &domain.ReusableWorkflowContract{Secrets: []domain.ReusableWorkflowSecretDefinition{{Name: "middle_token", Required: true, Evidence: testEvidence(fileB, 2, "on.workflow_call.secrets.middle_token")}}},
		Jobs:         []domain.WorkflowJob{bJob},
		References:   []domain.Reference{testReference("middle_token", fileB, 3)},
	}
	c := calleeWorkflow(fileC, []string{"final_token"})
	parsed := domain.ParsedRepository{Workflows: []domain.Workflow{a, b, c}}
	built := BuildWithOptions(parsed, BuildOptions{ReusableWorkflows: resolvedLocalResult(
		[3]string{fileA, "call", fileB},
		[3]string{fileB, "call", fileC},
	)})

	rootID := credentialIDByLabel(built, "ROOT_TOKEN")
	middleID := credentialIDByLabel(built, "middle_token")
	finalID := credentialIDByLabel(built, "final_token")
	if rootID == "" || middleID == "" || finalID == "" {
		t.Fatalf("missing chain credentials: root=%q middle=%q final=%q", rootID, middleID, finalID)
	}
	if forwardingEdge(built, rootID, middleID) == nil {
		t.Fatal("missing ROOT_TOKEN -> middle_token edge")
	}
	if forwardingEdge(built, middleID, finalID) == nil {
		t.Fatal("missing middle_token -> final_token edge")
	}

	paths := Traverse(built.Graph, rootID, 12)
	reachedFinal := false
	for _, p := range paths {
		for _, n := range p.Nodes {
			if n.ID == finalID {
				reachedFinal = true
			}
		}
	}
	if !reachedFinal {
		t.Fatal("ROOT_TOKEN must reach final_token through the two-hop forwarding chain")
	}
}

func TestForwardNoSecretReferenceInCallerValue(t *testing.T) {
	caller := domain.Workflow{Name: callerFile, File: callerFile, Evidence: testEvidence(callerFile, 1, "workflow"), Jobs: []domain.WorkflowJob{
		callerJobWithSecrets(callerFile, "call", "./.github/workflows/callee.yml", secretBinding("deployment_token", callerFile, 3)),
	}}
	callee := calleeWorkflow(calleeFile, []string{"deployment_token"})
	parsed := domain.ParsedRepository{Workflows: []domain.Workflow{caller, callee}}
	built := BuildWithOptions(parsed, BuildOptions{ReusableWorkflows: resolvedLocalResult([3]string{callerFile, "call", calleeFile})})

	aliasID := credentialIDByLabel(built, "deployment_token")
	if edges := forwardingEdgesTo(built, aliasID); len(edges) != 0 {
		t.Fatalf("no literal secret reference means no forwarding: %#v", edges)
	}
}

func TestForwardExpressionWithMultipleSecretReferences(t *testing.T) {
	caller := domain.Workflow{Name: callerFile, File: callerFile, Evidence: testEvidence(callerFile, 1, "workflow"), Jobs: []domain.WorkflowJob{
		callerJobWithSecrets(callerFile, "call", "./.github/workflows/callee.yml",
			secretBinding("deployment_token", callerFile, 3, testReference("SECRET_A", callerFile, 3), testReference("SECRET_B", callerFile, 3))),
	}}
	callee := calleeWorkflow(calleeFile, []string{"deployment_token"})
	parsed := domain.ParsedRepository{Workflows: []domain.Workflow{caller, callee}}
	built := BuildWithOptions(parsed, BuildOptions{ReusableWorkflows: resolvedLocalResult([3]string{callerFile, "call", calleeFile})})

	aliasID := credentialIDByLabel(built, "deployment_token")
	if edges := forwardingEdgesTo(built, aliasID); len(edges) != 0 {
		t.Fatalf("concatenation of multiple secrets must not be treated as confirmed forwarding: %#v", edges)
	}
}

func TestForwardArbitraryNonSecretExpression(t *testing.T) {
	caller := domain.Workflow{Name: callerFile, File: callerFile, Evidence: testEvidence(callerFile, 1, "workflow"), Jobs: []domain.WorkflowJob{
		callerJobWithSecrets(callerFile, "call", "./.github/workflows/callee.yml",
			secretBinding("deployment_token", callerFile, 3, contextRef("github.actor", callerFile, 3))),
	}}
	callee := calleeWorkflow(calleeFile, []string{"deployment_token"})
	parsed := domain.ParsedRepository{Workflows: []domain.Workflow{caller, callee}}
	built := BuildWithOptions(parsed, BuildOptions{ReusableWorkflows: resolvedLocalResult([3]string{callerFile, "call", calleeFile})})

	aliasID := credentialIDByLabel(built, "deployment_token")
	if edges := forwardingEdgesTo(built, aliasID); len(edges) != 0 {
		t.Fatalf("non-secret expression must not be treated as confirmed forwarding: %#v", edges)
	}
}

func TestForwardExternalReusableWorkflowNoForwarding(t *testing.T) {
	caller := domain.Workflow{Name: callerFile, File: callerFile, Evidence: testEvidence(callerFile, 1, "workflow"), Jobs: []domain.WorkflowJob{
		callerJobWithSecrets(callerFile, "call", "octo/repo/.github/workflows/deploy.yml@v1", secretBinding("deployment_token", callerFile, 3, testReference("PROD_TOKEN", callerFile, 3))),
	}}
	parsed := domain.ParsedRepository{Workflows: []domain.Workflow{caller}}
	built := BuildWithOptions(parsed, BuildOptions{ReusableWorkflows: reusableworkflow.Result{DirectCalls: []reusableworkflow.DirectCall{
		{CallerWorkflow: callerFile, CallerJobID: "call", Status: reusableworkflow.StatusOpaqueExternal},
	}}})

	prodID := credentialIDByLabel(built, "PROD_TOKEN")
	if edges := forwardingEdgesFrom(built, prodID); len(edges) != 0 {
		t.Fatalf("external call must not forward: %#v", edges)
	}
}

func TestForwardMissingTargetNoForwarding(t *testing.T) {
	caller := domain.Workflow{Name: callerFile, File: callerFile, Evidence: testEvidence(callerFile, 1, "workflow"), Jobs: []domain.WorkflowJob{
		callerJobWithSecrets(callerFile, "call", "./.github/workflows/missing.yml", secretBinding("deployment_token", callerFile, 3, testReference("PROD_TOKEN", callerFile, 3))),
	}}
	parsed := domain.ParsedRepository{Workflows: []domain.Workflow{caller}}
	built := BuildWithOptions(parsed, BuildOptions{ReusableWorkflows: reusableworkflow.Result{DirectCalls: []reusableworkflow.DirectCall{
		{CallerWorkflow: callerFile, CallerJobID: "call", Status: reusableworkflow.StatusTargetMissing},
	}}})

	prodID := credentialIDByLabel(built, "PROD_TOKEN")
	if edges := forwardingEdgesFrom(built, prodID); len(edges) != 0 {
		t.Fatalf("missing target must not forward: %#v", edges)
	}
}

func TestForwardTargetWithoutWorkflowCallNoForwarding(t *testing.T) {
	caller := domain.Workflow{Name: callerFile, File: callerFile, Evidence: testEvidence(callerFile, 1, "workflow"), Jobs: []domain.WorkflowJob{
		callerJobWithSecrets(callerFile, "call", "./.github/workflows/callee.yml", secretBinding("deployment_token", callerFile, 3, testReference("PROD_TOKEN", callerFile, 3))),
	}}
	// Target exists but declares no workflow_call contract at all (WorkflowCall == nil).
	callee := domain.Workflow{Name: calleeFile, File: calleeFile, Evidence: testEvidence(calleeFile, 1, "workflow"), Jobs: []domain.WorkflowJob{calleeUsageJob(calleeFile, "use", "deployment_token")}}
	parsed := domain.ParsedRepository{Workflows: []domain.Workflow{caller, callee}}
	// Status forced resolved_local directly (bypassing the real resolver,
	// which would never mark this resolved_local) to prove the builder's own
	// defensive nil-contract check independently.
	built := BuildWithOptions(parsed, BuildOptions{ReusableWorkflows: resolvedLocalResult([3]string{callerFile, "call", calleeFile})})

	prodID := credentialIDByLabel(built, "PROD_TOKEN")
	if edges := forwardingEdgesFrom(built, prodID); len(edges) != 0 {
		t.Fatalf("target without a workflow_call contract must not forward: %#v", edges)
	}
}

func TestForwardCycleDoesNotLoop(t *testing.T) {
	file := ".github/workflows/self.yml"
	job := callerJobWithSecrets(file, "call", "./"+file, secretBinding("self_alias", file, 3, testReference("SELF_TOKEN", file, 3)))
	job.References = []domain.Reference{testReference("self_alias", file, 5)}
	workflow := domain.Workflow{
		Name: file, File: file, Evidence: testEvidence(file, 1, "workflow"),
		Triggers:     []domain.WorkflowTrigger{{Name: "push", Evidence: testEvidence(file, 1, "on")}, {Name: "workflow_call", Evidence: testEvidence(file, 1, "on")}},
		WorkflowCall: &domain.ReusableWorkflowContract{Secrets: []domain.ReusableWorkflowSecretDefinition{{Name: "self_alias", Required: true, Evidence: testEvidence(file, 2, "on.workflow_call.secrets.self_alias")}}},
		Jobs:         []domain.WorkflowJob{job},
		References:   []domain.Reference{testReference("self_alias", file, 5)},
	}
	parsed := domain.ParsedRepository{Workflows: []domain.Workflow{workflow}}
	// propagateReusableWorkflowSecrets is a single flat pass with no
	// recursion, so a self-referential call cannot cause infinite
	// propagation; this is a direct, synchronous assertion of that.
	built := BuildWithOptions(parsed, BuildOptions{ReusableWorkflows: resolvedLocalResult([3]string{file, "call", file})})

	seen := make(map[string]bool, len(built.Graph.Edges))
	for _, e := range built.Graph.Edges {
		if seen[e.ID] {
			t.Fatalf("duplicate edge ID from self-cycle: %q", e.ID)
		}
		seen[e.ID] = true
	}
	selfID := credentialIDByLabel(built, "SELF_TOKEN")
	aliasID := credentialIDByLabel(built, "self_alias")
	if forwardingEdge(built, selfID, aliasID) == nil {
		t.Fatal("expected exactly one forwarding edge from the self-cycle")
	}
}

func TestForwardDepthChainDoesNotCrash(t *testing.T) {
	const hops = 11
	built, _, _ := buildForwardingChain(hops)

	forwardingCount := 0
	for _, e := range built.Graph.Edges {
		if e.Type == domain.EdgeExplicitlyForwardedTo {
			forwardingCount++
		}
	}
	if forwardingCount != hops-1 {
		t.Fatalf("expected %d forwarding edges across the chain, got %d", hops-1, forwardingCount)
	}
}

// buildForwardingChain builds a linear chain of `hops` workflows, each
// forwarding the previous hop's credential onward under a fresh alias, and
// returns the built graph plus the root source credential ID and the final
// hop's alias credential ID. The builder itself never suppresses a hop
// regardless of chain length; only traversal enforces the reusable-workflow
// depth cap, per hop, per path.
func buildForwardingChain(hops int) (built BuildResult, rootID, lastAliasID string) {
	var workflows []domain.Workflow
	var calls []reusableworkflow.DirectCall
	for i := 1; i <= hops; i++ {
		file := chainFileName(i)
		var jobs []domain.WorkflowJob
		var refs []domain.Reference
		var contract *domain.ReusableWorkflowContract
		triggers := []domain.WorkflowTrigger{{Name: "push", Evidence: testEvidence(file, 1, "on")}}
		// incomingAlias is the name under which this hop already holds the
		// value flowing down the chain: the true root secret at i==1, or the
		// alias it received from hop i-1 for every hop after that.
		incomingAlias := "SOURCE_1"
		if i > 1 {
			triggers = []domain.WorkflowTrigger{{Name: "workflow_call", Evidence: testEvidence(file, 1, "on")}}
			incomingAlias = "alias_" + strconv.Itoa(i-1)
			contract = &domain.ReusableWorkflowContract{Secrets: []domain.ReusableWorkflowSecretDefinition{{Name: incomingAlias, Required: true, Evidence: testEvidence(file, 2, "on.workflow_call.secrets."+incomingAlias)}}}
			usage := calleeUsageJob(file, "use", incomingAlias)
			jobs = append(jobs, usage)
			refs = append(refs, usage.References...)
		}
		if i < hops {
			outgoingAlias := "alias_" + strconv.Itoa(i)
			job := callerJobWithSecrets(file, "call", "./"+chainFileName(i+1), secretBinding(outgoingAlias, file, 3, testReference(incomingAlias, file, 3)))
			jobs = append(jobs, job)
			calls = append(calls, reusableworkflow.DirectCall{CallerWorkflow: file, CallerJobID: "call", TargetWorkflow: chainFileName(i + 1), Status: reusableworkflow.StatusResolvedLocal})
		}
		workflows = append(workflows, domain.Workflow{Name: file, File: file, Evidence: testEvidence(file, 1, "workflow"), Triggers: triggers, WorkflowCall: contract, Jobs: jobs, References: refs})
	}
	parsed := domain.ParsedRepository{Workflows: workflows}
	built = BuildWithOptions(parsed, BuildOptions{ReusableWorkflows: reusableworkflow.Result{DirectCalls: calls}})
	rootID = credentialIDByLabel(built, "SOURCE_1")
	lastAliasID = credentialIDByLabel(built, "alias_"+strconv.Itoa(hops-1))
	return built, rootID, lastAliasID
}

func chainFileName(i int) string {
	return ".github/workflows/chain-" + strconv.Itoa(i) + ".yml"
}

func TestForwardDeterministicOrdering(t *testing.T) {
	caller := domain.Workflow{Name: callerFile, File: callerFile, Evidence: testEvidence(callerFile, 1, "workflow"), Jobs: []domain.WorkflowJob{
		callerJobWithSecrets(callerFile, "call", "./.github/workflows/callee.yml",
			secretBinding("token_b", callerFile, 4, testReference("SECRET_B", callerFile, 4)),
			secretBinding("token_a", callerFile, 3, testReference("SECRET_A", callerFile, 3)),
		),
	}}
	callee := calleeWorkflow(calleeFile, []string{"token_a", "token_b"})
	parsed := domain.ParsedRepository{Workflows: []domain.Workflow{caller, callee}}
	options := BuildOptions{ReusableWorkflows: resolvedLocalResult([3]string{callerFile, "call", calleeFile})}

	first := BuildWithOptions(parsed, options)
	second := BuildWithOptions(parsed, options)
	if !reflect.DeepEqual(first, second) {
		t.Fatal("repeated build with secret forwarding is not deterministic")
	}
	firstJSON, _ := json.Marshal(first)
	secondJSON, _ := json.Marshal(second)
	if string(firstJSON) != string(secondJSON) {
		t.Fatal("repeated build serialization differs")
	}
	for i := 1; i < len(first.Graph.Edges); i++ {
		if first.Graph.Edges[i-1].ID > first.Graph.Edges[i].ID {
			t.Fatal("edges are not sorted")
		}
	}
}

func TestForwardStructuralCallAloneCreatesNoSecretExposure(t *testing.T) {
	caller := domain.Workflow{Name: callerFile, File: callerFile, Evidence: testEvidence(callerFile, 1, "workflow"), Jobs: []domain.WorkflowJob{
		reusableJob("call", "./.github/workflows/callee.yml"),
	}}
	callee := calleeWorkflow(calleeFile, []string{"deployment_token"})
	parsed := domain.ParsedRepository{Workflows: []domain.Workflow{caller, callee}}
	built := BuildWithOptions(parsed, BuildOptions{ReusableWorkflows: resolvedLocalResult([3]string{callerFile, "call", calleeFile})})

	for _, e := range built.Graph.Edges {
		if e.Type == domain.EdgeExplicitlyForwardedTo && e.EvidenceKind == domain.EvidenceConfirmedDataFlow {
			t.Fatalf("a structural call with no secrets: mapping must not create any forwarding edge: %#v", e)
		}
	}
}

func TestForwardOnlyForwardedSecretIsReachableUnrelatedCredentialStaysUnreachable(t *testing.T) {
	caller := domain.Workflow{Name: callerFile, File: callerFile, Evidence: testEvidence(callerFile, 1, "workflow"), Jobs: []domain.WorkflowJob{
		callerJobWithSecrets(callerFile, "call", "./.github/workflows/callee.yml", secretBinding("deployment_token", callerFile, 3, testReference("PROD_TOKEN", callerFile, 3))),
		{ID: "unrelated", Evidence: testEvidence(callerFile, 6, "jobs.unrelated"), References: []domain.Reference{testReference("OTHER_TOKEN", callerFile, 7)}},
	}}
	callee := calleeWorkflow(calleeFile, []string{"deployment_token"})
	parsed := domain.ParsedRepository{Workflows: []domain.Workflow{caller, callee}}
	built := BuildWithOptions(parsed, BuildOptions{ReusableWorkflows: resolvedLocalResult([3]string{callerFile, "call", calleeFile})})

	aliasID := credentialIDByLabel(built, "deployment_token")
	otherID := credentialIDByLabel(built, "OTHER_TOKEN")
	prodID := credentialIDByLabel(built, "PROD_TOKEN")
	if aliasID == "" || otherID == "" || prodID == "" {
		t.Fatalf("missing credentials: alias=%q other=%q prod=%q", aliasID, otherID, prodID)
	}

	prodPaths := Traverse(built.Graph, prodID, 12)
	reachedAlias := false
	for _, p := range prodPaths {
		for _, n := range p.Nodes {
			if n.ID == aliasID {
				reachedAlias = true
			}
		}
	}
	if !reachedAlias {
		t.Fatal("PROD_TOKEN must reach the alias it was explicitly forwarded to")
	}

	otherPaths := Traverse(built.Graph, otherID, 12)
	for _, p := range otherPaths {
		for _, n := range p.Nodes {
			if n.ID == aliasID {
				t.Fatalf("unrelated OTHER_TOKEN must not reach the callee's forwarded alias: %+v", p)
			}
		}
	}
}

func reachesNode(paths []domain.EvidencePath, nodeID string) bool {
	for _, p := range paths {
		for _, n := range p.Nodes {
			if n.ID == nodeID {
				return true
			}
		}
	}
	return false
}

func TestTraversalOneReusableWorkflowHopIsReachable(t *testing.T) {
	built, rootID, lastAliasID := buildForwardingChain(2)
	if !reachesNode(Traverse(built.Graph, rootID, 20), lastAliasID) {
		t.Fatal("a single reusable-workflow forwarding hop must be reachable")
	}
}

func TestTraversalExactlyNineHopsIsReachable(t *testing.T) {
	// 10 workflows in the chain => 9 forwarding transitions, exactly at the
	// resolver's maximum chain size; must still be fully reachable.
	built, rootID, lastAliasID := buildForwardingChain(10)
	if !reachesNode(Traverse(built.Graph, rootID, 20), lastAliasID) {
		t.Fatal("exactly 9 reusable-workflow forwarding hops must remain reachable")
	}
}

func TestTraversalTenthHopIsNotReachable(t *testing.T) {
	// 11 workflows => 10 forwarding transitions, one past the maximum; the
	// 9-hop midpoint stays reachable but the 10th hop's destination must not.
	built, rootID, lastAliasID := buildForwardingChain(11)
	ninthAliasID := credentialIDByLabel(built, "alias_9")
	paths := Traverse(built.Graph, rootID, 20)
	if !reachesNode(paths, ninthAliasID) {
		t.Fatal("the ninth reusable-workflow hop must remain reachable")
	}
	if reachesNode(paths, lastAliasID) {
		t.Fatal("the tenth reusable-workflow forwarding transition must not be traversed")
	}
}

func TestTraversalSameEdgeShallowInOneChainOverDepthInAnother(t *testing.T) {
	built, rootID, lastAliasID := buildForwardingChain(11)
	ninthAliasID := credentialIDByLabel(built, "alias_9")
	if rootID == "" || lastAliasID == "" || ninthAliasID == "" {
		t.Fatalf("missing chain credentials: root=%q ninth=%q last=%q", rootID, ninthAliasID, lastAliasID)
	}

	// From the far root, the alias_9 -> alias_10 edge is the 10th transition
	// and must be blocked.
	if reachesNode(Traverse(built.Graph, rootID, 20), lastAliasID) {
		t.Fatal("alias_9 -> alias_10 must be blocked when reached as the 10th hop from the far root")
	}
	// The identical edge, traversed starting from alias_9 directly (hop
	// count resets to zero for any new Traverse call), is only its 1st hop
	// and must be reachable. Same edge, not deleted, not globally
	// suppressed — only refused on the over-depth path.
	if !reachesNode(Traverse(built.Graph, ninthAliasID, 20), lastAliasID) {
		t.Fatal("alias_9 -> alias_10 must remain reachable when traversal starts closer, at hop 1")
	}
}

func TestTraversalReusableWorkflowHopCycleTerminates(t *testing.T) {
	credA := domain.Node{ID: "cred-a", Type: domain.NodeCredential}
	credB := domain.Node{ID: "cred-b", Type: domain.NodeCredential}
	credC := domain.Node{ID: "cred-c", Type: domain.NodeCredential}
	hop := func(id, from, to string) domain.Edge {
		return domain.Edge{ID: id, From: from, To: to, Type: domain.EdgeExplicitlyForwardedTo, EvidenceKind: domain.EvidenceConfirmedDataFlow, Confidence: domain.ConfidenceConfirmed, Metadata: map[string]string{reusableWorkflowHopMetadataKey: reusableWorkflowHopMetadataValue}}
	}
	g := domain.Graph{
		Nodes: []domain.Node{credA, credB, credC},
		Edges: []domain.Edge{hop("a-b", "cred-a", "cred-b"), hop("b-c", "cred-b", "cred-c"), hop("c-a", "cred-c", "cred-a")},
	}
	paths := Traverse(g, "cred-a", 20)
	for _, p := range paths {
		seen := make(map[string]bool, len(p.Nodes))
		for _, n := range p.Nodes {
			if seen[n.ID] {
				t.Fatalf("cycle revisited a node within one path: %+v", p)
			}
			seen[n.ID] = true
		}
	}
	if len(paths) == 0 {
		t.Fatal("expected at least the a->b->c path from the cycle")
	}
}

func TestTraversalOrdinaryForwardedToEdgesUnaffectedByHopCap(t *testing.T) {
	const length = 12 // deliberately more than MaxReusableWorkflowHops
	nodes := []domain.Node{{ID: "n0", Type: domain.NodeCredential}}
	var edges []domain.Edge
	for i := 1; i <= length; i++ {
		id := "n" + strconv.Itoa(i)
		nodes = append(nodes, domain.Node{ID: id, Type: domain.NodeCredential})
		edges = append(edges, domain.Edge{
			ID: "e" + strconv.Itoa(i), From: "n" + strconv.Itoa(i-1), To: id,
			Type: domain.EdgeExplicitlyForwardedTo, EvidenceKind: domain.EvidenceConfirmedDataFlow, Confidence: domain.ConfidenceConfirmed,
			// No reusable_workflow_hop metadata: an ordinary forwarding edge.
		})
	}
	g := domain.Graph{Nodes: nodes, Edges: edges}
	if !reachesNode(Traverse(g, "n0", 20), "n"+strconv.Itoa(length)) {
		t.Fatal("ordinary (non-reusable-workflow) ExplicitlyForwardedTo edges must not be capped by the reusable-workflow hop limit")
	}
}

func TestTraversalTwoRunsAreDeterministic(t *testing.T) {
	built, rootID, _ := buildForwardingChain(11)
	first := Traverse(built.Graph, rootID, 20)
	second := Traverse(built.Graph, rootID, 20)
	firstJSON, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	secondJSON, err := json.Marshal(second)
	if err != nil {
		t.Fatal(err)
	}
	if string(firstJSON) != string(secondJSON) {
		t.Fatal("two Traverse runs over the same graph produced different output")
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatal("two Traverse runs over the same graph are not deeply equal")
	}
}
