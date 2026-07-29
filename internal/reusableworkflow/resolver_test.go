package reusableworkflow

import (
	"encoding/json"
	"reflect"
	"sort"
	"testing"

	"github.com/Bavlik/CredScope/internal/domain"
)

func wf(file string, triggers []string, jobs ...domain.WorkflowJob) domain.Workflow {
	var trig []domain.WorkflowTrigger
	for _, t := range triggers {
		trig = append(trig, domain.WorkflowTrigger{Name: t})
	}
	return domain.Workflow{Name: file, File: file, Triggers: trig, Jobs: jobs}
}

func callerJob(id, uses string) domain.WorkflowJob {
	return domain.WorkflowJob{
		ID: id,
		ReusableWorkflow: &domain.ActionReference{
			Reference: uses,
			Evidence:  domain.Evidence{Location: domain.Location{Path: "caller.yml", Line: 1}},
		},
	}
}

func plainJob(id string) domain.WorkflowJob {
	return domain.WorkflowJob{ID: id}
}

func findCall(t *testing.T, result Result, callerWorkflow, jobID string) DirectCall {
	t.Helper()
	for _, c := range result.DirectCalls {
		if c.CallerWorkflow == callerWorkflow && c.CallerJobID == jobID {
			return c
		}
	}
	t.Fatalf("call for %s/%s not found in %#v", callerWorkflow, jobID, result.DirectCalls)
	return DirectCall{}
}

func TestResolveDirectLocalCall(t *testing.T) {
	workflows := []domain.Workflow{
		wf(".github/workflows/caller.yml", []string{"push"}, callerJob("call", "./.github/workflows/target.yml")),
		wf(".github/workflows/target.yml", []string{"workflow_call"}, plainJob("build")),
	}
	call := findCall(t, Resolve(workflows), ".github/workflows/caller.yml", "call")
	if call.Status != StatusResolvedLocal || call.TargetWorkflow != ".github/workflows/target.yml" {
		t.Fatalf("call = %#v", call)
	}
}

func TestResolveMissingTarget(t *testing.T) {
	workflows := []domain.Workflow{
		wf(".github/workflows/caller.yml", []string{"push"}, callerJob("call", "./.github/workflows/missing.yml")),
	}
	call := findCall(t, Resolve(workflows), ".github/workflows/caller.yml", "call")
	if call.Status != StatusTargetMissing {
		t.Fatalf("status = %v", call.Status)
	}
}

func TestResolveTargetWithoutWorkflowCall(t *testing.T) {
	workflows := []domain.Workflow{
		wf(".github/workflows/caller.yml", []string{"push"}, callerJob("call", "./.github/workflows/target.yml")),
		wf(".github/workflows/target.yml", []string{"push"}, plainJob("build")),
	}
	call := findCall(t, Resolve(workflows), ".github/workflows/caller.yml", "call")
	if call.Status != StatusTargetNotReusable {
		t.Fatalf("status = %v", call.Status)
	}
}

func TestResolveExternalCallRemainsOpaque(t *testing.T) {
	workflows := []domain.Workflow{
		wf(".github/workflows/caller.yml", []string{"push"}, callerJob("call", "octo/repo/.github/workflows/deploy.yml@v1")),
	}
	call := findCall(t, Resolve(workflows), ".github/workflows/caller.yml", "call")
	if call.Status != StatusOpaqueExternal || call.NormalizedTarget != "" {
		t.Fatalf("call = %#v", call)
	}
}

func TestResolveExpressionInUses(t *testing.T) {
	workflows := []domain.Workflow{
		wf(".github/workflows/caller.yml", []string{"push"}, callerJob("call", "${{ github.repository }}/.github/workflows/deploy.yml@main")),
	}
	call := findCall(t, Resolve(workflows), ".github/workflows/caller.yml", "call")
	if call.Status != StatusUnsupportedExpression {
		t.Fatalf("status = %v", call.Status)
	}
}

func TestResolvePathTraversalRejected(t *testing.T) {
	workflows := []domain.Workflow{
		wf(".github/workflows/caller.yml", []string{"push"}, callerJob("call", "../secret.yml")),
	}
	call := findCall(t, Resolve(workflows), ".github/workflows/caller.yml", "call")
	if call.Status != StatusRejectedPath {
		t.Fatalf("status = %v", call.Status)
	}
}

func TestResolveAbsoluteUnixPathRejected(t *testing.T) {
	workflows := []domain.Workflow{
		wf(".github/workflows/caller.yml", []string{"push"}, callerJob("call", "/etc/workflows/target.yml")),
	}
	call := findCall(t, Resolve(workflows), ".github/workflows/caller.yml", "call")
	if call.Status != StatusRejectedPath {
		t.Fatalf("status = %v", call.Status)
	}
}

func TestResolveWindowsDrivePathRejected(t *testing.T) {
	workflows := []domain.Workflow{
		wf(".github/workflows/caller.yml", []string{"push"}, callerJob("call", `C:\workflows\target.yml`)),
	}
	call := findCall(t, Resolve(workflows), ".github/workflows/caller.yml", "call")
	if call.Status != StatusRejectedPath {
		t.Fatalf("status = %v", call.Status)
	}
}

func TestResolveBackslashTraversalRejected(t *testing.T) {
	workflows := []domain.Workflow{
		wf(".github/workflows/caller.yml", []string{"push"}, callerJob("call", `./.github/workflows\target.yml`)),
	}
	call := findCall(t, Resolve(workflows), ".github/workflows/caller.yml", "call")
	if call.Status != StatusRejectedPath {
		t.Fatalf("status = %v", call.Status)
	}
}

func TestResolveNestedWorkflowDirectoryRejected(t *testing.T) {
	workflows := []domain.Workflow{
		wf(".github/workflows/caller.yml", []string{"push"}, callerJob("call", "./.github/workflows/sub/target.yml")),
	}
	call := findCall(t, Resolve(workflows), ".github/workflows/caller.yml", "call")
	if call.Status != StatusRejectedPath {
		t.Fatalf("status = %v", call.Status)
	}
}

func TestResolveWrongExtensionRejected(t *testing.T) {
	workflows := []domain.Workflow{
		wf(".github/workflows/caller.yml", []string{"push"}, callerJob("call", "./.github/workflows/target.txt")),
	}
	call := findCall(t, Resolve(workflows), ".github/workflows/caller.yml", "call")
	if call.Status != StatusRejectedPath {
		t.Fatalf("status = %v", call.Status)
	}
}

func TestResolveOutsideWorkflowsDirectoryRejected(t *testing.T) {
	workflows := []domain.Workflow{
		wf(".github/workflows/caller.yml", []string{"push"}, callerJob("call", "./scripts/build.yml")),
	}
	call := findCall(t, Resolve(workflows), ".github/workflows/caller.yml", "call")
	if call.Status != StatusRejectedPath {
		t.Fatalf("status = %v", call.Status)
	}
}

func TestResolveQueryFragmentSuffixRejected(t *testing.T) {
	workflows := []domain.Workflow{
		wf(".github/workflows/caller.yml", []string{"push"}, callerJob("call", "./.github/workflows/target.yml?raw=1")),
	}
	call := findCall(t, Resolve(workflows), ".github/workflows/caller.yml", "call")
	if call.Status != StatusRejectedPath {
		t.Fatalf("status = %v", call.Status)
	}
}

func TestResolveExactCaseSensitiveMatching(t *testing.T) {
	workflows := []domain.Workflow{
		wf(".github/workflows/caller.yml", []string{"push"}, callerJob("call", "./.github/workflows/Target.yml")),
		wf(".github/workflows/target.yml", []string{"workflow_call"}, plainJob("build")),
	}
	call := findCall(t, Resolve(workflows), ".github/workflows/caller.yml", "call")
	if call.Status != StatusTargetMissing {
		t.Fatalf("case-sensitive matching failed: status = %v", call.Status)
	}
}

func TestResolveDuplicateCalls(t *testing.T) {
	workflows := []domain.Workflow{
		wf(".github/workflows/caller.yml", []string{"push"},
			callerJob("call-a", "./.github/workflows/target.yml"),
			callerJob("call-b", "./.github/workflows/target.yml"),
		),
		wf(".github/workflows/target.yml", []string{"workflow_call"}, plainJob("build")),
	}
	result := Resolve(workflows)
	a := findCall(t, result, ".github/workflows/caller.yml", "call-a")
	b := findCall(t, result, ".github/workflows/caller.yml", "call-b")
	if a.Status != StatusResolvedLocal || b.Status != StatusResolvedLocal {
		t.Fatalf("duplicate calls not both resolved: %#v %#v", a, b)
	}
}

func TestResolveMultipleCallersToOneTarget(t *testing.T) {
	workflows := []domain.Workflow{
		wf(".github/workflows/caller1.yml", []string{"push"}, callerJob("call", "./.github/workflows/target.yml")),
		wf(".github/workflows/caller2.yml", []string{"push"}, callerJob("call", "./.github/workflows/target.yml")),
		wf(".github/workflows/target.yml", []string{"workflow_call"}, plainJob("build")),
	}
	result := Resolve(workflows)
	c1 := findCall(t, result, ".github/workflows/caller1.yml", "call")
	c2 := findCall(t, result, ".github/workflows/caller2.yml", "call")
	if c1.Status != StatusResolvedLocal || c2.Status != StatusResolvedLocal {
		t.Fatalf("multi-caller resolution = %#v %#v", c1, c2)
	}
}

func TestResolveDiamondIsNotACycle(t *testing.T) {
	workflows := []domain.Workflow{
		wf(".github/workflows/a.yml", []string{"push"},
			callerJob("to-b", "./.github/workflows/b.yml"),
			callerJob("to-c", "./.github/workflows/c.yml"),
		),
		wf(".github/workflows/b.yml", []string{"workflow_call"}, callerJob("to-d", "./.github/workflows/d.yml")),
		wf(".github/workflows/c.yml", []string{"workflow_call"}, callerJob("to-d", "./.github/workflows/d.yml")),
		wf(".github/workflows/d.yml", []string{"workflow_call"}, plainJob("build")),
	}
	result := Resolve(workflows)
	for _, diag := range result.Chains {
		if diag.Kind == ChainCycle {
			t.Fatalf("diamond graph must not report a cycle: %#v", result.Chains)
		}
	}
}

func TestResolveSelfCycle(t *testing.T) {
	workflows := []domain.Workflow{
		wf(".github/workflows/a.yml", []string{"push", "workflow_call"}, callerJob("call", "./.github/workflows/a.yml")),
	}
	result := Resolve(workflows)
	if !hasCycle(result.Chains, []string{".github/workflows/a.yml"}) {
		t.Fatalf("self-cycle not detected: %#v", result.Chains)
	}
}

func TestResolveTwoWorkflowCycle(t *testing.T) {
	workflows := []domain.Workflow{
		wf(".github/workflows/a.yml", []string{"push", "workflow_call"}, callerJob("call", "./.github/workflows/b.yml")),
		wf(".github/workflows/b.yml", []string{"workflow_call"}, callerJob("call", "./.github/workflows/a.yml")),
	}
	result := Resolve(workflows)
	if !hasCycle(result.Chains, []string{".github/workflows/a.yml", ".github/workflows/b.yml"}) {
		t.Fatalf("two-workflow cycle not detected: %#v", result.Chains)
	}
	count := 0
	for _, diag := range result.Chains {
		if diag.Kind == ChainCycle {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("cycle reported %d times, want exactly once: %#v", count, result.Chains)
	}
}

func TestResolveThreeWorkflowCycle(t *testing.T) {
	workflows := []domain.Workflow{
		wf(".github/workflows/a.yml", []string{"push", "workflow_call"}, callerJob("call", "./.github/workflows/b.yml")),
		wf(".github/workflows/b.yml", []string{"workflow_call"}, callerJob("call", "./.github/workflows/c.yml")),
		wf(".github/workflows/c.yml", []string{"workflow_call"}, callerJob("call", "./.github/workflows/a.yml")),
	}
	result := Resolve(workflows)
	if !hasCycle(result.Chains, []string{".github/workflows/a.yml", ".github/workflows/b.yml", ".github/workflows/c.yml"}) {
		t.Fatalf("three-workflow cycle not detected: %#v", result.Chains)
	}
}

func linearChain(n int) []domain.Workflow {
	workflows := make([]domain.Workflow, 0, n)
	for i := 1; i <= n; i++ {
		file := chainFile(i)
		triggers := []string{"push"}
		if i > 1 {
			triggers = []string{"workflow_call"}
		}
		var jobs []domain.WorkflowJob
		if i < n {
			jobs = []domain.WorkflowJob{callerJob("call", "./"+chainFile(i+1))}
		} else {
			jobs = []domain.WorkflowJob{plainJob("build")}
		}
		workflows = append(workflows, wf(file, triggers, jobs...))
	}
	return workflows
}

func chainFile(i int) string {
	return ".github/workflows/w" + itoa(i) + ".yml"
}

func itoa(i int) string {
	if i < 10 {
		return string(rune('0' + i))
	}
	return string(rune('0'+i/10)) + string(rune('0'+i%10))
}

func TestResolveExactlyTenWorkflowsAccepted(t *testing.T) {
	result := Resolve(linearChain(10))
	for _, diag := range result.Chains {
		if diag.Kind == ChainDepthExceeded {
			t.Fatalf("10-workflow chain must not exceed depth: %#v", result.Chains)
		}
	}
}

func TestResolveElevenWorkflowsExceedsDepth(t *testing.T) {
	result := Resolve(linearChain(11))
	found := false
	for _, diag := range result.Chains {
		if diag.Kind == ChainDepthExceeded && diag.Depth == 11 {
			found = true
			if diag.Path[0] != ".github/workflows/w1.yml" {
				t.Fatalf("depth diagnostic path should start at root: %#v", diag)
			}
		}
	}
	if !found {
		t.Fatalf("expected depth-exceeded diagnostic for 11-workflow chain: %#v", result.Chains)
	}
	last := findCall(t, result, ".github/workflows/w10.yml", "call")
	if last.Status != StatusResolvedLocal {
		t.Fatalf("depth-exceeded chain must not change direct call status: %#v", last)
	}
}

func TestResolveSameEdgeShallowInOneChainAndOverDepthInAnother(t *testing.T) {
	// Root at w2 reaches w11 in exactly 10 hops (shallow, accepted).
	// Root at w1 reaches the same w10->w11 edge at depth 11 (exceeded).
	result := Resolve(linearChain(11))
	sawExceeded, sawAccepted := false, false
	for _, diag := range result.Chains {
		if diag.Kind != ChainDepthExceeded {
			continue
		}
		if diag.Path[0] == ".github/workflows/w1.yml" {
			sawExceeded = true
		}
	}
	// A chain rooted at w2 spans w2..w11: 10 workflows, exactly at the limit.
	twoElevenWorkflows := linearChain(11)[1:]
	subResult := Resolve(twoElevenWorkflows)
	sawAccepted = true
	for _, diag := range subResult.Chains {
		if diag.Kind == ChainDepthExceeded {
			sawAccepted = false
		}
	}
	if !sawExceeded {
		t.Fatalf("expected depth-exceeded diagnostic rooted at w1: %#v", result.Chains)
	}
	if !sawAccepted {
		t.Fatalf("expected no depth-exceeded diagnostic for the w2-rooted sub-chain: %#v", subResult.Chains)
	}
}

func TestResolveStableDeterministicOrdering(t *testing.T) {
	workflows := []domain.Workflow{
		wf(".github/workflows/b-caller.yml", []string{"push"}, callerJob("call", "./.github/workflows/target.yml")),
		wf(".github/workflows/a-caller.yml", []string{"push"}, callerJob("call", "./.github/workflows/target.yml")),
		wf(".github/workflows/target.yml", []string{"workflow_call"}, plainJob("build")),
	}
	first := Resolve(workflows)
	if first.DirectCalls[0].CallerWorkflow != ".github/workflows/a-caller.yml" {
		t.Fatalf("direct calls not sorted deterministically: %#v", first.DirectCalls)
	}
	if !sort.SliceIsSorted(first.DirectCalls, func(i, j int) bool { return lessCall(first.DirectCalls[i], first.DirectCalls[j]) }) {
		t.Fatal("direct calls not stably sorted")
	}
}

func TestResolveTwoInProcessCallsAreByteIdentical(t *testing.T) {
	workflows := linearChain(11)
	first := Resolve(workflows)
	second := Resolve(workflows)
	firstJSON, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	secondJSON, err := json.Marshal(second)
	if err != nil {
		t.Fatal(err)
	}
	if string(firstJSON) != string(secondJSON) {
		t.Fatal("two in-process Resolve calls produced different output")
	}
}

func TestResolveDoesNotMutateInput(t *testing.T) {
	workflows := linearChain(11)
	workflows = append(workflows, wf(".github/workflows/external.yml", []string{"push"}, callerJob("call", "octo/repo/.github/workflows/deploy.yml@v1")))
	before, err := json.Marshal(workflows)
	if err != nil {
		t.Fatal(err)
	}
	beforeCopy := make([]domain.Workflow, len(workflows))
	copy(beforeCopy, workflows)

	_ = Resolve(workflows)

	after, err := json.Marshal(workflows)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("Resolve mutated its input workflows (JSON diverged)")
	}
	if !reflect.DeepEqual(beforeCopy, workflows) {
		t.Fatal("Resolve mutated its input workflows (DeepEqual diverged)")
	}
}

func hasCycle(chains []ChainDiagnostic, canonical []string) bool {
	for _, diag := range chains {
		if diag.Kind != ChainCycle {
			continue
		}
		if reflect.DeepEqual(diag.Path, canonicalizeCycle(canonical)) {
			return true
		}
	}
	return false
}
