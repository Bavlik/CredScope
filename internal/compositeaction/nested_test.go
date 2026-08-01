package compositeaction

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/Bavlik/CredScope/internal/domain"
	"github.com/Bavlik/CredScope/internal/parsers/githubactions"
)

func resolveRepo(t *testing.T, root string, workflows []domain.Workflow) domain.CompositeActionResolution {
	t.Helper()
	finder := newFinder(t, root)
	result, err := Resolve(context.Background(), finder, githubactions.New(), workflows)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func nestedUsesYAML(usesTarget string) string {
	return "name: Nested\ndescription: test\nruns:\n  using: composite\n  steps:\n    - uses: " + usesTarget + "\n"
}

func nestedTwoUsesYAML(a, b string) string {
	return "name: Nested\ndescription: test\nruns:\n  using: composite\n  steps:\n    - uses: " + a + "\n    - uses: " + b + "\n"
}

func findNestedCall(t *testing.T, result domain.CompositeActionResolution, parentDir string, stepIndex int) domain.NestedCompositeActionCall {
	t.Helper()
	for _, c := range result.NestedCalls {
		if c.ParentCanonicalDirectory == parentDir && c.ParentActionStepIndex == stepIndex {
			return c
		}
	}
	t.Fatalf("nested call for parent %q step %d not found in %#v", parentDir, stepIndex, result.NestedCalls)
	return domain.NestedCompositeActionCall{}
}

func findAction(t *testing.T, result domain.CompositeActionResolution, directory string) domain.ActionMetadata {
	t.Helper()
	for _, a := range result.Actions {
		if a.Directory == directory {
			return a
		}
	}
	t.Fatalf("action %q not found in %#v", directory, result.Actions)
	return domain.ActionMetadata{}
}

func hasAction(result domain.CompositeActionResolution, directory string) bool {
	for _, a := range result.Actions {
		if a.Directory == directory {
			return true
		}
	}
	return false
}

func countDiagnostics(result domain.CompositeActionResolution, kind domain.NestedCompositeActionDiagnosticKind) int {
	count := 0
	for _, d := range result.Diagnostics {
		if d.Kind == kind {
			count++
		}
	}
	return count
}

// 1. one local nested composite action resolves.
func TestNestedOneChildResolves(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, ".github/actions/a/action.yml", nestedUsesYAML("./.github/actions/b"))
	writeFile(t, root, ".github/actions/b/action.yml", compositeYAML)
	workflows := []domain.Workflow{wf("caller.yml", job("build", actionStep("./.github/actions/a")))}

	result := resolveRepo(t, root, workflows)
	if !hasAction(result, ".github/actions/a") || !hasAction(result, ".github/actions/b") {
		t.Fatalf("expected both A and B canonical actions, got %#v", result.Actions)
	}
	nested := findNestedCall(t, result, ".github/actions/a", 0)
	if nested.Status != domain.CompositeActionResolvedLocalComposite || nested.CanonicalDirectory != ".github/actions/b" {
		t.Fatalf("unexpected nested call: %#v", nested)
	}
}

// 2. two different child actions resolve.
func TestNestedTwoDifferentChildrenResolve(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, ".github/actions/a/action.yml", nestedTwoUsesYAML("./.github/actions/b", "./.github/actions/c"))
	writeFile(t, root, ".github/actions/b/action.yml", compositeYAML)
	writeFile(t, root, ".github/actions/c/action.yml", compositeYAML)
	workflows := []domain.Workflow{wf("caller.yml", job("build", actionStep("./.github/actions/a")))}

	result := resolveRepo(t, root, workflows)
	if !hasAction(result, ".github/actions/b") || !hasAction(result, ".github/actions/c") {
		t.Fatalf("expected both children resolved, got %#v", result.Actions)
	}
	if findNestedCall(t, result, ".github/actions/a", 0).CanonicalDirectory != ".github/actions/b" {
		t.Fatal("step 0 should target B")
	}
	if findNestedCall(t, result, ".github/actions/a", 1).CanonicalDirectory != ".github/actions/c" {
		t.Fatal("step 1 should target C")
	}
}

// 3. same child referenced by two parent steps.
func TestNestedSameChildTwoParentSteps(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, ".github/actions/a/action.yml", nestedTwoUsesYAML("./.github/actions/b", "./.github/actions/b"))
	writeFile(t, root, ".github/actions/b/action.yml", compositeYAML)
	workflows := []domain.Workflow{wf("caller.yml", job("build", actionStep("./.github/actions/a")))}

	result := resolveRepo(t, root, workflows)
	count := 0
	for _, a := range result.Actions {
		if a.Directory == ".github/actions/b" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("B must appear exactly once in Actions despite two references, got %d", count)
	}
	if findNestedCall(t, result, ".github/actions/a", 0).CanonicalDirectory != ".github/actions/b" || findNestedCall(t, result, ".github/actions/a", 1).CanonicalDirectory != ".github/actions/b" {
		t.Fatal("both steps must resolve to B")
	}
}

// 4. same child referenced by two canonical parent actions.
func TestNestedSameChildTwoCanonicalParents(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, ".github/actions/a/action.yml", nestedUsesYAML("./.github/actions/shared"))
	writeFile(t, root, ".github/actions/c/action.yml", nestedUsesYAML("./.github/actions/shared"))
	writeFile(t, root, ".github/actions/shared/action.yml", compositeYAML)
	workflows := []domain.Workflow{wf("caller.yml", job("build",
		actionStepWithID("s0", "./.github/actions/a"),
		actionStepWithID("s1", "./.github/actions/c"),
	))}

	result := resolveRepo(t, root, workflows)
	count := 0
	for _, a := range result.Actions {
		if a.Directory == ".github/actions/shared" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("shared child must appear exactly once, got %d", count)
	}
	if findNestedCall(t, result, ".github/actions/a", 0).CanonicalDirectory != ".github/actions/shared" {
		t.Fatal("A must resolve to shared")
	}
	if findNestedCall(t, result, ".github/actions/c", 0).CanonicalDirectory != ".github/actions/shared" {
		t.Fatal("C must resolve to shared")
	}
}

// 5. diamond graph resolves without cycle.
func TestNestedDiamondNoCycle(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, ".github/actions/a/action.yml", nestedTwoUsesYAML("./.github/actions/b", "./.github/actions/c"))
	writeFile(t, root, ".github/actions/b/action.yml", nestedUsesYAML("./.github/actions/d"))
	writeFile(t, root, ".github/actions/c/action.yml", nestedUsesYAML("./.github/actions/d"))
	writeFile(t, root, ".github/actions/d/action.yml", compositeYAML)
	workflows := []domain.Workflow{wf("caller.yml", job("build", actionStep("./.github/actions/a")))}

	result := resolveRepo(t, root, workflows)
	if countDiagnostics(result, domain.NestedCompositeActionDiagnosticCycle) != 0 {
		t.Fatalf("diamond must not be classified as a cycle: %#v", result.Diagnostics)
	}
	count := 0
	for _, a := range result.Actions {
		if a.Directory == ".github/actions/d" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("D must be parsed exactly once despite two paths reaching it, got %d", count)
	}
}

// 6. direct cycle terminates.
func TestNestedDirectCycleTerminates(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, ".github/actions/a/action.yml", nestedUsesYAML("./.github/actions/a"))
	workflows := []domain.Workflow{wf("caller.yml", job("build", actionStep("./.github/actions/a")))}

	result := resolveRepo(t, root, workflows)
	if countDiagnostics(result, domain.NestedCompositeActionDiagnosticCycle) != 1 {
		t.Fatalf("expected exactly one cycle diagnostic, got %#v", result.Diagnostics)
	}
	if countDiagnostics(result, domain.NestedCompositeActionDiagnosticDepthExceeded) != 0 {
		t.Fatalf("a direct A->A cycle must never also emit a depth diagnostic: %#v", result.Diagnostics)
	}
	for _, d := range result.Diagnostics {
		if d.Kind == domain.NestedCompositeActionDiagnosticCycle {
			if len(d.Path) != 2 || d.Path[0] != ".github/actions/a" || d.Path[1] != ".github/actions/a" {
				t.Fatalf("expected closed self-cycle path [A, A], got %#v", d.Path)
			}
			if d.Limit != 0 {
				t.Fatalf("cycle diagnostic must set Limit == 0, got %d", d.Limit)
			}
		}
	}
}

// 7. indirect two-action cycle terminates.
func TestNestedIndirectTwoActionCycleTerminates(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, ".github/actions/a/action.yml", nestedUsesYAML("./.github/actions/b"))
	writeFile(t, root, ".github/actions/b/action.yml", nestedUsesYAML("./.github/actions/a"))
	workflows := []domain.Workflow{wf("caller.yml", job("build", actionStep("./.github/actions/a")))}

	result := resolveRepo(t, root, workflows)
	if countDiagnostics(result, domain.NestedCompositeActionDiagnosticCycle) != 1 {
		t.Fatalf("expected exactly one cycle diagnostic, got %#v", result.Diagnostics)
	}
	if countDiagnostics(result, domain.NestedCompositeActionDiagnosticDepthExceeded) != 0 {
		t.Fatalf("a two-action A->B->A cycle must never also emit a depth diagnostic: %#v", result.Diagnostics)
	}
	// Both A and B must still be resolved (metadata retained despite the
	// cycle) and both nested calls recorded.
	if !hasAction(result, ".github/actions/a") || !hasAction(result, ".github/actions/b") {
		t.Fatal("both A and B metadata must be retained despite the cycle")
	}
	if len(result.NestedCalls) != 2 {
		t.Fatalf("expected both A->B and B->A nested calls recorded, got %#v", result.NestedCalls)
	}
}

// 8. longer cycle terminates.
func TestNestedLongerCycleTerminates(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, ".github/actions/a/action.yml", nestedUsesYAML("./.github/actions/b"))
	writeFile(t, root, ".github/actions/b/action.yml", nestedUsesYAML("./.github/actions/c"))
	writeFile(t, root, ".github/actions/c/action.yml", nestedUsesYAML("./.github/actions/a"))
	workflows := []domain.Workflow{wf("caller.yml", job("build", actionStep("./.github/actions/a")))}

	result := resolveRepo(t, root, workflows)
	if countDiagnostics(result, domain.NestedCompositeActionDiagnosticCycle) != 1 {
		t.Fatalf("expected exactly one cycle diagnostic, got %#v", result.Diagnostics)
	}
	if countDiagnostics(result, domain.NestedCompositeActionDiagnosticDepthExceeded) != 0 {
		t.Fatalf("a longer A->B->C->A cycle must never also emit a depth diagnostic: %#v", result.Diagnostics)
	}
	for _, d := range result.Diagnostics {
		if d.Kind == domain.NestedCompositeActionDiagnosticCycle && len(d.Path) != 4 {
			t.Fatalf("expected a closed 3-node cycle path of length 4, got %#v", d.Path)
		}
	}
}

// cycle with a separate genuine 11-action acyclic branch: root has two
// children, one leading into a cycle and one leading down a genuine,
// acyclic 11-deep chain. Must produce exactly one cycle diagnostic and
// exactly one depth diagnostic, the depth diagnostic covering only the
// acyclic branch.
func TestNestedCycleWithSeparateAcyclicDeepBranch(t *testing.T) {
	root := t.TempDir()
	// root -> cyclic (cyclic -> cyclic, a direct self-cycle)
	writeFile(t, root, ".github/actions/root/action.yml", nestedTwoUsesYAML("./.github/actions/cyclic", "./.github/actions/deepchain0"))
	writeFile(t, root, ".github/actions/cyclic/action.yml", nestedUsesYAML("./.github/actions/cyclic"))
	// root -> deepchain0 -> ... -> deepchain10 (11 actions total on this
	// path: root itself plus deepchain0..deepchain9, attempting deepchain10
	// as the 11th).
	for i := 0; i < 10; i++ {
		dir := fmt.Sprintf(".github/actions/deepchain%d", i)
		next := fmt.Sprintf("./.github/actions/deepchain%d", i+1)
		writeFile(t, root, dir+"/action.yml", nestedUsesYAML(next))
	}
	writeFile(t, root, ".github/actions/deepchain10/action.yml", compositeYAML)
	workflows := []domain.Workflow{wf("caller.yml", job("build", actionStep("./.github/actions/root")))}

	result := resolveRepo(t, root, workflows)
	if countDiagnostics(result, domain.NestedCompositeActionDiagnosticCycle) != 1 {
		t.Fatalf("expected exactly one cycle diagnostic, got %#v", result.Diagnostics)
	}
	if countDiagnostics(result, domain.NestedCompositeActionDiagnosticDepthExceeded) != 1 {
		t.Fatalf("expected exactly one depth diagnostic for the separate acyclic branch, got %#v", result.Diagnostics)
	}
	for _, d := range result.Diagnostics {
		if d.Kind == domain.NestedCompositeActionDiagnosticDepthExceeded {
			for _, node := range d.Path {
				if node == ".github/actions/cyclic" {
					t.Fatalf("depth diagnostic must cover only the acyclic branch, got path %#v", d.Path)
				}
			}
		}
	}
}

// 9. shared child is not classified as cycle (repeated on the diamond's two
// branches, never on its own ancestor stack).
func TestNestedSharedChildNotCycle(t *testing.T) {
	// Reuses the diamond fixture from test 5; asserted there too, but this
	// test exists explicitly to name the requirement.
	root := t.TempDir()
	writeFile(t, root, ".github/actions/a/action.yml", nestedTwoUsesYAML("./.github/actions/b", "./.github/actions/c"))
	writeFile(t, root, ".github/actions/b/action.yml", nestedUsesYAML("./.github/actions/d"))
	writeFile(t, root, ".github/actions/c/action.yml", nestedUsesYAML("./.github/actions/d"))
	writeFile(t, root, ".github/actions/d/action.yml", compositeYAML)
	workflows := []domain.Workflow{wf("caller.yml", job("build", actionStep("./.github/actions/a")))}

	result := resolveRepo(t, root, workflows)
	if countDiagnostics(result, domain.NestedCompositeActionDiagnosticCycle) != 0 {
		t.Fatalf("shared descendant on separate branches must not be a cycle: %#v", result.Diagnostics)
	}
}

// 10. metadata for each canonical directory parsed once — proven indirectly
// via the diamond case (test 5/9) and directly here by checking Actions
// contains exactly one entry per unique directory even with many references.
func TestNestedMetadataParsedOncePerDirectory(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, ".github/actions/a/action.yml", nestedTwoUsesYAML("./.github/actions/shared", "./.github/actions/shared"))
	writeFile(t, root, ".github/actions/shared/action.yml", compositeYAML)
	workflows := []domain.Workflow{wf("caller.yml", job("build", actionStep("./.github/actions/a")))}

	result := resolveRepo(t, root, workflows)
	seen := map[string]int{}
	for _, a := range result.Actions {
		seen[a.Directory]++
	}
	for dir, count := range seen {
		if count != 1 {
			t.Fatalf("directory %q appears %d times in Actions, want 1", dir, count)
		}
	}
}

// 11/12. already-cached CA1 root action still has its own nested steps
// expanded — proving metadataCache and expanded are genuinely separate
// states: A is cached (parsed) by CA1's own top-level resolution before
// resolveNested ever runs, but must still be expanded (its own runs.steps
// inspected) to discover B.
func TestNestedCachedTopLevelActionStillExpanded(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, ".github/actions/a/action.yml", nestedUsesYAML("./.github/actions/b"))
	writeFile(t, root, ".github/actions/b/action.yml", compositeYAML)
	workflows := []domain.Workflow{wf("caller.yml", job("build", actionStep("./.github/actions/a")))}

	result := resolveRepo(t, root, workflows)
	// A was already resolved (cached) by the pre-existing top-level loop —
	// confirmed present in Calls with resolved status.
	call := findCall(t, result, "caller.yml", "build", 0)
	if call.Status != domain.CompositeActionResolvedLocalComposite || call.CanonicalDirectory != ".github/actions/a" {
		t.Fatalf("A must resolve as a normal CA1 top-level call: %#v", call)
	}
	// A must still have been expanded: B must appear as a nested call and
	// as a resolved canonical action, which only happens if A's own
	// Runs.Steps were inspected despite A's metadata already being cached.
	if !hasAction(result, ".github/actions/b") {
		t.Fatal("cached-but-unexpanded A must still have its nested uses: discovered")
	}
}

// 13. allowed depth 10 has no depth diagnostic; 14. attempted depth 11
// emits one depth diagnostic. Built via a generated chain of actions, each
// calling the next.
func buildChain(t *testing.T, root string, length int) {
	t.Helper()
	for i := 0; i < length; i++ {
		dir := fmt.Sprintf(".github/actions/chain%d", i)
		if i == length-1 {
			writeFile(t, root, dir+"/action.yml", compositeYAML)
			continue
		}
		next := fmt.Sprintf("./.github/actions/chain%d", i+1)
		writeFile(t, root, dir+"/action.yml", nestedUsesYAML(next))
	}
}

func TestNestedDepthTenAllowedNoDiagnostic(t *testing.T) {
	root := t.TempDir()
	// chain0 (the workflow-resolved root, depth 1) through chain9 (depth
	// 10): exactly 10 composite actions on the path, no 11th attempted.
	buildChain(t, root, 10)
	workflows := []domain.Workflow{wf("caller.yml", job("build", actionStep("./.github/actions/chain0")))}

	result := resolveRepo(t, root, workflows)
	if countDiagnostics(result, domain.NestedCompositeActionDiagnosticDepthExceeded) != 0 {
		t.Fatalf("a path of exactly 10 composite actions must not exceed depth: %#v", result.Diagnostics)
	}
}

func TestNestedDepthElevenExceeds(t *testing.T) {
	root := t.TempDir()
	// chain0 (depth 1) through chain10 (depth 11): the 11th action must be
	// rejected.
	buildChain(t, root, 11)
	workflows := []domain.Workflow{wf("caller.yml", job("build", actionStep("./.github/actions/chain0")))}

	result := resolveRepo(t, root, workflows)
	if countDiagnostics(result, domain.NestedCompositeActionDiagnosticDepthExceeded) != 1 {
		t.Fatalf("expected exactly one depth-exceeded diagnostic, got %#v", result.Diagnostics)
	}
	for _, d := range result.Diagnostics {
		if d.Kind == domain.NestedCompositeActionDiagnosticDepthExceeded {
			if d.Depth != 11 {
				t.Fatalf("expected attempted depth 11, got %d", d.Depth)
			}
			if d.Limit != 10 {
				t.Fatalf("expected configured Limit 10, got %d", d.Limit)
			}
			if len(d.Path) != 11 {
				t.Fatalf("expected an 11-entry attempted chain, got %#v", d.Path)
			}
		}
	}
	// The chain's own resolution (metadata, nested calls) must still be
	// fully present up to and including the 11th call site — only the
	// diagnostic reports the over-depth path; nothing is deleted.
	if !hasAction(result, ".github/actions/chain10") {
		t.Fatal("the 11th action's metadata must still be resolved and retained despite the depth diagnostic")
	}
}

// 15. over-depth path does not suppress a valid shallow path to the same
// canonical action: two different roots (rootA at depth 1..11 exceeding,
// rootB directly at depth 1..2 shallow) both target the same deep leaf via
// different chain lengths; the shallow root's own path must report no
// depth-exceeded diagnostic even though a different root's path to a
// similarly-deep chain does.
func TestNestedOverDepthDoesNotSuppressShallowPath(t *testing.T) {
	root := t.TempDir()
	buildChain(t, root, 11) // rooted at chain0, exceeds at chain10
	// A second, independent, shallow root pointing directly at the same
	// deep leaf action (chain10) — reached in one hop, well within budget.
	writeFile(t, root, ".github/actions/shallow-root/action.yml", nestedUsesYAML("./.github/actions/chain10"))
	workflows := []domain.Workflow{wf("caller.yml", job("build",
		actionStepWithID("s0", "./.github/actions/chain0"),
		actionStepWithID("s1", "./.github/actions/shallow-root"),
	))}

	result := resolveRepo(t, root, workflows)
	for _, d := range result.Diagnostics {
		if d.Kind == domain.NestedCompositeActionDiagnosticDepthExceeded && d.RootCanonicalDirectory == ".github/actions/shallow-root" {
			t.Fatalf("shallow-root's own 2-level path must not be reported as depth-exceeded: %#v", d)
		}
	}
}

// 16. repeated canonical action on different branches is evaluated per
// path (diamond depth: each branch counts its own path length
// independently) — reuses the diamond fixture, asserting no depth
// diagnostic at this shallow depth regardless of D being reached twice.
func TestNestedRepeatedActionDifferentBranchesPerPathDepth(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, ".github/actions/a/action.yml", nestedTwoUsesYAML("./.github/actions/b", "./.github/actions/c"))
	writeFile(t, root, ".github/actions/b/action.yml", nestedUsesYAML("./.github/actions/d"))
	writeFile(t, root, ".github/actions/c/action.yml", nestedUsesYAML("./.github/actions/d"))
	writeFile(t, root, ".github/actions/d/action.yml", compositeYAML)
	workflows := []domain.Workflow{wf("caller.yml", job("build", actionStep("./.github/actions/a")))}

	result := resolveRepo(t, root, workflows)
	if countDiagnostics(result, domain.NestedCompositeActionDiagnosticDepthExceeded) != 0 {
		t.Fatalf("shallow diamond must not exceed depth: %#v", result.Diagnostics)
	}
}

// 17. repository-root-relative nested path resolves; 18. parent-directory-
// relative interpretation is not invented: a nested `./sibling` reference
// inside deploy/action.yml must resolve relative to the REPOSITORY ROOT
// (".github/actions/sibling" does not exist), never relative to
// ".github/actions/deploy/sibling".
func TestNestedRepositoryRootRelativePathSemantics(t *testing.T) {
	root := t.TempDir()
	// The nested reference is the full repo-root-relative path, matching
	// official GitHub composite-action semantics.
	writeFile(t, root, ".github/actions/deploy/action.yml", nestedUsesYAML("./.github/actions/authenticate"))
	writeFile(t, root, ".github/actions/authenticate/action.yml", compositeYAML)
	workflows := []domain.Workflow{wf("caller.yml", job("build", actionStep("./.github/actions/deploy")))}

	result := resolveRepo(t, root, workflows)
	nested := findNestedCall(t, result, ".github/actions/deploy", 0)
	if nested.Status != domain.CompositeActionResolvedLocalComposite || nested.CanonicalDirectory != ".github/actions/authenticate" {
		t.Fatalf("expected repository-root-relative resolution to authenticate, got %#v", nested)
	}
}

func TestNestedParentRelativeInterpretationNotInvented(t *testing.T) {
	root := t.TempDir()
	// deploy/action.yml references "./sibling" — if resolution were
	// (incorrectly) parent-relative, this would mean
	// ".github/actions/deploy/sibling", which does not exist on disk. Since
	// CA3A resolves from the repository root, "./sibling" means the
	// repository-root directory "sibling", which also does not exist here
	// — the call must be metadata_missing, never silently reinterpreted
	// against the parent directory.
	writeFile(t, root, ".github/actions/deploy/action.yml", nestedUsesYAML("./sibling"))
	workflows := []domain.Workflow{wf("caller.yml", job("build", actionStep("./.github/actions/deploy")))}

	result := resolveRepo(t, root, workflows)
	nested := findNestedCall(t, result, ".github/actions/deploy", 0)
	if nested.Status != domain.CompositeActionMetadataMissing {
		t.Fatalf("expected metadata_missing (repo-root-relative, not parent-relative), got %#v", nested)
	}
}

// 19. exact-case path succeeds; 20. case mismatch produces the existing
// safe status.
func TestNestedExactCasePathSucceeds(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, ".github/actions/Deploy/action.yml", nestedUsesYAML("./.github/actions/Auth"))
	writeFile(t, root, ".github/actions/Auth/action.yml", compositeYAML)
	workflows := []domain.Workflow{wf("caller.yml", job("build", actionStep("./.github/actions/Deploy")))}

	result := resolveRepo(t, root, workflows)
	nested := findNestedCall(t, result, ".github/actions/Deploy", 0)
	if nested.Status != domain.CompositeActionResolvedLocalComposite || nested.CanonicalDirectory != ".github/actions/Auth" {
		t.Fatalf("exact-case match must resolve, got %#v", nested)
	}
}

func TestNestedCaseMismatchIsMetadataMissing(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, ".github/actions/deploy/action.yml", nestedUsesYAML("./.github/actions/Auth"))
	writeFile(t, root, ".github/actions/auth/action.yml", compositeYAML) // lowercase on disk
	workflows := []domain.Workflow{wf("caller.yml", job("build", actionStep("./.github/actions/deploy")))}

	result := resolveRepo(t, root, workflows)
	nested := findNestedCall(t, result, ".github/actions/deploy", 0)
	if nested.Status != domain.CompositeActionMetadataMissing {
		t.Fatalf("case-mismatched reference must be metadata_missing (matching CA1 exact-case semantics), got %#v", nested)
	}
}

// 21-26: unsafe local-path shapes rejected, mirroring CA1's own validator
// exactly (reused unchanged).
func TestNestedUnsafePathShapesRejected(t *testing.T) {
	cases := map[string]string{
		"traversal":      "../escape",
		"backslash":      ".\\github\\actions\\x",
		"absolute":       "/etc/passwd",
		"query_fragment": "./.github/actions/x?query",
	}
	for name, target := range cases {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			writeFile(t, root, ".github/actions/deploy/action.yml", nestedUsesYAML(target))
			workflows := []domain.Workflow{wf("caller.yml", job("build", actionStep("./.github/actions/deploy")))}
			result := resolveRepo(t, root, workflows)
			nested := findNestedCall(t, result, ".github/actions/deploy", 0)
			if nested.Status != domain.CompositeActionRejectedPath {
				t.Fatalf("%s: expected rejected_path, got %#v", name, nested)
			}
		})
	}
}

func TestNestedDrivePathRejected(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, ".github/actions/deploy/action.yml", nestedUsesYAML(`C:/actions/x`))
	workflows := []domain.Workflow{wf("caller.yml", job("build", actionStep("./.github/actions/deploy")))}
	result := resolveRepo(t, root, workflows)
	nested := findNestedCall(t, result, ".github/actions/deploy", 0)
	if nested.Status != domain.CompositeActionRejectedPath {
		t.Fatalf("expected rejected_path for drive-letter path, got %#v", nested)
	}
}

func TestNestedUNCPathRejected(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, ".github/actions/deploy/action.yml", nestedUsesYAML(`//server/share`))
	workflows := []domain.Workflow{wf("caller.yml", job("build", actionStep("./.github/actions/deploy")))}
	result := resolveRepo(t, root, workflows)
	nested := findNestedCall(t, result, ".github/actions/deploy", 0)
	if nested.Status != domain.CompositeActionRejectedPath {
		t.Fatalf("expected rejected_path for UNC path, got %#v", nested)
	}
}

// 27. symlink/reparse rejected — skipped on platforms/environments where
// symlink creation requires elevated privileges (matching this repository's
// own existing convention for symlink-dependent tests).
func TestNestedSymlinkRejected(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, ".github/actions/real/action.yml", compositeYAML)
	linkPath := filepath.Join(root, ".github", "actions", "linked")
	if err := os.Symlink(filepath.Join(root, ".github", "actions", "real"), linkPath); err != nil {
		t.Skipf("symlink creation not supported in this environment: %v", err)
	}
	writeFile(t, root, ".github/actions/deploy/action.yml", nestedUsesYAML("./.github/actions/linked"))
	workflows := []domain.Workflow{wf("caller.yml", job("build", actionStep("./.github/actions/deploy")))}
	result := resolveRepo(t, root, workflows)
	nested := findNestedCall(t, result, ".github/actions/deploy", 0)
	if nested.Status != domain.CompositeActionRejectedPath {
		t.Fatalf("expected rejected_path for a symlinked directory component, got %#v", nested)
	}
}

// 28. metadata missing.
func TestNestedMetadataMissing(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, ".github/actions/deploy/action.yml", nestedUsesYAML("./.github/actions/nowhere"))
	workflows := []domain.Workflow{wf("caller.yml", job("build", actionStep("./.github/actions/deploy")))}
	result := resolveRepo(t, root, workflows)
	nested := findNestedCall(t, result, ".github/actions/deploy", 0)
	if nested.Status != domain.CompositeActionMetadataMissing {
		t.Fatalf("expected metadata_missing, got %#v", nested)
	}
}

// 29. metadata ambiguous.
func TestNestedMetadataAmbiguous(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, ".github/actions/deploy/action.yml", nestedUsesYAML("./.github/actions/ambiguous"))
	writeFile(t, root, ".github/actions/ambiguous/action.yml", compositeYAML)
	writeFile(t, root, ".github/actions/ambiguous/action.yaml", compositeYAML)
	workflows := []domain.Workflow{wf("caller.yml", job("build", actionStep("./.github/actions/deploy")))}
	result := resolveRepo(t, root, workflows)
	nested := findNestedCall(t, result, ".github/actions/deploy", 0)
	if nested.Status != domain.CompositeActionMetadataAmbiguous {
		t.Fatalf("expected metadata_ambiguous, got %#v", nested)
	}
}

// 30. malformed metadata.
func TestNestedMalformedMetadata(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, ".github/actions/deploy/action.yml", nestedUsesYAML("./.github/actions/broken"))
	writeFile(t, root, ".github/actions/broken/action.yml", malformedYAML)
	workflows := []domain.Workflow{wf("caller.yml", job("build", actionStep("./.github/actions/deploy")))}
	result := resolveRepo(t, root, workflows)
	nested := findNestedCall(t, result, ".github/actions/deploy", 0)
	if nested.Status != domain.CompositeActionMalformedMetadata {
		t.Fatalf("expected malformed_metadata, got %#v", nested)
	}
}

// 31. target_not_composite.
func TestNestedTargetNotComposite(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, ".github/actions/deploy/action.yml", nestedUsesYAML("./.github/actions/jsaction"))
	writeFile(t, root, ".github/actions/jsaction/action.yml", node20YAML)
	workflows := []domain.Workflow{wf("caller.yml", job("build", actionStep("./.github/actions/deploy")))}
	result := resolveRepo(t, root, workflows)
	nested := findNestedCall(t, result, ".github/actions/deploy", 0)
	if nested.Status != domain.CompositeActionTargetNotComposite {
		t.Fatalf("expected target_not_composite, got %#v", nested)
	}
	if hasAction(result, ".github/actions/jsaction") {
		t.Fatal("target_not_composite action must not appear in canonical Actions")
	}
}

// 32. external action remains opaque; 33. Docker action remains opaque;
// 34. expression action remains unsupported.
func TestNestedExternalDockerExpressionRemainOpaque(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, ".github/actions/deploy/action.yml", `name: Deploy
description: test
runs:
  using: composite
  steps:
    - uses: actions/checkout@v4
    - uses: docker://alpine:3.19
    - uses: ${{ inputs.dynamic }}
`)
	workflows := []domain.Workflow{wf("caller.yml", job("build", actionStep("./.github/actions/deploy")))}
	result := resolveRepo(t, root, workflows)
	if findNestedCall(t, result, ".github/actions/deploy", 0).Status != domain.CompositeActionOpaqueExternal {
		t.Fatal("step 0 (owner/repo) must remain opaque_external")
	}
	if findNestedCall(t, result, ".github/actions/deploy", 1).Status != domain.CompositeActionOpaqueDocker {
		t.Fatal("step 1 (docker://) must remain opaque_docker")
	}
	if findNestedCall(t, result, ".github/actions/deploy", 2).Status != domain.CompositeActionUnsupportedExpression {
		t.Fatal("step 2 (expression) must remain unsupported_expression")
	}
}

// 35. safe nonexistent directory is metadata_missing (already covered by
// TestNestedMetadataMissing above; this test names the "safe nonexistent
// directory" wording explicitly with a deeper, still-safe path shape).
func TestNestedSafeNonexistentDirectoryIsMetadataMissing(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, ".github/actions/deploy/action.yml", nestedUsesYAML("./.github/actions/does/not/exist"))
	workflows := []domain.Workflow{wf("caller.yml", job("build", actionStep("./.github/actions/deploy")))}
	result := resolveRepo(t, root, workflows)
	nested := findNestedCall(t, result, ".github/actions/deploy", 0)
	if nested.Status != domain.CompositeActionMetadataMissing {
		t.Fatalf("expected metadata_missing for a safe nonexistent directory, got %#v", nested)
	}
}

// 36. deterministic action ordering; 37. deterministic nested call
// ordering; 38 (diagnostic ordering) is exercised in TestNestedDiagnosticsDeterministic below.
func TestNestedDeterministicOrdering(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, ".github/actions/a/action.yml", nestedTwoUsesYAML("./.github/actions/z", "./.github/actions/b"))
	writeFile(t, root, ".github/actions/z/action.yml", compositeYAML)
	writeFile(t, root, ".github/actions/b/action.yml", compositeYAML)
	workflows := []domain.Workflow{wf("caller.yml", job("build", actionStep("./.github/actions/a")))}

	result := resolveRepo(t, root, workflows)
	for i := 1; i < len(result.Actions); i++ {
		if result.Actions[i-1].Directory >= result.Actions[i].Directory {
			t.Fatalf("Actions not sorted by directory: %#v", result.Actions)
		}
	}
	for i := 1; i < len(result.NestedCalls); i++ {
		a, b := result.NestedCalls[i-1], result.NestedCalls[i]
		if a.ParentCanonicalDirectory > b.ParentCanonicalDirectory {
			t.Fatalf("NestedCalls not sorted by parent directory: %#v", result.NestedCalls)
		}
		if a.ParentCanonicalDirectory == b.ParentCanonicalDirectory && a.ParentActionStepIndex > b.ParentActionStepIndex {
			t.Fatalf("NestedCalls not sorted by parent step index within parent: %#v", result.NestedCalls)
		}
	}
}

func TestNestedDiagnosticsDeterministic(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, ".github/actions/a/action.yml", nestedUsesYAML("./.github/actions/a"))
	workflows := []domain.Workflow{wf("caller.yml", job("build", actionStep("./.github/actions/a")))}

	first := resolveRepo(t, root, workflows)
	second := resolveRepo(t, root, workflows)
	if len(first.Diagnostics) != len(second.Diagnostics) {
		t.Fatalf("diagnostic count not deterministic: %d vs %d", len(first.Diagnostics), len(second.Diagnostics))
	}
	for i := range first.Diagnostics {
		if !reflect.DeepEqual(first.Diagnostics[i], second.Diagnostics[i]) {
			t.Fatalf("diagnostics not deterministically ordered/equal at index %d: %#v vs %#v", i, first.Diagnostics[i], second.Diagnostics[i])
		}
	}
}

// 39. cancellation returns empty result and error.
func TestNestedContextCancellationReturnsEmptyResultAndError(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, ".github/actions/a/action.yml", nestedUsesYAML("./.github/actions/b"))
	writeFile(t, root, ".github/actions/b/action.yml", compositeYAML)
	workflows := []domain.Workflow{wf("caller.yml", job("build", actionStep("./.github/actions/a")))}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	finder := newFinder(t, root)
	result, err := Resolve(ctx, finder, githubactions.New(), workflows)
	if err == nil {
		t.Fatal("expected an error for a canceled context")
	}
	if len(result.Actions) != 0 || len(result.Calls) != 0 || len(result.NestedCalls) != 0 || len(result.Diagnostics) != 0 {
		t.Fatalf("expected an empty result, got %#v", result)
	}
}

// 40. input workflows remain immutable.
func TestNestedWorkflowsRemainImmutable(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, ".github/actions/a/action.yml", nestedUsesYAML("./.github/actions/b"))
	writeFile(t, root, ".github/actions/b/action.yml", compositeYAML)
	workflows := []domain.Workflow{wf("caller.yml", job("build", actionStep("./.github/actions/a")))}
	before := workflows[0].Jobs[0].Steps[0].Action.Reference

	resolveRepo(t, root, workflows)

	after := workflows[0].Jobs[0].Steps[0].Action.Reference
	if before != after {
		t.Fatalf("workflows were mutated: before=%q after=%q", before, after)
	}
}

// 41. separately resolved results share no slices; 42. metadata slices are
// not shared between runs.
func TestNestedSeparatelyResolvedResultsShareNoSlices(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, ".github/actions/a/action.yml", nestedUsesYAML("./.github/actions/b"))
	writeFile(t, root, ".github/actions/b/action.yml", compositeYAML)
	workflows := []domain.Workflow{wf("caller.yml", job("build", actionStep("./.github/actions/a")))}

	first := resolveRepo(t, root, workflows)
	second := resolveRepo(t, root, workflows)

	first.NestedCalls[0].RawReference = "MUTATED"
	if second.NestedCalls[0].RawReference == "MUTATED" {
		t.Fatal("mutating one result's NestedCalls affected a separately resolved result")
	}

	first.Actions[0].Inputs = append(first.Actions[0].Inputs, domain.ActionInputDefinition{Name: "injected"})
	for _, input := range second.Actions[0].Inputs {
		if input.Name == "injected" {
			t.Fatal("mutating one result's Actions[0].Inputs affected a separately resolved result")
		}
	}
}

// separately resolved results' diagnostic Path slices are never shared:
// mutating one result's diagnostic Path must never affect another,
// independently produced result's diagnostic Path.
func TestNestedSeparatelyResolvedDiagnosticsShareNoPathSlices(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, ".github/actions/a/action.yml", nestedUsesYAML("./.github/actions/a"))
	workflows := []domain.Workflow{wf("caller.yml", job("build", actionStep("./.github/actions/a")))}

	first := resolveRepo(t, root, workflows)
	second := resolveRepo(t, root, workflows)
	if len(first.Diagnostics) == 0 || len(second.Diagnostics) == 0 {
		t.Fatal("expected at least one diagnostic in each result")
	}

	first.Diagnostics[0].Path[0] = "MUTATED"
	if second.Diagnostics[0].Path[0] == "MUTATED" {
		t.Fatal("mutating one result's diagnostic Path affected a separately resolved result")
	}
}
