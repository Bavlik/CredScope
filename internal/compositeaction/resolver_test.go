package compositeaction

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/Bavlik/CredScope/internal/discovery"
	"github.com/Bavlik/CredScope/internal/domain"
	"github.com/Bavlik/CredScope/internal/parsers/githubactions"
)

const compositeYAML = `name: Deploy
description: Deploys the app
inputs:
  token:
    required: true
runs:
  using: composite
  steps:
    - run: echo hi
      shell: bash
`

const node20YAML = `name: Node Action
description: A JS action
runs:
  using: node20
  main: index.js
`

const dockerMetadataYAML = `name: Docker Action
description: A docker action
runs:
  using: docker
  image: Dockerfile
`

const malformedYAML = `name: Bad
description: missing runs
`

func newFinder(t *testing.T, root string) *discovery.Finder {
	t.Helper()
	finder, err := discovery.New(root, discovery.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return finder
}

func writeFile(t *testing.T, root, relPath, content string) {
	t.Helper()
	full := filepath.Join(root, filepath.FromSlash(relPath))
	if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func actionStep(uses string) domain.WorkflowStep {
	return domain.WorkflowStep{
		Action: &domain.ActionReference{Reference: uses, Evidence: domain.Evidence{Location: domain.Location{Path: "caller.yml", Line: 1}}},
	}
}

func actionStepWithID(id, uses string) domain.WorkflowStep {
	step := actionStep(uses)
	step.ID = id
	return step
}

func wf(file string, jobs ...domain.WorkflowJob) domain.Workflow {
	return domain.Workflow{Name: file, File: file, Jobs: jobs}
}

func job(id string, steps ...domain.WorkflowStep) domain.WorkflowJob {
	return domain.WorkflowJob{ID: id, Steps: steps}
}

func findCall(t *testing.T, result domain.CompositeActionResolution, workflow, jobID string, stepIndex int) domain.CompositeActionCall {
	t.Helper()
	for _, c := range result.Calls {
		if c.CallerWorkflow == workflow && c.CallerJobID == jobID && c.CallerStepIndex == stepIndex {
			return c
		}
	}
	t.Fatalf("call for %s/%s[%d] not found in %#v", workflow, jobID, stepIndex, result.Calls)
	return domain.CompositeActionCall{}
}

func resolveOne(t *testing.T, root, uses string) domain.CompositeActionCall {
	t.Helper()
	finder := newFinder(t, root)
	parser := githubactions.New()
	workflows := []domain.Workflow{wf(".github/workflows/caller.yml", job("build", actionStep(uses)))}
	result, err := Resolve(context.Background(), finder, parser, workflows)
	if err != nil {
		t.Fatal(err)
	}
	return findCall(t, result, ".github/workflows/caller.yml", "build", 0)
}

// 1. action.yml resolved.
func TestResolveActionYMLResolved(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, ".github/actions/deploy/action.yml", compositeYAML)
	call := resolveOne(t, root, "./.github/actions/deploy")
	if call.Status != domain.CompositeActionResolvedLocalComposite || call.MetadataFile != "action.yml" {
		t.Fatalf("call = %#v", call)
	}
}

// 2. action.yaml resolved.
func TestResolveActionYAMLResolved(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, ".github/actions/deploy/action.yaml", compositeYAML)
	call := resolveOne(t, root, "./.github/actions/deploy")
	if call.Status != domain.CompositeActionResolvedLocalComposite || call.MetadataFile != "action.yaml" {
		t.Fatalf("call = %#v", call)
	}
}

// 3. both safe files -> metadata_ambiguous.
func TestResolveBothMetadataFilesAmbiguous(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "actions/security/action.yml", compositeYAML)
	writeFile(t, root, "actions/security/action.yaml", compositeYAML)
	call := resolveOne(t, root, "./actions/security")
	if call.Status != domain.CompositeActionMetadataAmbiguous {
		t.Fatalf("status = %v", call.Status)
	}
}

// 4. neither -> metadata_missing.
func TestResolveNeitherMetadataFileMissing(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "tools", "action"), 0o750); err != nil {
		t.Fatal(err)
	}
	call := resolveOne(t, root, "./tools/action")
	if call.Status != domain.CompositeActionMetadataMissing {
		t.Fatalf("status = %v", call.Status)
	}
	if call.CanonicalDirectory != "tools/action" {
		t.Fatalf("CanonicalDirectory = %q, want it preserved for a missing-metadata safe directory", call.CanonicalDirectory)
	}
}

// A syntactically valid, confined reference whose target directory does not
// exist at all (as opposed to existing but empty) must also be
// metadata_missing, never rejected_path, and must preserve CanonicalDirectory.
func TestResolveNonexistentDirectoryIsMetadataMissing(t *testing.T) {
	root := t.TempDir()
	call := resolveOne(t, root, "./tools/does-not-exist")
	if call.Status != domain.CompositeActionMetadataMissing {
		t.Fatalf("status = %v, want metadata_missing", call.Status)
	}
	if call.CanonicalDirectory != "tools/does-not-exist" {
		t.Fatalf("CanonicalDirectory = %q", call.CanonicalDirectory)
	}
}

// Resolving the same nonexistent directory twice must produce the same
// status and the same CanonicalDirectory both times.
func TestResolveMissingDirectoryDeterministic(t *testing.T) {
	root := t.TempDir()
	finder := newFinder(t, root)
	parser := githubactions.New()
	workflows := []domain.Workflow{wf(".github/workflows/caller.yml", job("build", actionStep("./tools/missing")))}
	first, err := Resolve(context.Background(), finder, parser, workflows)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Resolve(context.Background(), finder, parser, workflows)
	if err != nil {
		t.Fatal(err)
	}
	c1 := findCall(t, first, ".github/workflows/caller.yml", "build", 0)
	c2 := findCall(t, second, ".github/workflows/caller.yml", "build", 0)
	if c1.Status != domain.CompositeActionMetadataMissing {
		t.Fatalf("status = %v", c1.Status)
	}
	if c1.Status != c2.Status || c1.CanonicalDirectory != c2.CanonicalDirectory || c1.CanonicalDirectory != "tools/missing" {
		t.Fatalf("not deterministic: c1=%#v c2=%#v", c1, c2)
	}
}

// 5. malformed YAML -> malformed_metadata.
func TestResolveMalformedMetadata(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "tools/action/action.yml", malformedYAML)
	call := resolveOne(t, root, "./tools/action")
	if call.Status != domain.CompositeActionMalformedMetadata {
		t.Fatalf("status = %v", call.Status)
	}
}

// 6. node20 -> target_not_composite.
func TestResolveNode20TargetNotComposite(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "tools/action/action.yml", node20YAML)
	call := resolveOne(t, root, "./tools/action")
	if call.Status != domain.CompositeActionTargetNotComposite {
		t.Fatalf("status = %v", call.Status)
	}
}

// 7. Docker metadata -> target_not_composite.
func TestResolveDockerMetadataTargetNotComposite(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "tools/action/action.yml", dockerMetadataYAML)
	call := resolveOne(t, root, "./tools/action")
	if call.Status != domain.CompositeActionTargetNotComposite {
		t.Fatalf("status = %v", call.Status)
	}
}

// 8. composite -> resolved_local_composite, with canonical ActionMetadata present.
func TestResolveCompositeResolvedWithCanonicalAction(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, ".github/actions/deploy/action.yml", compositeYAML)
	finder := newFinder(t, root)
	parser := githubactions.New()
	workflows := []domain.Workflow{wf(".github/workflows/caller.yml", job("build", actionStep("./.github/actions/deploy")))}
	result, err := Resolve(context.Background(), finder, parser, workflows)
	if err != nil {
		t.Fatal(err)
	}
	call := findCall(t, result, ".github/workflows/caller.yml", "build", 0)
	if call.Status != domain.CompositeActionResolvedLocalComposite {
		t.Fatalf("status = %v", call.Status)
	}
	if len(result.Actions) != 1 || result.Actions[0].Directory != call.CanonicalDirectory || result.Actions[0].Name != "Deploy" {
		t.Fatalf("actions = %#v", result.Actions)
	}
}

// CallerStepID is preserved verbatim as display/evidence, even though
// CallerStepIndex remains the authoritative identity field.
func TestResolveCallerStepIDPreserved(t *testing.T) {
	root := t.TempDir()
	finder := newFinder(t, root)
	parser := githubactions.New()
	workflows := []domain.Workflow{wf(".github/workflows/caller.yml", job("build", actionStepWithID("checkout-step", "actions/checkout@v4")))}
	result, err := Resolve(context.Background(), finder, parser, workflows)
	if err != nil {
		t.Fatal(err)
	}
	call := findCall(t, result, ".github/workflows/caller.yml", "build", 0)
	if call.CallerStepID != "checkout-step" {
		t.Fatalf("CallerStepID = %q", call.CallerStepID)
	}
}

// 9. external -> opaque_external.
func TestResolveExternalOpaque(t *testing.T) {
	root := t.TempDir()
	call := resolveOne(t, root, "actions/checkout@v4")
	if call.Status != domain.CompositeActionOpaqueExternal || call.CanonicalDirectory != "" {
		t.Fatalf("call = %#v", call)
	}
}

// 10. docker:// -> opaque_docker.
func TestResolveDockerReferenceOpaque(t *testing.T) {
	root := t.TempDir()
	call := resolveOne(t, root, "docker://alpine:3")
	if call.Status != domain.CompositeActionOpaqueDocker {
		t.Fatalf("status = %v", call.Status)
	}
}

// 11. expression -> unsupported_expression.
func TestResolveExpressionUnsupported(t *testing.T) {
	root := t.TempDir()
	call := resolveOne(t, root, "${{ inputs.action }}")
	if call.Status != domain.CompositeActionUnsupportedExpression {
		t.Fatalf("status = %v", call.Status)
	}
	call = resolveOne(t, root, "${{ github.workspace }}/action")
	if call.Status != domain.CompositeActionUnsupportedExpression {
		t.Fatalf("status = %v", call.Status)
	}
}

// 12. traversal -> rejected_path.
func TestResolveTraversalRejected(t *testing.T) {
	root := t.TempDir()
	for _, raw := range []string{"../action", "./../action", "./a/../action", "./a/../../action"} {
		call := resolveOne(t, root, raw)
		if call.Status != domain.CompositeActionRejectedPath {
			t.Fatalf("raw=%q status = %v", raw, call.Status)
		}
	}
}

// Traversal rejection is component-based: only a path component that is
// exactly ".." is rejected. A legitimate directory name that merely
// contains two dots must resolve normally, never rejected as traversal.
func TestResolveLegitimateDoubleDotNamesAccepted(t *testing.T) {
	root := t.TempDir()
	for _, dir := range []string{
		"actions/release..candidate",
		"actions/..hidden",
		"actions/name..part",
		"actions/v1.0..next",
	} {
		writeFile(t, root, dir+"/action.yml", compositeYAML)
		call := resolveOne(t, root, "./"+dir)
		if call.Status != domain.CompositeActionResolvedLocalComposite {
			t.Fatalf("dir=%q status = %v, want resolved_local_composite", dir, call.Status)
		}
		if call.CanonicalDirectory != dir {
			t.Fatalf("dir=%q CanonicalDirectory = %q", dir, call.CanonicalDirectory)
		}
	}
}

// 13. absolute Unix -> rejected_path.
func TestResolveAbsoluteUnixRejected(t *testing.T) {
	root := t.TempDir()
	call := resolveOne(t, root, "/absolute/action")
	if call.Status != domain.CompositeActionRejectedPath {
		t.Fatalf("status = %v", call.Status)
	}
}

// 14. Windows drive -> rejected_path.
func TestResolveWindowsDriveRejected(t *testing.T) {
	root := t.TempDir()
	for _, raw := range []string{`C:\actions\deploy`, "C:/actions/deploy"} {
		call := resolveOne(t, root, raw)
		if call.Status != domain.CompositeActionRejectedPath {
			t.Fatalf("raw=%q status = %v", raw, call.Status)
		}
	}
}

// 15. UNC -> rejected_path.
func TestResolveUNCRejected(t *testing.T) {
	root := t.TempDir()
	for _, raw := range []string{`\\server\share\action`, "//server/share/action"} {
		call := resolveOne(t, root, raw)
		if call.Status != domain.CompositeActionRejectedPath {
			t.Fatalf("raw=%q status = %v", raw, call.Status)
		}
	}
}

// 16. backslash -> rejected_path.
func TestResolveBackslashRejected(t *testing.T) {
	root := t.TempDir()
	call := resolveOne(t, root, `.\actions\deploy`)
	if call.Status != domain.CompositeActionRejectedPath {
		t.Fatalf("status = %v", call.Status)
	}
}

// 17. query -> rejected_path.
func TestResolveQueryRejected(t *testing.T) {
	root := t.TempDir()
	call := resolveOne(t, root, "./action?action=1")
	if call.Status != domain.CompositeActionRejectedPath {
		t.Fatalf("status = %v", call.Status)
	}
}

// 18. fragment -> rejected_path.
func TestResolveFragmentRejected(t *testing.T) {
	root := t.TempDir()
	call := resolveOne(t, root, "./action#fragment")
	if call.Status != domain.CompositeActionRejectedPath {
		t.Fatalf("status = %v", call.Status)
	}
}

// 19. direct action.yml -> rejected_path.
func TestResolveDirectActionYMLRejected(t *testing.T) {
	root := t.TempDir()
	call := resolveOne(t, root, "./action/action.yml")
	if call.Status != domain.CompositeActionRejectedPath {
		t.Fatalf("status = %v", call.Status)
	}
}

// 20. direct action.yaml -> rejected_path.
func TestResolveDirectActionYAMLRejected(t *testing.T) {
	root := t.TempDir()
	call := resolveOne(t, root, "./action/action.yaml")
	if call.Status != domain.CompositeActionRejectedPath {
		t.Fatalf("status = %v", call.Status)
	}
}

// 21. trailing slash normalization.
func TestResolveTrailingSlashNormalized(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "tools/action/action.yml", compositeYAML)
	call := resolveOne(t, root, "./tools/action/")
	if call.Status != domain.CompositeActionResolvedLocalComposite || call.CanonicalDirectory != "tools/action" {
		t.Fatalf("call = %#v", call)
	}
}

// 22. repeated slash normalization.
func TestResolveRepeatedSlashNormalized(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "a/b/action.yml", compositeYAML)
	call := resolveOne(t, root, "./a//b")
	if call.Status != domain.CompositeActionResolvedLocalComposite || call.CanonicalDirectory != "a/b" {
		t.Fatalf("call = %#v", call)
	}
}

// 23. repository root action ./.
func TestResolveRepositoryRootAction(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "action.yml", compositeYAML)
	call := resolveOne(t, root, "./")
	if call.Status != domain.CompositeActionResolvedLocalComposite || call.CanonicalDirectory != "." {
		t.Fatalf("call = %#v", call)
	}
}

// 24. exact case matching.
func TestResolveExactCaseMatches(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "tools/action/action.yml", compositeYAML)
	call := resolveOne(t, root, "./tools/action")
	if call.Status != domain.CompositeActionResolvedLocalComposite || call.MetadataFile != "action.yml" {
		t.Fatalf("call = %#v", call)
	}
}

// 25. case mismatch -> metadata_missing (on-disk filename casing differs
// from the exact "action.yml"/"action.yaml" candidates this resolver looks
// for; directory-entry matching is exact-case, never OS-default-insensitive).
func TestResolveCaseMismatchIsMetadataMissing(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "tools/action/Action.yml", compositeYAML)
	call := resolveOne(t, root, "./tools/action")
	if call.Status != domain.CompositeActionMetadataMissing {
		t.Fatalf("status = %v", call.Status)
	}
}

// Cross-platform regression: a directory-component case mismatch must never
// resolve, on any OS, including Windows and macOS where the underlying
// filesystem is case-insensitive by default. The exact-case reference must
// still resolve normally.
func TestResolveDirectoryComponentCaseMismatchIsMetadataMissing(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "Actions/Deploy/action.yml", compositeYAML)

	mismatched := resolveOne(t, root, "./actions/deploy")
	if mismatched.Status != domain.CompositeActionMetadataMissing {
		t.Fatalf("status = %v, want metadata_missing for a directory-component case mismatch", mismatched.Status)
	}

	exact := resolveOne(t, root, "./Actions/Deploy")
	if exact.Status != domain.CompositeActionResolvedLocalComposite {
		t.Fatalf("status = %v, want resolved_local_composite for the exact-case reference", exact.Status)
	}
	if exact.CanonicalDirectory != "Actions/Deploy" {
		t.Fatalf("CanonicalDirectory = %q, case must be preserved exactly", exact.CanonicalDirectory)
	}
}

// A case mismatch on only one of two nested components must still be
// treated as not found, regardless of which component mismatches.
func TestResolveDirectoryPartialComponentCaseMismatch(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "Actions/Deploy/action.yml", compositeYAML)

	firstWrong := resolveOne(t, root, "./actions/Deploy")
	if firstWrong.Status != domain.CompositeActionMetadataMissing {
		t.Fatalf("first-component mismatch: status = %v", firstWrong.Status)
	}
	secondWrong := resolveOne(t, root, "./Actions/deploy")
	if secondWrong.Status != domain.CompositeActionMetadataMissing {
		t.Fatalf("second-component mismatch: status = %v", secondWrong.Status)
	}
}

// 26. symlinked action directory -> rejected_path.
func TestResolveSymlinkedActionDirectoryRejected(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real-action")
	writeFile(t, root, "real-action/action.yml", compositeYAML)
	link := filepath.Join(root, "linked-action")
	if err := os.Symlink(real, link); err != nil {
		if runtime.GOOS == "windows" {
			t.Skip("creating symlinks requires elevated privileges on this Windows host")
		}
		t.Fatal(err)
	}
	call := resolveOne(t, root, "./linked-action")
	if call.Status != domain.CompositeActionRejectedPath {
		t.Fatalf("status = %v", call.Status)
	}
}

// 27. symlinked metadata file -> rejected_path.
func TestResolveSymlinkedMetadataFileRejected(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "real-action/action.yml", compositeYAML)
	if err := os.MkdirAll(filepath.Join(root, "linked-metadata"), 0o750); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "linked-metadata", "action.yml")
	if err := os.Symlink(filepath.Join(root, "real-action", "action.yml"), link); err != nil {
		if runtime.GOOS == "windows" {
			t.Skip("creating symlinks requires elevated privileges on this Windows host")
		}
		t.Fatal(err)
	}
	call := resolveOne(t, root, "./linked-metadata")
	if call.Status != domain.CompositeActionRejectedPath {
		t.Fatalf("status = %v", call.Status)
	}
}

// 28. safe action.yml plus symlink action.yaml -> rejected_path (the unsafe
// sibling must never be silently ignored just because a safe candidate
// also exists).
func TestResolveSafeFilePlusSymlinkSiblingRejected(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "mixed-action/action.yml", compositeYAML)
	writeFile(t, root, "elsewhere/action.yaml", compositeYAML)
	link := filepath.Join(root, "mixed-action", "action.yaml")
	if err := os.Symlink(filepath.Join(root, "elsewhere", "action.yaml"), link); err != nil {
		if runtime.GOOS == "windows" {
			t.Skip("creating symlinks requires elevated privileges on this Windows host")
		}
		t.Fatal(err)
	}
	call := resolveOne(t, root, "./mixed-action")
	if call.Status != domain.CompositeActionRejectedPath {
		t.Fatalf("status = %v", call.Status)
	}
}

// 29. metadata candidate is directory -> rejected_path.
func TestResolveMetadataCandidateIsDirectoryRejected(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "odd-action", "action.yml"), 0o750); err != nil {
		t.Fatal(err)
	}
	call := resolveOne(t, root, "./odd-action")
	if call.Status != domain.CompositeActionRejectedPath {
		t.Fatalf("status = %v", call.Status)
	}
}

// 30. deeply nested action.
func TestResolveDeeplyNestedAction(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "a/b/c/d/e/f/g/action.yml", compositeYAML)
	call := resolveOne(t, root, "./a/b/c/d/e/f/g")
	if call.Status != domain.CompositeActionResolvedLocalComposite {
		t.Fatalf("status = %v", call.Status)
	}
}

// 31. referenced action under vendor/ignored directory resolves safely
// because resolution is on-demand (Finder.ResolveDirectory), not the
// broad, ignored-directory-filtering Find() walk.
func TestResolveActionUnderIgnoredDirectoryResolves(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "vendor/action/action.yml", compositeYAML)
	call := resolveOne(t, root, "./vendor/action")
	if call.Status != domain.CompositeActionResolvedLocalComposite {
		t.Fatalf("status = %v", call.Status)
	}
}

// 32. context cancellation.
func TestResolveContextCancellation(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "tools/action/action.yml", compositeYAML)
	finder := newFinder(t, root)
	parser := githubactions.New()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	workflows := []domain.Workflow{wf(".github/workflows/caller.yml", job("build", actionStep("./tools/action")))}
	result, err := Resolve(ctx, finder, parser, workflows)
	if err == nil {
		t.Fatal("expected context cancellation error")
	}
	// Cancellation is fatal: it must never surface as a per-call status
	// (e.g. malformed_metadata), and no partial result is returned.
	if len(result.Calls) != 0 || len(result.Actions) != 0 {
		t.Fatalf("expected zero-value result on cancellation, got %#v", result)
	}
}

// 33. deterministic ordering: Calls are sorted by (CallerWorkflow,
// CallerJobID, CallerStepIndex) regardless of input workflow order.
func TestResolveDeterministicOrdering(t *testing.T) {
	root := t.TempDir()
	finder := newFinder(t, root)
	parser := githubactions.New()
	workflows := []domain.Workflow{
		wf(".github/workflows/b.yml", job("build", actionStep("actions/checkout@v4"))),
		wf(".github/workflows/a.yml", job("build", actionStep("actions/checkout@v4"))),
	}
	result, err := Resolve(context.Background(), finder, parser, workflows)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Calls) != 2 || result.Calls[0].CallerWorkflow != ".github/workflows/a.yml" || result.Calls[1].CallerWorkflow != ".github/workflows/b.yml" {
		t.Fatalf("calls = %#v", result.Calls)
	}
}

// 34. repeated resolution byte-identical.
func TestResolveRepeatedResolutionIdentical(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, ".github/actions/deploy/action.yml", compositeYAML)
	finder := newFinder(t, root)
	parser := githubactions.New()
	workflows := []domain.Workflow{wf(".github/workflows/caller.yml", job("build", actionStep("./.github/actions/deploy")))}
	first, err := Resolve(context.Background(), finder, parser, workflows)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Resolve(context.Background(), finder, parser, workflows)
	if err != nil {
		t.Fatal(err)
	}
	firstJSON, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	secondJSON, err := json.Marshal(second)
	if err != nil {
		t.Fatal(err)
	}
	if string(firstJSON) != string(secondJSON) {
		t.Fatalf("resolution not byte-identical:\nfirst:  %s\nsecond: %s", firstJSON, secondJSON)
	}
}

// 35. input workflows immutable.
func TestResolveInputWorkflowsImmutable(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, ".github/actions/deploy/action.yml", compositeYAML)
	finder := newFinder(t, root)
	parser := githubactions.New()
	workflows := []domain.Workflow{wf(".github/workflows/caller.yml", job("build", actionStep("./.github/actions/deploy")))}
	before, err := json.Marshal(workflows)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Resolve(context.Background(), finder, parser, workflows); err != nil {
		t.Fatal(err)
	}
	after, err := json.Marshal(workflows)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatalf("input workflows mutated by Resolve:\nbefore: %s\nafter:  %s", before, after)
	}
}

// 36. separately resolved results do not share mutable nested slices.
func TestResolveSeparateResultsDoNotShareBackingArrays(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, ".github/actions/deploy/action.yml", compositeYAML)
	finder := newFinder(t, root)
	parser := githubactions.New()
	workflows := []domain.Workflow{wf(".github/workflows/caller.yml", job("build", actionStep("./.github/actions/deploy")))}
	first, err := Resolve(context.Background(), finder, parser, workflows)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Resolve(context.Background(), finder, parser, workflows)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Actions) != 1 || len(second.Actions) != 1 || len(first.Actions[0].Inputs) == 0 || len(second.Actions[0].Inputs) == 0 {
		t.Fatalf("expected both results to have one action with inputs: first=%#v second=%#v", first.Actions, second.Actions)
	}
	originalName := second.Actions[0].Inputs[0].Name
	first.Actions[0].Inputs[0].Name = "mutated-by-test"
	if second.Actions[0].Inputs[0].Name != originalName {
		t.Fatalf("mutating first result's nested slice affected second result: got %q, want %q", second.Actions[0].Inputs[0].Name, originalName)
	}
}

// 37. one canonical ActionMetadata for multiple calls.
func TestResolveOneCanonicalActionForMultipleCalls(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "tools/action/action.yml", compositeYAML)
	finder := newFinder(t, root)
	parser := githubactions.New()
	workflows := []domain.Workflow{
		wf(".github/workflows/caller.yml",
			job("first", actionStep("./tools/action")),
			job("second", actionStep("./tools/action")),
		),
	}
	result, err := Resolve(context.Background(), finder, parser, workflows)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Actions) != 1 {
		t.Fatalf("actions = %#v, want exactly one canonical action", result.Actions)
	}
	firstCall := findCall(t, result, ".github/workflows/caller.yml", "first", 0)
	secondCall := findCall(t, result, ".github/workflows/caller.yml", "second", 0)
	if firstCall.CanonicalDirectory != secondCall.CanonicalDirectory || firstCall.Status != domain.CompositeActionResolvedLocalComposite {
		t.Fatalf("calls = %#v / %#v", firstCall, secondCall)
	}
}

// 38. parser called once per canonical directory. Black-box: two calls into
// the same directory still produce exactly one canonical action (proven
// above by TestResolveOneCanonicalActionForMultipleCalls). White-box here:
// Resolve's own mechanism for this guarantee is that resolveDirectory is
// invoked at most once per element of uniqueSortedDirectories' output, so
// proving that helper collapses duplicate directory references to one entry
// proves parsing itself can happen at most once per canonical directory.
func TestUniqueSortedDirectoriesDedupesForSingleParse(t *testing.T) {
	pending := []pendingLocal{
		{callIndex: 0, directory: "tools/action"},
		{callIndex: 1, directory: "tools/action"},
		{callIndex: 2, directory: "a/b"},
	}
	directories := uniqueSortedDirectories(pending)
	if len(directories) != 2 || directories[0] != "a/b" || directories[1] != "tools/action" {
		t.Fatalf("directories = %#v", directories)
	}
}
