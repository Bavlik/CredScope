package corpustest

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeMinimalCase creates a self-contained, always-succeeding case: an
// empty repository (no workflows, no Compose, no imported findings), so
// Execute can run it quickly without depending on the real testdata/corpus
// fixtures or their pipeline behavior.
func writeMinimalCase(t *testing.T, corpusRoot, id string, withGoldens bool) {
	t.Helper()
	dir := filepath.Join(corpusRoot, "gitleaks", id)
	mustMkdirAll(t, filepath.Join(dir, "repository"))
	mustWriteFile(t, filepath.Join(dir, "repository", "README.md"), "placeholder\n")
	mustWriteFile(t, filepath.Join(dir, "README.md"), "# "+id+"\n")
	mustWriteFile(t, filepath.Join(dir, "case.yaml"), minimalManifestYAML(id, "success", ""))
	if withGoldens {
		mustWriteFile(t, filepath.Join(dir, "expected.json"), "{}")
		mustWriteFile(t, filepath.Join(dir, "expected.sarif"), "{}")
	}
}

// writeBrokenCase declares expect.result: success but ships a fixture that
// cannot actually be ingested (a structurally invalid workflow), so Execute
// deterministically fails. Used to test that a failing case aborts a batch
// update without needing the AV-sensitive full 26-case corpus.
func writeBrokenCase(t *testing.T, corpusRoot, id string) {
	t.Helper()
	dir := filepath.Join(corpusRoot, "gitleaks", id)
	mustMkdirAll(t, filepath.Join(dir, "repository", ".github", "workflows"))
	mustWriteFile(t, filepath.Join(dir, "repository", ".github", "workflows", "bad.yml"), "name: broken\non: push\njobs:\n  broken:\n    steps: not-a-list\n")
	mustWriteFile(t, filepath.Join(dir, "README.md"), "# "+id+"\n")
	mustWriteFile(t, filepath.Join(dir, "case.yaml"), minimalManifestYAML(id, "success", ""))
}

func minimalManifestYAML(id, result, errorContains string) string {
	doc := "schema_version: 1\n" +
		"id: " + id + "\n" +
		"title: regression fixture\n" +
		"description: regression fixture, not a real corpus case\n" +
		"category: gitleaks\n" +
		"inputs:\n  repository: repository\n" +
		"expect:\n  result: " + result + "\n"
	if errorContains != "" {
		doc += "  error_contains: " + errorContains + "\n"
	}
	return doc
}

func mustMkdirAll(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatal(err)
	}
}

func mustWriteFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestFilterAllowsSelectedCaseDespiteSiblingMissingGoldens proves that
// selecting one case with -case lets it be compared even though a sibling,
// unselected case has no golden files at all.
func TestFilterAllowsSelectedCaseDespiteSiblingMissingGoldens(t *testing.T) {
	root := t.TempDir()
	writeMinimalCase(t, root, "has-goldens", true)
	writeMinimalCase(t, root, "missing-goldens", false)

	all, err := Discover(root)
	if err != nil {
		t.Fatalf("discover should succeed without requiring goldens: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("expected 2 cases, got %d", len(all))
	}

	selected, err := Filter(all, "has-goldens")
	if err != nil {
		t.Fatalf("filter should find the selected case: %v", err)
	}
	if len(selected) != 1 || selected[0].ID != "has-goldens" {
		t.Fatalf("filter returned wrong case set: %#v", selected)
	}
	if err := RequireGoldens(selected); err != nil {
		t.Fatalf("selected case has its own goldens and must pass: %v", err)
	}
}

// TestUnfilteredCompareRequiresGoldensForEveryCase proves that without a
// -case filter, a missing golden file on any success case is still caught.
func TestUnfilteredCompareRequiresGoldensForEveryCase(t *testing.T) {
	root := t.TempDir()
	writeMinimalCase(t, root, "has-goldens", true)
	writeMinimalCase(t, root, "missing-goldens", false)

	all, err := Discover(root)
	if err != nil {
		t.Fatal(err)
	}
	selected, err := Filter(all, "") // no -case: everything selected
	if err != nil {
		t.Fatal(err)
	}
	err = RequireGoldens(selected)
	if err == nil {
		t.Fatal("expected an error naming the case missing golden files")
	}
	if !strings.Contains(err.Error(), "missing-goldens") {
		t.Fatalf("error should name the offending case, got: %v", err)
	}
}

// TestFilterUnknownCaseIDListsValidIDs proves an unknown -case value fails
// clearly and lists every real case ID (never a secret) to help fix a typo.
func TestFilterUnknownCaseIDListsValidIDs(t *testing.T) {
	root := t.TempDir()
	writeMinimalCase(t, root, "alpha-case", true)
	writeMinimalCase(t, root, "beta-case", true)

	all, err := Discover(root)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Filter(all, "does-not-exist")
	if err == nil {
		t.Fatal("expected an error for an unknown case id")
	}
	message := err.Error()
	for _, want := range []string{"does-not-exist", "alpha-case", "beta-case"} {
		if !strings.Contains(message, want) {
			t.Errorf("error message %q should mention %q", message, want)
		}
	}
}

// TestTargetedUpdateWritesOnlySelectedCase proves a -case-scoped update
// writes goldens for the selected case only, leaving a sibling untouched.
func TestTargetedUpdateWritesOnlySelectedCase(t *testing.T) {
	root := t.TempDir()
	writeMinimalCase(t, root, "target-case", false)
	writeMinimalCase(t, root, "sibling-case", false)

	all, err := Discover(root)
	if err != nil {
		t.Fatal(err)
	}
	selected, err := Filter(all, "target-case")
	if err != nil {
		t.Fatal(err)
	}
	pending, err := StageAll(context.Background(), selected, func(string) string { return t.TempDir() })
	if err != nil {
		t.Fatalf("staging the selected case should succeed: %v", err)
	}
	if _, err := PublishAll(pending); err != nil {
		t.Fatalf("publishing the selected case should succeed: %v", err)
	}

	if _, err := os.Stat(filepath.Join(root, "gitleaks", "target-case", "expected.json")); err != nil {
		t.Errorf("target case should have expected.json: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "gitleaks", "sibling-case", "expected.json")); err == nil {
		t.Error("sibling case must not have received a golden file from a targeted update")
	}
}

// TestFullUpdateIsAllOrNothing proves that one failing case in an
// unfiltered update batch aborts staging before any file is written for
// ANY case in the batch, including ones that would otherwise have succeeded.
func TestFullUpdateIsAllOrNothing(t *testing.T) {
	root := t.TempDir()
	writeMinimalCase(t, root, "good-case", false)
	writeBrokenCase(t, root, "broken-case")

	all, err := Discover(root)
	if err != nil {
		t.Fatal(err)
	}
	selected, err := Filter(all, "")
	if err != nil {
		t.Fatal(err)
	}
	_, err = StageAll(context.Background(), selected, func(string) string { return t.TempDir() })
	if err == nil {
		t.Fatal("expected staging to fail because of the broken case")
	}
	if !strings.Contains(err.Error(), "broken-case") {
		t.Fatalf("error should name the failing case, got: %v", err)
	}

	for _, id := range []string{"good-case", "broken-case"} {
		if _, statErr := os.Stat(filepath.Join(root, "gitleaks", id, "expected.json")); statErr == nil {
			t.Errorf("case %s must not have a golden file after an aborted all-or-nothing update", id)
		}
	}
}
