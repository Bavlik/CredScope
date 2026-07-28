package corpustest

import (
	"context"
	"flag"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// update regenerates every success case's expected.json/expected.sarif from
// the real pipeline. It is opt-in, refuses to run anywhere but this module's
// testdata/corpus, and never writes a partial result: every case is
// re-analyzed successfully before any golden file is touched.
//
//	go test ./internal/corpustest -run TestCorpus -update
var update = flag.Bool("update", false, "regenerate corpus golden files (opt-in; never run in normal CI)")

// caseID restricts a run (compare or update) to a single case, e.g.:
//
//	go test ./internal/corpustest -run TestCorpus -case gitleaks-normal-finding -update
var caseID = flag.String("case", "", "restrict to a single case ID (optional)")

// corpusRoot locates testdata/corpus relative to this source file and
// refuses to proceed if the module root does not look like CredScope, so
// -update can never write files outside this repository.
func corpusRoot(t *testing.T) string {
	t.Helper()
	_, current, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not locate corpustest source file via runtime.Caller")
	}
	moduleRoot := filepath.Clean(filepath.Join(filepath.Dir(current), "..", ".."))
	data, err := os.ReadFile(filepath.Join(moduleRoot, "go.mod"))
	if err != nil {
		t.Fatalf("refusing to run: cannot read go.mod under %s: %v", moduleRoot, err)
	}
	if !strings.Contains(string(data), "module github.com/Bavlik/CredScope") {
		t.Fatalf("refusing to run: %s is not the CredScope repository root", moduleRoot)
	}
	root := filepath.Join(moduleRoot, "testdata", "corpus")
	if info, err := os.Stat(root); err != nil || !info.IsDir() {
		t.Fatalf("refusing to run: %s is not a directory", root)
	}
	return root
}

// TestCorpus discovers every case under testdata/corpus, validates its
// manifest, and runs it against the real ingest -> analyze -> report
// pipeline. Without -update it compares rendered output byte-for-byte
// against committed golden files. With -update it regenerates them.
//
// Filtering order matters: Discover only checks global, filter-independent
// structural safety (unique IDs, valid manifests, confined paths, no
// symlinks). The -case filter is applied next. Only THEN is golden-file
// existence enforced (via RequireGoldens, in compare mode) — scoped to
// whatever survived filtering. This means an unrelated case that has no
// golden files yet can never block a different, explicitly selected case
// from being compared or updated.
func TestCorpus(t *testing.T) {
	root := corpusRoot(t)
	all, err := Discover(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) == 0 {
		t.Fatal("no corpus cases discovered under testdata/corpus")
	}

	cases, err := Filter(all, *caseID)
	if err != nil {
		t.Fatal(err) // unknown -case id: error already lists every valid id, no secret material
	}

	if *update {
		if *caseID != "" {
			t.Logf("targeted update: case %s only", *caseID)
		}
		runUpdate(t, cases)
		return
	}

	if err := RequireGoldens(cases); err != nil {
		t.Fatal(err)
	}

	for _, corpusCase := range cases {
		corpusCase := corpusCase
		t.Run(corpusCase.ID, func(t *testing.T) {
			t.Parallel()
			runCompare(t, corpusCase)
		})
	}
}

func runCompare(t *testing.T, c Case) {
	t.Helper()
	outcome, err := Execute(context.Background(), c, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if c.Manifest.Expect.Result == ExpectError {
		return // Execute already validated the controlled error message.
	}
	actualDir := t.TempDir()
	for _, artifact := range []struct {
		file   string
		actual []byte
	}{
		{"expected.json", outcome.Rendered.JSON},
		{"expected.sarif", outcome.Rendered.SARIF},
	} {
		diff, err := compareGolden(c, artifact.file, artifact.actual, actualDir)
		if err != nil {
			t.Fatal(err)
		}
		if diff != nil {
			t.Error(diff.String())
		}
	}
}

// runUpdate stages every case in the batch (via StageAll) before writing
// anything, so a single failing case aborts the whole batch with nothing
// written — golden files are updated all-or-nothing. With a single-case
// batch (the -case-scoped path), this trivially updates just that case.
func runUpdate(t *testing.T, cases []Case) {
	t.Helper()
	pending, err := StageAll(context.Background(), cases, func(string) string { return t.TempDir() })
	if err != nil {
		t.Fatalf("update aborted before writing any file: %v", err)
	}
	updated, err := PublishAll(pending)
	if err != nil {
		t.Fatalf("update failed partway through publishing: %v", err)
	}
	for _, id := range updated {
		t.Logf("updated %s: expected.json, expected.sarif", id)
	}
}
