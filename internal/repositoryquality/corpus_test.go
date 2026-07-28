package repositoryquality

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Bavlik/CredScope/internal/corpustest"
	"gopkg.in/yaml.v3"
)

// corpusRoot locates testdata/corpus relative to the module root shared
// with the rest of this package's release/packaging guards.
func corpusRoot(t *testing.T) string {
	t.Helper()
	return filepath.Join(repositoryRoot(t), "testdata", "corpus")
}

// TestCorpusManifestsAreStructurallyValid re-runs the same discovery and
// validation the corpus runner itself uses (unique IDs, valid case.yaml,
// confined paths, no symlinks, required README.md, category consistency)
// as an ordinary part of `go test ./...`, so a broken corpus case is caught
// without anyone needing to know to run the corpustest package specifically.
func TestCorpusManifestsAreStructurallyValid(t *testing.T) {
	cases, err := corpustest.Discover(corpusRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) == 0 {
		t.Fatal("no corpus cases discovered under testdata/corpus")
	}
}

// TestCorpusDiscoveryOrderIsDeterministic proves Discover returns the same,
// ID-sorted order on repeated calls, independent of filesystem iteration
// order.
func TestCorpusDiscoveryOrderIsDeterministic(t *testing.T) {
	root := corpusRoot(t)
	first, err := corpustest.Discover(root)
	if err != nil {
		t.Fatal(err)
	}
	second, err := corpustest.Discover(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != len(second) {
		t.Fatalf("discovery returned different case counts across runs: %d vs %d", len(first), len(second))
	}
	for i := range first {
		if first[i].ID != second[i].ID {
			t.Fatalf("discovery order not stable at index %d: %q vs %q", i, first[i].ID, second[i].ID)
		}
	}
	for i := 1; i < len(first); i++ {
		if first[i-1].ID >= first[i].ID {
			t.Fatalf("cases not sorted by id: %q >= %q", first[i-1].ID, first[i].ID)
		}
	}
}

// TestCorpusSuccessCasesHaveGoldenFiles enforces the corpus's end goal:
// every case whose manifest expects success must carry committed
// expected.json and expected.sarif golden files. Until golden generation
// completes (currently blocked on this Windows machine and deferred to
// Linux — see docs/TEST_CORPUS.md), this test is EXPECTED to fail, listing
// exactly which cases still need generation; that is the intended, visible
// signal that generation is incomplete, not a masked or silently skipped
// requirement.
func TestCorpusSuccessCasesHaveGoldenFiles(t *testing.T) {
	cases, err := corpustest.Discover(corpusRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := corpustest.RequireGoldens(cases); err != nil {
		t.Fatal(err)
	}
}

// TestCorpusNoSymlinksAbsolutePathsOrOversizedFixtures walks the entire
// corpus tree (not just manifest-declared paths) rejecting symlinks,
// suspicious machine-specific absolute path text inside fixture content,
// unexpected executable file extensions, and unreasonably large files.
func TestCorpusNoSymlinksAbsolutePathsOrOversizedFixtures(t *testing.T) {
	root := corpusRoot(t)
	const maxFixtureSize = 200 * 1024 // generous; real fixtures are tiny
	forbiddenExtensions := map[string]bool{
		".exe": true, ".dll": true, ".so": true, ".dylib": true,
		".bat": true, ".cmd": true, ".ps1": true, ".sh": true, ".bin": true,
	}
	suspiciousPathMarkers := []string{`C:\Users`, `C:\Projects`, "/home/", "/Users/", "/root/", "/tmp/credscope"}

	err := filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.Mode()&os.ModeSymlink != 0 {
			t.Errorf("symlink not allowed in corpus fixtures: %s", path)
			return nil
		}
		if info.IsDir() {
			return nil
		}
		if forbiddenExtensions[strings.ToLower(filepath.Ext(path))] {
			t.Errorf("unexpected executable-looking file in corpus fixtures: %s", path)
		}
		if info.Size() > maxFixtureSize {
			t.Errorf("fixture exceeds size limit of %d bytes: %s (%d bytes)", maxFixtureSize, path, info.Size())
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Errorf("read %s: %v", path, readErr)
			return nil
		}
		text := string(data)
		for _, marker := range suspiciousPathMarkers {
			if strings.Contains(text, marker) {
				t.Errorf("fixture %s contains a machine-specific absolute path marker %q", path, marker)
			}
		}
		if strings.Contains(strings.ToUpper(text), "-----BEGIN") && strings.Contains(strings.ToUpper(text), "PRIVATE KEY") {
			t.Errorf("fixture %s appears to contain private key material", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestCorpusGoldenFilesAreValidJSONAndSARIF checks every committed
// expected.json/expected.sarif that exists so far parses successfully and
// carries the expected schema markers, without requiring every case to
// have goldens yet (that is TestCorpusSuccessCasesHaveGoldenFiles's job).
func TestCorpusGoldenFilesAreValidJSONAndSARIF(t *testing.T) {
	cases, err := corpustest.Discover(corpusRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, c := range cases {
		jsonPath := filepath.Join(c.Dir, "expected.json")
		if data, readErr := os.ReadFile(jsonPath); readErr == nil {
			checked++
			if !json.Valid(data) {
				t.Errorf("case %s: expected.json is not valid JSON", c.ID)
			} else if !strings.Contains(string(data), `"schema_version":"2"`) && !strings.Contains(string(data), `"schema_version": "2"`) {
				t.Errorf("case %s: expected.json does not declare schema_version 2", c.ID)
			}
		}
		sarifPath := filepath.Join(c.Dir, "expected.sarif")
		if data, readErr := os.ReadFile(sarifPath); readErr == nil {
			checked++
			if !json.Valid(data) {
				t.Errorf("case %s: expected.sarif is not valid JSON", c.ID)
			} else if !strings.Contains(string(data), `"2.1.0"`) {
				t.Errorf("case %s: expected.sarif does not declare SARIF version 2.1.0", c.ID)
			}
		}
	}
	if checked == 0 {
		t.Skip("no golden files exist yet to validate")
	}
}

// TestCorpusCanariesAbsentFromCommittedGoldens re-checks, at the
// repository-quality level, that every case's declared canaries are absent
// from whatever golden files currently exist — independent confirmation
// alongside the corpustest runner's own per-render check.
func TestCorpusCanariesAbsentFromCommittedGoldens(t *testing.T) {
	cases, err := corpustest.Discover(corpusRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		if len(c.Canaries) == 0 {
			continue
		}
		for _, name := range []string{"expected.json", "expected.sarif"} {
			data, readErr := os.ReadFile(filepath.Join(c.Dir, name))
			if readErr != nil {
				continue // golden not generated yet; not this test's concern
			}
			text := string(data)
			for _, canary := range c.Canaries {
				if strings.Contains(text, canary) {
					t.Errorf("case %s: %s contains a declared canary value", c.ID, name)
				}
			}
		}
	}
}

// TestCorpusCoverageDocumentReferencesRealCaseIDs ensures COVERAGE.md
// mentions every corpus case that actually exists, so the coverage matrix
// cannot silently drift out of sync with the corpus as cases are added.
func TestCorpusCoverageDocumentReferencesRealCaseIDs(t *testing.T) {
	root := corpusRoot(t)
	cases, err := corpustest.Discover(root)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(root, "COVERAGE.md"))
	if err != nil {
		t.Fatalf("read COVERAGE.md: %v", err)
	}
	document := string(data)
	for _, c := range cases {
		if !strings.Contains(document, c.ID) {
			t.Errorf("COVERAGE.md does not mention corpus case %q", c.ID)
		}
	}
}

// TestCorpusCoverageExceptionsAreWellFormed ensures every exception entry
// in coverage-exceptions.yaml carries all required fields and a unique ID,
// so an exception can never silently omit its justification or owner.
func TestCorpusCoverageExceptionsAreWellFormed(t *testing.T) {
	root := corpusRoot(t)
	data, err := os.ReadFile(filepath.Join(root, "coverage-exceptions.yaml"))
	if err != nil {
		t.Fatalf("read coverage-exceptions.yaml: %v", err)
	}
	var doc struct {
		Exceptions []struct {
			ID            string `yaml:"id"`
			UncoveredItem string `yaml:"uncovered_item"`
			Reason        string `yaml:"reason"`
			Owner         string `yaml:"owner"`
			BlocksV1      bool   `yaml:"blocks_v1"`
		} `yaml:"exceptions"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parse coverage-exceptions.yaml: %v", err)
	}
	seen := make(map[string]bool)
	for _, item := range doc.Exceptions {
		if item.ID == "" || item.UncoveredItem == "" || item.Reason == "" || item.Owner == "" {
			t.Errorf("coverage exception %+v is missing a required field", item)
		}
		if seen[item.ID] {
			t.Errorf("duplicate coverage exception id %q", item.ID)
		}
		seen[item.ID] = true
	}
}
