package corpustest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// These tests exercise Manifest.Validate and Discover's structural safety
// checks in isolation, against small synthetic fixtures. They never invoke
// Execute or the analysis pipeline, so they stay fast and independent of
// whatever platform-specific build/execution constraints affect the full
// corpus run.

func newCaseDir(t *testing.T, root, category, id string) string {
	t.Helper()
	dir := filepath.Join(root, category, id)
	mustMkdirAll(t, filepath.Join(dir, "repository"))
	mustWriteFile(t, filepath.Join(dir, "repository", "README.md"), "placeholder\n")
	mustWriteFile(t, filepath.Join(dir, "README.md"), "# "+id+"\n")
	return dir
}

func TestValidateRejectsPathTraversalInRepository(t *testing.T) {
	root := t.TempDir()
	dir := newCaseDir(t, root, "gitleaks", "traversal-case")
	manifest, err := parseManifestString(minimalManifestYAML("traversal-case", "success", "") + "")
	if err != nil {
		t.Fatal(err)
	}
	manifest.Inputs.Repository = "../../escape"
	if err := manifest.Validate(dir, CategoryGitleaks); err == nil {
		t.Fatal("expected parent-traversal repository path to be rejected")
	} else if !strings.Contains(err.Error(), "escapes the case directory") {
		t.Fatalf("expected an escapes-the-case-directory error, got: %v", err)
	}
}

func TestValidateRejectsAbsolutePathInGitleaksInput(t *testing.T) {
	root := t.TempDir()
	dir := newCaseDir(t, root, "gitleaks", "absolute-case")
	manifest, err := parseManifestString(minimalManifestYAML("absolute-case", "success", ""))
	if err != nil {
		t.Fatal(err)
	}
	manifest.Inputs.Gitleaks = `C:\Windows\System32\config\SAM`
	manifest.Canaries = []string{"CREDSCOPE_TEST_CANARY_UNUSED"}
	if err := manifest.Validate(dir, CategoryGitleaks); err == nil {
		t.Fatal("expected an absolute gitleaks input path to be rejected")
	} else if !strings.Contains(err.Error(), "case-relative") {
		t.Fatalf("expected a case-relative error, got: %v", err)
	}
}

func TestValidateRejectsSymlinkedRepositoryInput(t *testing.T) {
	root := t.TempDir()
	dir := newCaseDir(t, root, "gitleaks", "symlink-case")
	outsideTarget := filepath.Join(root, "outside-target")
	mustMkdirAll(t, outsideTarget)
	linkPath := filepath.Join(dir, "linked-repository")
	if err := os.Symlink(outsideTarget, linkPath); err != nil {
		t.Skipf("symlink creation unsupported in this environment: %v", err)
	}
	manifest, err := parseManifestString(minimalManifestYAML("symlink-case", "success", ""))
	if err != nil {
		t.Fatal(err)
	}
	manifest.Inputs.Repository = "linked-repository"
	if err := manifest.Validate(dir, CategoryGitleaks); err == nil {
		t.Fatal("expected a symlinked repository input to be rejected")
	} else if !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("expected a symbolic-link error, got: %v", err)
	}
}

func TestValidateRequiresCanaryWhenGitleaksReportHasSecret(t *testing.T) {
	root := t.TempDir()
	dir := newCaseDir(t, root, "gitleaks", "needs-canary-case")
	mustWriteFile(t, filepath.Join(dir, "gitleaks.json"), `[{"RuleID":"demo","Secret":"CREDSCOPE_TEST_CANARY_REQUIRED","File":"a.env"}]`)
	manifest, err := parseManifestString(minimalManifestYAML("needs-canary-case", "success", ""))
	if err != nil {
		t.Fatal(err)
	}
	manifest.Inputs.Gitleaks = "gitleaks.json"
	if err := manifest.Validate(dir, CategoryGitleaks); err == nil {
		t.Fatal("expected validation to require a declared canary")
	} else if !strings.Contains(err.Error(), "forbidden_output_strings must declare") {
		t.Fatalf("expected a missing-canary error, got: %v", err)
	}
	manifest.Canaries = []string{"CREDSCOPE_TEST_CANARY_REQUIRED"}
	if err := manifest.Validate(dir, CategoryGitleaks); err != nil {
		t.Fatalf("declaring the canary should satisfy validation: %v", err)
	}
}

func TestValidateAllowsMissingCanaryWhenGitleaksReportHasNoSecret(t *testing.T) {
	root := t.TempDir()
	dir := newCaseDir(t, root, "gitleaks", "no-secret-case")
	mustWriteFile(t, filepath.Join(dir, "gitleaks.json"), `[{"RuleID":"demo","File":"a.env","StartLine":1}]`)
	manifest, err := parseManifestString(minimalManifestYAML("no-secret-case", "success", ""))
	if err != nil {
		t.Fatal(err)
	}
	manifest.Inputs.Gitleaks = "gitleaks.json"
	if err := manifest.Validate(dir, CategoryGitleaks); err != nil {
		t.Fatalf("no Secret/Match field present, canary should not be required: %v", err)
	}
}

func TestValidateRejectsEmptyDescription(t *testing.T) {
	root := t.TempDir()
	dir := newCaseDir(t, root, "gitleaks", "empty-description-case")
	manifest, err := parseManifestString(minimalManifestYAML("empty-description-case", "success", ""))
	if err != nil {
		t.Fatal(err)
	}
	manifest.Description = "   "
	if err := manifest.Validate(dir, CategoryGitleaks); err == nil {
		t.Fatal("expected an empty description to be rejected")
	}
}

func TestValidateRejectsUnsupportedSchemaVersion(t *testing.T) {
	root := t.TempDir()
	dir := newCaseDir(t, root, "gitleaks", "bad-schema-case")
	manifest, err := parseManifestString(minimalManifestYAML("bad-schema-case", "success", ""))
	if err != nil {
		t.Fatal(err)
	}
	manifest.SchemaVersion = 99
	if err := manifest.Validate(dir, CategoryGitleaks); err == nil {
		t.Fatal("expected an unsupported schema_version to be rejected")
	} else if !strings.Contains(err.Error(), "schema_version") {
		t.Fatalf("expected a schema_version error, got: %v", err)
	}
}

func TestValidateRejectsCategoryMismatch(t *testing.T) {
	root := t.TempDir()
	dir := newCaseDir(t, root, "gitleaks", "wrong-category-case")
	manifest, err := parseManifestString(minimalManifestYAML("wrong-category-case", "success", ""))
	if err != nil {
		t.Fatal(err)
	}
	manifest.Category = CategoryCompose // directory is under gitleaks/
	if err := manifest.Validate(dir, CategoryGitleaks); err == nil {
		t.Fatal("expected a category/directory mismatch to be rejected")
	}
}

func TestValidateRejectsIDDirectoryMismatch(t *testing.T) {
	root := t.TempDir()
	dir := newCaseDir(t, root, "gitleaks", "actual-dir-name")
	manifest, err := parseManifestString(minimalManifestYAML("declared-different-id", "success", ""))
	if err != nil {
		t.Fatal(err)
	}
	if err := manifest.Validate(dir, CategoryGitleaks); err == nil {
		t.Fatal("expected id/directory-name mismatch to be rejected")
	} else if !strings.Contains(err.Error(), "must match directory name") {
		t.Fatalf("expected an id/directory mismatch error, got: %v", err)
	}
}

func TestLoadManifestRejectsMalformedYAML(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "case.yaml")
	mustWriteFile(t, path, "id: [unterminated\n")
	if _, err := LoadManifest(path); err == nil {
		t.Fatal("expected malformed YAML to be rejected")
	}
}

func TestLoadManifestRejectsUnknownFields(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "case.yaml")
	mustWriteFile(t, path, minimalManifestYAML("unknown-field-case", "success", "")+"unknown_field: true\n")
	if _, err := LoadManifest(path); err == nil {
		t.Fatal("expected an unknown top-level field to be rejected by strict decoding")
	}
}

func TestDiscoverRejectsDuplicateCaseIDAcrossCategories(t *testing.T) {
	root := t.TempDir()
	writeMinimalCase(t, root, "same-id", true)
	// Reuse the same ID under a different category directory to force a
	// cross-category collision, which Manifest.Validate's own id==dirname
	// check cannot catch on its own (each individual manifest is locally
	// self-consistent; only cross-case discovery can see the collision).
	dir := filepath.Join(root, "compose", "same-id")
	mustMkdirAll(t, filepath.Join(dir, "repository"))
	mustWriteFile(t, filepath.Join(dir, "repository", "README.md"), "placeholder\n")
	mustWriteFile(t, filepath.Join(dir, "README.md"), "# same-id\n")
	manifest := strings.Replace(minimalManifestYAML("same-id", "success", ""), "category: gitleaks", "category: compose", 1)
	mustWriteFile(t, filepath.Join(dir, "case.yaml"), manifest)

	if _, err := Discover(root); err == nil {
		t.Fatal("expected duplicate case id across categories to be rejected")
	} else if !strings.Contains(err.Error(), "duplicate case id") {
		t.Fatalf("expected a duplicate-case-id error, got: %v", err)
	}
}

// parseManifestString decodes a manifest YAML document the same way
// LoadManifest does, without requiring it to already live on disk at a
// specific path — useful for building a base manifest a test then mutates
// before calling Validate directly.
func parseManifestString(yamlDoc string) (Manifest, error) {
	root := os.TempDir()
	path := filepath.Join(root, "credscope-corpustest-manifest-fragment.yaml")
	if err := os.WriteFile(path, []byte(yamlDoc), 0o644); err != nil {
		return Manifest{}, err
	}
	defer os.Remove(path)
	return LoadManifest(path)
}
