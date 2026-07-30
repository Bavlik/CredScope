package githubactions

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestActionMetadataFilenameGateRejectsInvalidPaths proves ParseActionMetadata
// receives one explicit metadata file and never searches a directory, picks
// a sibling file, or accepts an arbitrary YAML filename: the final path
// component must be exactly "action.yml" or "action.yaml" (case-sensitive),
// and the path itself must be a clean, repository-relative reference.
func TestActionMetadataFilenameGateRejectsInvalidPaths(t *testing.T) {
	cases := []struct {
		name string
		path string
	}{
		{"wrong_filename_metadata_yml", ".github/actions/deploy/metadata.yml"},
		{"wrong_extension_action_json", ".github/actions/deploy/action.json"},
		{"wrong_filename_workflow_yml", ".github/actions/deploy/workflow.yml"},
		{"directory_no_filename", ".github/actions/demo"},
		{"directory_trailing_slash", ".github/actions/demo/"},
		{"absolute_unix_path", "/etc/action.yml"},
		{"windows_drive_path", `C:\actions\deploy\action.yml`},
		{"windows_drive_forward_slash", "C:/actions/deploy/action.yml"},
		{"unc_path", `\\server\share\action.yml`},
		{"unc_path_forward_slash", "//server/share/action.yml"},
		{"backslash_path", `.github\actions\deploy\action.yml`},
		{"parent_traversal", "../action.yml"},
		{"embedded_traversal", ".github/actions/../../../etc/action.yml"},
		{"query_suffix", ".github/actions/deploy/action.yml?raw=1"},
		{"fragment_suffix", ".github/actions/deploy/action.yml#frag"},
		{"empty_path", ""},
	}
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".github", "actions", "deploy"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".github", "actions", "deploy", "action.yml"), []byte(minimalComposite), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New().ParseActionMetadata(context.Background(), root, tc.path); err == nil {
				t.Fatalf("expected rejection for path %q", tc.path)
			}
		})
	}
}

func TestActionMetadataFilenameGateAcceptsActionYml(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".github", "actions", "deploy"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".github", "actions", "deploy", "action.yml"), []byte(minimalComposite), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New().ParseActionMetadata(context.Background(), root, ".github/actions/deploy/action.yml"); err != nil {
		t.Fatalf("expected acceptance, got %v", err)
	}
}

func TestActionMetadataFilenameGateAcceptsActionYaml(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".github", "actions", "deploy"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".github", "actions", "deploy", "action.yaml"), []byte(minimalComposite), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New().ParseActionMetadata(context.Background(), root, ".github/actions/deploy/action.yaml"); err != nil {
		t.Fatalf("expected acceptance, got %v", err)
	}
}

func TestActionMetadataFilenameGateCaseSensitive(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".github", "actions", "deploy"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".github", "actions", "deploy", "Action.YML"), []byte(minimalComposite), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New().ParseActionMetadata(context.Background(), root, ".github/actions/deploy/Action.YML"); err == nil {
		t.Fatal("expected case-sensitive rejection of Action.YML")
	}
}

// --- Directory and file confinement (review item 4) ---

func TestActionMetadataRejectsSymlinkedMetadataFile(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, ".github", "actions", "deploy")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "real-action.yml")
	if err := os.WriteFile(target, []byte(minimalComposite), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "action.yml")
	if err := os.Symlink(target, link); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("creating symlinks requires privilege: %v", err)
		}
		t.Fatal(err)
	}
	if _, err := New().ParseActionMetadata(context.Background(), root, ".github/actions/deploy/action.yml"); err == nil {
		t.Fatal("expected rejection of a symlinked metadata file")
	}
}

func TestActionMetadataRejectsSymlinkedParentDirectory(t *testing.T) {
	root := t.TempDir()
	realDir := filepath.Join(root, "real")
	if err := os.MkdirAll(realDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(realDir, "action.yml"), []byte(minimalComposite), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "linked")
	if err := os.Symlink(realDir, link); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("creating symlinks requires privilege: %v", err)
		}
		t.Fatal(err)
	}
	if _, err := New().ParseActionMetadata(context.Background(), root, "linked/action.yml"); err == nil {
		t.Fatal("expected rejection when a parent directory component is a symlink")
	}
}

func TestActionMetadataRejectsRepositoryEscape(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "repository")
	if err := os.Mkdir(root, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(parent, "outside"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(parent, "outside", "action.yml"), []byte(minimalComposite), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New().ParseActionMetadata(context.Background(), root, "../outside/action.yml"); err == nil {
		t.Fatal("expected rejection of a repository-escaping path")
	}
}

func TestActionMetadataConfinementDoesNotMutateRootOrSourceFile(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, ".github", "actions", "deploy")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "action.yml")
	if err := os.WriteFile(path, []byte(minimalComposite), 0o600); err != nil {
		t.Fatal(err)
	}
	rootBefore := root
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New().ParseActionMetadata(context.Background(), root, ".github/actions/deploy/action.yml"); err != nil {
		t.Fatal(err)
	}
	if root != rootBefore {
		t.Fatal("repository root input must remain unchanged")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("source metadata file must remain unchanged")
	}
}
