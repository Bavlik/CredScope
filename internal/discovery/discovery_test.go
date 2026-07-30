package discovery

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

var defaultIncludes = []string{
	".github/workflows/*.yml", ".github/workflows/*.yaml",
	"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml",
}

func writeFixture(t *testing.T, root, relative, content string) string {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestFindDiscoversSupportedInputsInStableOrder(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "docker-compose.yml", "services: {}")
	writeFixture(t, root, ".github/workflows/z.yaml", "name: z")
	writeFixture(t, root, ".github/workflows/a.yml", "name: a")
	writeFixture(t, root, ".github/workflows/readme.txt", "ignored")

	finder, err := New(root, Options{Includes: defaultIncludes})
	if err != nil {
		t.Fatal(err)
	}
	first, err := finder.Find()
	if err != nil {
		t.Fatal(err)
	}
	second, err := finder.Find()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("discovery is not deterministic:\n%#v\n%#v", first, second)
	}
	if len(first) != 3 {
		t.Fatalf("got %d files, want 3: %#v", len(first), first)
	}
	got := make([]string, len(first))
	for i, file := range first {
		rel, relErr := filepath.Rel(root, file.Path)
		if relErr != nil {
			t.Fatal(relErr)
		}
		got[i] = filepath.ToSlash(rel)
	}
	want := []string{".github/workflows/a.yml", ".github/workflows/z.yaml", "docker-compose.yml"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("paths = %#v, want %#v", got, want)
	}
}

func TestFindSkipsCommonIgnoredDirectories(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "vendor/.github/workflows/ignored.yml", "name: ignored")
	writeFixture(t, root, "node_modules/.github/workflows/ignored.yml", "name: ignored")
	finder, err := New(root, Options{Includes: []string{"**/.github/workflows/*.yml"}})
	if err != nil {
		t.Fatal(err)
	}
	files, err := finder.Find()
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 0 {
		t.Fatalf("ignored directories produced files: %#v", files)
	}
}

func TestResolveFileRejectsPathTraversal(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "repository")
	if err := os.Mkdir(root, 0o750); err != nil {
		t.Fatal(err)
	}
	writeFixture(t, parent, "outside.json", "[]")
	finder, err := New(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := finder.ResolveFile("../outside.json"); err == nil || !strings.Contains(err.Error(), "outside repository root") {
		t.Fatalf("expected traversal rejection, got %v", err)
	}
}

func TestResolveFileRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	target := writeFixture(t, root, "target.json", "[]")
	link := filepath.Join(root, "link.json")
	if err := os.Symlink(target, link); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("creating symlinks requires privilege: %v", err)
		}
		t.Fatal(err)
	}
	finder, err := New(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := finder.ResolveFile("link.json"); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("expected symlink rejection, got %v", err)
	}
}

func TestFindRejectsOversizedSupportedInput(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "compose.yml", strings.Repeat("x", 33))
	finder, err := New(root, Options{Includes: defaultIncludes, MaxFileSize: 32})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := finder.Find(); err == nil || !strings.Contains(err.Error(), "exceeds maximum size") {
		t.Fatalf("expected oversized input error, got %v", err)
	}
}

func TestFindRejectsExcessiveSupportedInputCount(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, ".github/workflows/a.yml", "name: a")
	writeFixture(t, root, ".github/workflows/b.yml", "name: b")
	finder, err := New(root, Options{Includes: defaultIncludes, MaxFiles: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := finder.Find(); err == nil || !strings.Contains(err.Error(), "maximum of 1 files") {
		t.Fatalf("expected input-count limit, got %v", err)
	}
}

func TestNewRejectsUnsafePattern(t *testing.T) {
	if _, err := New(t.TempDir(), Options{Includes: []string{"../*.yml"}}); err == nil {
		t.Fatal("expected unsafe pattern error")
	}
}

func TestResolveDirectoryAcceptsRepositoryRoot(t *testing.T) {
	root := t.TempDir()
	finder, err := New(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := finder.ResolveDirectory(".")
	if err != nil {
		t.Fatal(err)
	}
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Clean(resolved) != filepath.Clean(realRoot) {
		t.Fatalf("resolved = %q, want repository root %q", resolved, realRoot)
	}
}

func TestResolveDirectoryAcceptsNestedDirectory(t *testing.T) {
	root := t.TempDir()
	nested := filepath.Join(root, ".github", "actions", "deploy")
	if err := os.MkdirAll(nested, 0o750); err != nil {
		t.Fatal(err)
	}
	finder, err := New(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := finder.ResolveDirectory(".github/actions/deploy")
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(resolved) != "deploy" {
		t.Fatalf("resolved = %q, want a path ending in deploy", resolved)
	}
}

func TestResolveDirectoryAcceptsHiddenDirectory(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".hidden", "action"), 0o750); err != nil {
		t.Fatal(err)
	}
	finder, err := New(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := finder.ResolveDirectory(".hidden/action"); err != nil {
		t.Fatalf("hidden directory should resolve: %v", err)
	}
}

func TestResolveDirectoryAcceptsDeeplyNestedDirectory(t *testing.T) {
	root := t.TempDir()
	deep := "a/b/c/d/e/f/g"
	if err := os.MkdirAll(filepath.Join(root, filepath.FromSlash(deep)), 0o750); err != nil {
		t.Fatal(err)
	}
	finder, err := New(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := finder.ResolveDirectory(deep); err != nil {
		t.Fatalf("deeply nested directory should resolve: %v", err)
	}
}

func TestResolveDirectoryRejectsNonexistentDirectory(t *testing.T) {
	root := t.TempDir()
	finder, err := New(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := finder.ResolveDirectory("does/not/exist"); err == nil {
		t.Fatal("expected error for nonexistent directory")
	}
}

func TestResolveDirectoryRejectsRegularFileTarget(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "action.yml", "name: x")
	finder, err := New(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := finder.ResolveDirectory("action.yml"); err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("expected not-a-directory rejection, got %v", err)
	}
}

func TestResolveDirectoryRejectsParentTraversal(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "repository")
	if err := os.Mkdir(root, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(parent, "outside"), 0o750); err != nil {
		t.Fatal(err)
	}
	finder, err := New(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := finder.ResolveDirectory("../outside"); err == nil || !strings.Contains(err.Error(), "outside repository root") {
		t.Fatalf("expected traversal rejection, got %v", err)
	}
}

func TestResolveDirectoryRejectsDeepParentTraversal(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "repository")
	if err := os.Mkdir(root, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(parent, "outside"), 0o750); err != nil {
		t.Fatal(err)
	}
	finder, err := New(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "a"), 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := finder.ResolveDirectory("a/../../outside"); err == nil || !strings.Contains(err.Error(), "outside repository root") {
		t.Fatalf("expected traversal rejection, got %v", err)
	}
}

func TestResolveDirectoryRejectsAbsoluteUnixPath(t *testing.T) {
	root := t.TempDir()
	finder, err := New(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := finder.ResolveDirectory("/etc/action"); err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("expected absolute-path rejection, got %v", err)
	}
}

func TestResolveDirectoryRejectsWindowsDrivePath(t *testing.T) {
	root := t.TempDir()
	finder, err := New(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := finder.ResolveDirectory(`C:\actions\deploy`); err == nil {
		t.Fatal("expected drive-letter path rejection")
	}
}

func TestResolveDirectoryRejectsUNCPath(t *testing.T) {
	root := t.TempDir()
	finder, err := New(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := finder.ResolveDirectory(`//server/share/action`); err == nil || !strings.Contains(err.Error(), "UNC") {
		t.Fatalf("expected UNC-path rejection, got %v", err)
	}
}

func TestResolveDirectoryRejectsBackslashPath(t *testing.T) {
	root := t.TempDir()
	finder, err := New(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := finder.ResolveDirectory(`.github\actions\deploy`); err == nil || !strings.Contains(err.Error(), "backslash") {
		t.Fatalf("expected backslash rejection, got %v", err)
	}
}

func TestResolveDirectoryRejectsNUL(t *testing.T) {
	root := t.TempDir()
	finder, err := New(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := finder.ResolveDirectory("action\x00dir"); err == nil || !strings.Contains(err.Error(), "NUL") {
		t.Fatalf("expected NUL rejection, got %v", err)
	}
}

func TestResolveDirectoryRejectsSymlinkedIntermediateDirectory(t *testing.T) {
	root := t.TempDir()
	realDir := filepath.Join(root, "real")
	if err := os.MkdirAll(filepath.Join(realDir, "action"), 0o750); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "linked")
	if err := os.Symlink(realDir, link); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("creating symlinks requires privilege: %v", err)
		}
		t.Fatal(err)
	}
	finder, err := New(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := finder.ResolveDirectory("linked/action"); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("expected symlink rejection for intermediate component, got %v", err)
	}
}

func TestResolveDirectoryRejectsSymlinkedFinalDirectory(t *testing.T) {
	root := t.TempDir()
	realDir := filepath.Join(root, "real-action")
	if err := os.MkdirAll(realDir, 0o750); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "action-link")
	if err := os.Symlink(realDir, link); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("creating symlinks requires privilege: %v", err)
		}
		t.Fatal(err)
	}
	finder, err := New(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := finder.ResolveDirectory("action-link"); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("expected symlink rejection for final directory, got %v", err)
	}
}

// ResolveDirectory must preserve Linux-style exact-case semantics on every
// platform, including Windows and macOS where the default filesystem is
// case-insensitive. A directory-component case mismatch must behave exactly
// like the component not existing at all (fs.ErrNotExist), never a silent
// case-insensitive match.
func TestResolveDirectoryRequiresExactCase(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "Actions", "Deploy"), 0o750); err != nil {
		t.Fatal(err)
	}
	finder, err := New(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := finder.ResolveDirectory("actions/deploy"); err == nil {
		t.Fatal("expected case-mismatched path to be rejected")
	} else if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("expected fs.ErrNotExist for a case mismatch, got %v", err)
	}
	resolved, err := finder.ResolveDirectory("Actions/Deploy")
	if err != nil {
		t.Fatalf("exact-case path must resolve: %v", err)
	}
	if filepath.Base(resolved) != "Deploy" {
		t.Fatalf("resolved = %q, want a path ending in Deploy", resolved)
	}
}

// A case mismatch on only one of two nested components must still be
// rejected as fs.ErrNotExist, regardless of which component mismatches.
func TestResolveDirectoryRequiresExactCasePerComponent(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "Actions", "Deploy"), 0o750); err != nil {
		t.Fatal(err)
	}
	finder, err := New(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := finder.ResolveDirectory("actions/Deploy"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("first-component mismatch: expected fs.ErrNotExist, got %v", err)
	}
	if _, err := finder.ResolveDirectory("Actions/deploy"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("second-component mismatch: expected fs.ErrNotExist, got %v", err)
	}
}

// A directory that genuinely does not exist must also be reported as
// fs.ErrNotExist through a typed check, not fragile error-string matching.
func TestResolveDirectoryNonexistentIsErrNotExist(t *testing.T) {
	root := t.TempDir()
	finder, err := New(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := finder.ResolveDirectory("does/not/exist"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("expected fs.ErrNotExist, got %v", err)
	}
}

func TestResolveDirectoryIsDeterministic(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".github", "actions", "deploy"), 0o750); err != nil {
		t.Fatal(err)
	}
	finder, err := New(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	first, err := finder.ResolveDirectory(".github/actions/deploy")
	if err != nil {
		t.Fatal(err)
	}
	second, err := finder.ResolveDirectory(".github/actions/deploy")
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("repeated resolution differs: %q vs %q", first, second)
	}
}

func TestResolveDirectoryDoesNotMutateRootInput(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "action"), 0o750); err != nil {
		t.Fatal(err)
	}
	rootBefore := root
	finder, err := New(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := finder.ResolveDirectory("action"); err != nil {
		t.Fatal(err)
	}
	if root != rootBefore {
		t.Fatal("root input string must remain unchanged")
	}
}

func TestUniqueFilesDeduplicatesWindowsStyleCase(t *testing.T) {
	input := []File{
		{Path: `C:\repo\compose.yml`, Kind: KindCompose},
		{Path: `c:\REPO\compose.yml`, Kind: KindCompose},
	}
	got := UniqueFiles(input)
	if len(got) != 1 {
		t.Fatalf("got %d files, want 1", len(got))
	}
}

func TestUniqueFilesPreservesDistinctPOSIXCase(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows filesystems use case-insensitive path identity")
	}
	input := []File{
		{Path: "/repo/A.yml", Kind: KindGitHubActions},
		{Path: "/repo/a.yml", Kind: KindGitHubActions},
	}
	if got := UniqueFiles(input); len(got) != 2 {
		t.Fatalf("got %d files, want 2", len(got))
	}
}
