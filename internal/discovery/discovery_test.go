package discovery

import (
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

func TestNewRejectsUnsafePattern(t *testing.T) {
	if _, err := New(t.TempDir(), Options{Includes: []string{"../*.yml"}}); err == nil {
		t.Fatal("expected unsafe pattern error")
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
