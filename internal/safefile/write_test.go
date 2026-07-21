package safefile

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestWriteReportUsesOwnerOnlyPermissions(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "report.json")
	if err := WriteReport(root, path, []byte("safe")); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "safe" {
		t.Fatalf("report = %q", data)
	}
	if runtime.GOOS != "windows" {
		info, statErr := os.Stat(path)
		if statErr != nil {
			t.Fatal(statErr)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Fatalf("permissions = %o, want 600", got)
		}
	}
}

func TestWriteReportSafelyReplacesRegularFile(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "report.json")
	if err := os.WriteFile(path, []byte("previous"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := WriteReport(root, path, []byte("replacement")); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "replacement" {
		t.Fatalf("report = %q", data)
	}
	backups, err := filepath.Glob(filepath.Join(root, ".credscope-previous-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(backups) != 0 {
		t.Fatalf("backup files remain: %#v", backups)
	}
}

func TestWriteReportCreatesConfinedParentDirectories(t *testing.T) {
	root := t.TempDir()
	destination := filepath.FromSlash("reports/nested/report.json")
	if err := WriteReport(root, destination, []byte("safe")); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(root, destination))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "safe" {
		t.Fatalf("report = %q", data)
	}
	if runtime.GOOS != "windows" {
		for _, directory := range []string{"reports", filepath.Join("reports", "nested")} {
			info, statErr := os.Stat(filepath.Join(root, directory))
			if statErr != nil {
				t.Fatal(statErr)
			}
			if got := info.Mode().Perm(); got != 0o700 {
				t.Fatalf("directory %s permissions = %o, want 700", directory, got)
			}
		}
	}
}

func TestWriteReportAcceptsWindowsSeparatorsOnWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows path semantics")
	}
	root := t.TempDir()
	if err := WriteReport(root, `reports\nested\report.json`, []byte("safe")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "reports", "nested", "report.json")); err != nil {
		t.Fatal(err)
	}
}

func TestWriteReportRejectsTraversal(t *testing.T) {
	root := t.TempDir()
	if err := WriteReport(root, "../outside.json", []byte("unsafe")); err == nil || !strings.Contains(err.Error(), "outside repository root") {
		t.Fatalf("expected traversal error, got %v", err)
	}
}

func TestWriteReportProtectedRejectsInputOverwrite(t *testing.T) {
	root := t.TempDir()
	input := filepath.Join(root, "compose.yml")
	if err := os.WriteFile(input, []byte("services: {}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteReportProtected(root, "compose.yml", []byte("report"), []string{input}); err == nil || !strings.Contains(err.Error(), "overwrite an analysis input") {
		t.Fatalf("error = %v", err)
	}
	data, err := os.ReadFile(input)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "services: {}" {
		t.Fatal("protected input changed")
	}
}

func TestWriteReportRejectsSymlinkDestination(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target.json")
	if err := os.WriteFile(target, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "report.json")
	if err := os.Symlink(target, link); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("creating symlinks requires privilege: %v", err)
		}
		t.Fatal(err)
	}
	if err := WriteReport(root, link, []byte("replacement")); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("expected symlink error, got %v", err)
	}
	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "original" {
		t.Fatal("symlink target was modified")
	}
}

func TestWriteReportRejectsSymlinkParent(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	link := filepath.Join(root, "reports")
	if err := os.Symlink(outside, link); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("creating symlinks requires privilege: %v", err)
		}
		t.Fatal(err)
	}
	err := WriteReport(root, filepath.Join("reports", "report.json"), []byte("unsafe"))
	if err == nil || !strings.Contains(err.Error(), "symbolic link or reparse point") {
		t.Fatalf("expected linked-parent error, got %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(outside, "report.json")); !os.IsNotExist(statErr) {
		t.Fatalf("outside report was created: %v", statErr)
	}
}

func FuzzWriteReportPathConfinement(f *testing.F) {
	for _, seed := range []string{"report.json", "reports/nested/report.json", "../outside.json", `C:\outside.json`, "reports/..", "semi;colon.json", "dollar$(noop).json"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, destination string) {
		if len(destination) > 256 || strings.ContainsRune(destination, 0) {
			t.Skip()
		}
		root := t.TempDir()
		err := WriteReport(root, destination, []byte("safe"))
		if err != nil {
			return
		}
		candidate := destination
		if !filepath.IsAbs(candidate) {
			candidate = filepath.Join(root, candidate)
		}
		absolute, absErr := filepath.Abs(candidate)
		if absErr != nil {
			t.Fatal(absErr)
		}
		relative, relErr := filepath.Rel(root, absolute)
		if relErr != nil || relative == ".." || strings.HasPrefix(filepath.ToSlash(relative), "../") {
			t.Fatalf("successful write escaped root: %q", destination)
		}
	})
}
