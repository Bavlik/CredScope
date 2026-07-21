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
