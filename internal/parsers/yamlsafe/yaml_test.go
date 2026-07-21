package yamlsafe

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func FuzzBoundedYAMLValidation(f *testing.F) {
	f.Add([]byte("name: demo\njobs:\n  test:\n    runs-on: ubuntu-latest\n"))
	f.Add([]byte("a: &a [1, 2]\nb: *a\n"))
	f.Add([]byte("a: ["))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		var document yaml.Node
		if err := yaml.NewDecoder(bytes.NewReader(data)).Decode(&document); err != nil {
			return
		}
		state := validationState{active: make(map[*yaml.Node]bool)}
		_ = state.validate(&document, 0)
		if state.nodes > MaxNodes+1 || state.aliases > MaxAliases+1 {
			t.Fatalf("validator exceeded its stop boundary: nodes=%d aliases=%d", state.nodes, state.aliases)
		}
	})
}

func TestParseRejectsExcessiveDepth(t *testing.T) {
	root := t.TempDir()
	var content strings.Builder
	for i := 0; i < MaxDepth+5; i++ {
		content.WriteString(strings.Repeat("  ", i) + "level:\n")
	}
	content.WriteString(strings.Repeat("  ", MaxDepth+5) + "end: true\n")
	path := filepath.Join(root, "deep.yml")
	if err := os.WriteFile(path, []byte(content.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err := Parse(root, path)
	var parseErr *ParseError
	if !errors.As(err, &parseErr) || parseErr.Kind != ErrorComplexity {
		t.Fatalf("expected complexity error, got %v", err)
	}
}

func TestMalformedFixtureExceedsDepthLimit(t *testing.T) {
	root := filepath.Join("..", "..", "..", "testdata", "malformed")
	_, _, err := Parse(root, "deep.yml")
	var parseErr *ParseError
	if !errors.As(err, &parseErr) || parseErr.Kind != ErrorComplexity {
		t.Fatalf("expected fixture complexity error, got %v", err)
	}
}

func TestParseRejectsAliasAbuse(t *testing.T) {
	root := t.TempDir()
	content := "base: &base\n  value: demo\nitems:\n" + strings.Repeat("  - *base\n", MaxAliases+1)
	path := filepath.Join(root, "aliases.yml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err := Parse(root, path)
	var parseErr *ParseError
	if !errors.As(err, &parseErr) || parseErr.Kind != ErrorComplexity {
		t.Fatalf("expected alias limit error, got %v", err)
	}
}

func TestParseRejectsOversizedInput(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "large.yml")
	content := append([]byte("value: "), []byte(strings.Repeat("x", 10<<20))...)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err := Parse(root, path)
	if err == nil || !strings.Contains(err.Error(), "exceeds maximum size") {
		t.Fatalf("expected size error, got %v", err)
	}
}

func TestParseRejectsMultipleDocuments(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "multiple.yml")
	if err := os.WriteFile(path, []byte("a: 1\n---\nb: 2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err := Parse(root, path)
	if err == nil || !strings.Contains(err.Error(), "multiple YAML documents") {
		t.Fatalf("expected document error, got %v", err)
	}
}

func TestParseRejectsPathTraversal(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "repository")
	if err := os.Mkdir(root, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(parent, "outside.yml"), []byte("safe: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err := Parse(root, "../outside.yml")
	if err == nil || !strings.Contains(err.Error(), "outside repository root") {
		t.Fatalf("expected confinement error, got %v", err)
	}
}

func TestParseRejectsDuplicateKeys(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "duplicate.yml")
	if err := os.WriteFile(path, []byte("value: one\nvalue: two\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err := Parse(root, path)
	var parseErr *ParseError
	if !errors.As(err, &parseErr) || parseErr.Kind != ErrorStructure {
		t.Fatalf("expected structure error, got %v", err)
	}
}
