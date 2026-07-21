package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func executeCommand(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	cmd := NewRootCommand(BuildInfo{Version: "v0.1.0-test", Commit: "abc", Date: "today"}, &stdout, &stderr)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return stdout.String() + stderr.String(), err
}

func TestVersionCommand(t *testing.T) {
	output, err := executeCommand(t, "version")
	if err != nil {
		t.Fatal(err)
	}
	if output != "CredScope v0.1.0-test (commit abc, built today)\n" {
		t.Fatalf("output = %q", output)
	}
}

func TestRulesAreSortedAndExplainable(t *testing.T) {
	output, err := executeCommand(t, "rules", "list")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Index(output, "CRD101") > strings.Index(output, "CRD401") {
		t.Fatalf("rules not sorted: %s", output)
	}
	output, err = executeCommand(t, "explain", "crd101")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output, "CRD101 — Credential finding imported") {
		t.Fatalf("unexpected explanation: %s", output)
	}
}

func TestFoundationScanDiscoversFiles(t *testing.T) {
	root := t.TempDir()
	workflow := filepath.Join(root, ".github", "workflows", "ci.yml")
	if err := os.MkdirAll(filepath.Dir(workflow), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(workflow, []byte("name: CI"), 0o600); err != nil {
		t.Fatal(err)
	}
	output, err := executeCommand(t, "scan", root)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output, "github-actions  .github/workflows/ci.yml") {
		t.Fatalf("input missing from output: %s", output)
	}
}

func TestCLIOverridesConfiguration(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, ".credscope.yml")
	content := "version: 1\nrisk:\n  fail_on: low\n  minimum_score: 10\noutput:\n  verbose: true\n"
	if err := os.WriteFile(configPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	output, err := executeCommand(t, "scan", root, "--fail-on", "critical", "--minimum-score", "90")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output, "fail-on=critical minimum-score=90") {
		t.Fatalf("CLI did not override config: %s", output)
	}
}

func TestMalformedConfigurationUsesUsageExitClass(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, ".credscope.yml")
	if err := os.WriteFile(configPath, []byte("version: 99\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := executeCommand(t, "scan", root)
	var coded *codedError
	if !errors.As(err, &coded) || coded.code != ExitUsage {
		t.Fatalf("error = %#v, want usage coded error", err)
	}
}

func TestGitleaksPathTraversalUsesMalformedInputExitClass(t *testing.T) {
	root := t.TempDir()
	_, err := executeCommand(t, "scan", root, "--gitleaks-report", "../outside.json")
	var coded *codedError
	if !errors.As(err, &coded) || coded.code != ExitMalformedInput {
		t.Fatalf("error = %#v, want malformed-input coded error", err)
	}
}

func TestUnknownRuleDoesNotEchoTerminalControls(t *testing.T) {
	_, err := executeCommand(t, "explain", "BAD\x1b[31m")
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), "\x1b") {
		t.Fatalf("error contains terminal control: %q", err)
	}
}
