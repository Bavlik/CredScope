package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func executeCommand(t *testing.T, args ...string) (string, error) {
	t.Helper()
	stdout, stderr, err := executeCommandSeparate(t, args...)
	return stdout + stderr, err
}

func executeCommandSeparate(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	fixed := func() time.Time { return time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC) }
	cmd := newRootCommand(BuildInfo{Version: "v0.1.0-test", Commit: "abc", Date: "today"}, &stdout, &stderr, fixed)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return stdout.String(), stderr.String(), err
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

func TestDefaultScanRunsCompleteEmptyPipeline(t *testing.T) {
	root := t.TempDir()
	workflow := filepath.Join(root, ".github", "workflows", "ci.yml")
	if err := os.MkdirAll(filepath.Dir(workflow), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(workflow, []byte("name: CI\non: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	output, err := executeCommand(t, "scan", root)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output, "Credentials analyzed: 0") || !strings.Contains(output, "No credential blast-radius paths were identified") {
		t.Fatalf("analysis summary missing: %s", output)
	}
}

func TestScanRejectsMalformedDiscoveredWorkflow(t *testing.T) {
	root := t.TempDir()
	workflow := filepath.Join(root, ".github", "workflows", "bad.yml")
	if err := os.MkdirAll(filepath.Dir(workflow), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(workflow, []byte("name: bad\njobs: [broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := executeCommand(t, "scan", root)
	var coded *codedError
	if !errors.As(err, &coded) || coded.code != ExitMalformedInput {
		t.Fatalf("error = %#v, want malformed-input coded error", err)
	}
}

func TestScanRejectsInvalidReporterFormatBeforeAnalysis(t *testing.T) {
	root := t.TempDir()
	bad := filepath.Join(root, ".github", "workflows", "bad.yml")
	if err := os.MkdirAll(filepath.Dir(bad), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bad, []byte("malformed: ["), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := executeCommand(t, "scan", root, "--format", "xml")
	var coded *codedError
	if !errors.As(err, &coded) || coded.code != ExitUsage {
		t.Fatalf("error = %#v, want usage coded error", err)
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
	if !strings.Contains(output, "Threshold: fail-on=critical minimum-score=90") {
		t.Fatalf("CLI did not override config: %s", output)
	}
}

func TestAllFormatsUseCompleteCriticalAnalysisAndCleanStdout(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", "testdata", "vulnerable"))
	if err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"terminal", "json", "sarif", "html", "mermaid"} {
		t.Run(format, func(t *testing.T) {
			stdout, stderr, scanErr := executeCommandSeparate(t, "scan", root, "--gitleaks-report", "gitleaks.json", "--format", format, "--no-color")
			if scanErr != nil {
				t.Fatal(scanErr)
			}
			if stderr != "" {
				t.Fatalf("stderr polluted: %q", stderr)
			}
			knownRawOne := "FAKE_RAW_" + "SECRET_FOR_TESTS_ONLY"
			knownRawTwo := "DEMO_DATABASE_PASSWORD_" + "VALUE_FOR_TESTS_ONLY"
			if strings.Contains(stdout, knownRawOne) || strings.Contains(stdout, knownRawTwo) {
				t.Fatal("raw secret leaked")
			}
			if !strings.Contains(stdout, "CRD304") || !strings.Contains(stdout, "FAKE_PRODUCTION_TOKEN") {
				t.Fatalf("format %s omitted common score/rule identity", format)
			}
			switch format {
			case "terminal":
				if !strings.Contains(stdout, "CRITICAL - FAKE_PRODUCTION_TOKEN") {
					t.Fatal(stdout)
				}
			case "json":
				var doc struct {
					Schema  string `json:"schema_version"`
					Summary struct {
						Critical int `json:"critical"`
					} `json:"summary"`
				}
				if json.Unmarshal([]byte(stdout), &doc) != nil || doc.Schema != "1" || doc.Summary.Critical == 0 {
					t.Fatal(stdout)
				}
			case "sarif":
				var doc struct {
					Version string `json:"version"`
				}
				if json.Unmarshal([]byte(stdout), &doc) != nil || doc.Version != "2.1.0" {
					t.Fatal(stdout)
				}
			case "html":
				if !strings.HasPrefix(stdout, "<!doctype html>") || !strings.Contains(stdout, "FAKE_PRODUCTION_TOKEN") {
					t.Fatal(stdout)
				}
			case "mermaid":
				if !strings.Contains(stdout, "```mermaid") || !strings.Contains(stdout, "FAKE_PRODUCTION_TOKEN") {
					t.Fatal(stdout)
				}
			}
		})
	}
}

func TestOutputFileThresholdAndMinimumScoreExitClasses(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", "testdata", "vulnerable", "write-all"))
	if err != nil {
		t.Fatal(err)
	}
	_, _, thresholdErr := executeCommandSeparate(t, "scan", root, "--format", "json", "--fail-on", "high")
	var coded *codedError
	if !errors.As(thresholdErr, &coded) || coded.code != ExitThreshold || !coded.silent {
		t.Fatalf("threshold error = %#v", thresholdErr)
	}
	_, _, noThresholdErr := executeCommandSeparate(t, "scan", root, "--format", "json", "--fail-on", "critical", "--minimum-score", "101")
	var usage *codedError
	if !errors.As(noThresholdErr, &usage) || usage.code != ExitUsage {
		t.Fatalf("minimum score error = %#v", noThresholdErr)
	}
	stdout, _, noThresholdErr := executeCommandSeparate(t, "scan", root, "--format", "json", "--fail-on", "critical", "--minimum-score", "100")
	if noThresholdErr == nil {
		t.Fatal("critical score 100 should exceed threshold")
	}
	if stdout == "" {
		t.Fatal("report must be emitted before threshold exit")
	}
}

func TestSecureOutputFileAndInputOverwriteProtection(t *testing.T) {
	root := t.TempDir()
	workflow := filepath.Join(root, ".github", "workflows", "ci.yml")
	if err := os.MkdirAll(filepath.Dir(workflow), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(workflow, []byte("name: CI\non: push\npermissions: read-all\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, err := executeCommandSeparate(t, "scan", root, "--format", "json", "--output", "report.json")
	if err != nil || stdout != "" || stderr != "" {
		t.Fatalf("stdout=%q stderr=%q err=%v", stdout, stderr, err)
	}
	data, err := os.ReadFile(filepath.Join(root, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(data) {
		t.Fatal("output is not JSON")
	}
	_, _, overwriteErr := executeCommandSeparate(t, "scan", root, "--output", filepath.ToSlash(filepath.Join(".github", "workflows", "ci.yml")))
	var coded *codedError
	if !errors.As(overwriteErr, &coded) || coded.code != ExitInternal {
		t.Fatalf("expected protected output error: %v", overwriteErr)
	}
}

func TestQuietVerboseNoColorAndReportFailure(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", "testdata", "vulnerable", "development"))
	if err != nil {
		t.Fatal(err)
	}
	quiet, _, err := executeCommandSeparate(t, "scan", root, "--quiet", "--no-color")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(quiet, "Scoring policy:") || strings.Contains(quiet, "\x1b") {
		t.Fatalf("quiet/no-color failed: %s", quiet)
	}
	verbose, _, err := executeCommandSeparate(t, "scan", root, "--verbose", "--no-color")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(verbose, "Score breakdown:") || !strings.Contains(verbose, ".github/workflows/development.yml") {
		t.Fatalf("verbose evidence missing: %s", verbose)
	}
	_, _, renderErr := executeCommandSeparate(t, "scan", root, "--output", ".")
	var coded *codedError
	if !errors.As(renderErr, &coded) || coded.code != ExitInternal {
		t.Fatalf("report failure = %#v", renderErr)
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
