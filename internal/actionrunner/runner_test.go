package actionrunner

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestArgumentsPreserveSpacesAndShellMetacharacters(t *testing.T) {
	input := Inputs{Path: "repo with spaces;touch injected", GitleaksReport: "reports/gitleaks file.json", Config: "config files/safe.yml", Format: "sarif", Output: "reports/result file.sarif", FailOn: "high", MinimumScore: 40, Verbose: true, NoColor: true}
	want := []string{"scan", input.Path, "--gitleaks-report", input.GitleaksReport, "--config", input.Config, "--format", "sarif", "--fail-on", "high", "--minimum-score", "40", "--output", input.Output, "--verbose=true", "--no-color=true"}
	if got := Arguments(input); !reflect.DeepEqual(got, want) {
		t.Fatalf("arguments = %#v, want %#v", got, want)
	}
	for _, arg := range Arguments(input) {
		if arg == "touch" || arg == "injected" {
			t.Fatalf("input was split into executable shell tokens: %#v", Arguments(input))
		}
	}
}

func TestParseInputsDefaultsOptionalValuesAndRejectsInvalidValues(t *testing.T) {
	env := map[string]string{}
	get := func(key string) string { return env[key] }
	got, err := ParseInputs(get)
	if err != nil {
		t.Fatal(err)
	}
	if got.Path != "." || got.Format != "sarif" || got.FailOn != "high" || got.Output != "" || !got.NoColor {
		t.Fatalf("unexpected defaults: %#v", got)
	}
	for name, value := range map[string]string{"INPUT_FORMAT": "xml", "INPUT_FAIL_ON": "urgent", "INPUT_MINIMUM_SCORE": "101", "INPUT_VERBOSE": "sometimes", "INPUT_PATH": "bad\npath"} {
		t.Run(name, func(t *testing.T) {
			invalid := map[string]string{name: value}
			if _, parseErr := ParseInputs(func(key string) string { return invalid[key] }); parseErr == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestSummaryParsingAndArguments(t *testing.T) {
	input := Inputs{Path: "repo", Format: "html", Output: "report.html", FailOn: "critical", MinimumScore: 90, Verbose: true}
	args := strings.Join(SummaryArguments(input), "\x00")
	for _, expected := range []string{"--format=json", "--output=", "--fail-on=none", "--minimum-score=0", "--verbose=false"} {
		if !strings.Contains(args, expected) {
			t.Fatalf("summary arguments missing %q: %#v", expected, SummaryArguments(input))
		}
	}
	summary, err := parseSummary([]byte(`{"summary":{"credential_count":3,"low":1,"critical":2,"highest_score":100}}`))
	if err != nil {
		t.Fatal(err)
	}
	if summary.HighestSeverity != "critical" || summary.HighestScore != 100 || summary.Credentials != 3 {
		t.Fatalf("summary = %#v", summary)
	}
}

type fakeExecutor struct {
	commands []command
	codes    []int
	summary  string
}

func (f *fakeExecutor) Run(_ context.Context, spec command) (int, error) {
	f.commands = append(f.commands, spec)
	index := len(f.commands) - 1
	if index == 2 && f.summary != "" {
		_, _ = spec.Stdout.Write([]byte(f.summary))
	}
	if index < len(f.codes) {
		return f.codes[index], nil
	}
	return 0, nil
}

func TestRunPropagatesThresholdAndWritesSafeOutputs(t *testing.T) {
	root := t.TempDir()
	outputFile := filepath.Join(root, "github-output")
	if err := os.WriteFile(outputFile, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{
		"GITHUB_ACTION_PATH": root, "GITHUB_WORKSPACE": root, "RUNNER_TEMP": filepath.Join(root, "runner temp"), "GITHUB_OUTPUT": outputFile,
		"INPUT_PATH": "repository with spaces; echo unsafe", "INPUT_FORMAT": "sarif", "INPUT_OUTPUT": "report with spaces.sarif", "INPUT_FAIL_ON": "high", "INPUT_MINIMUM_SCORE": "0", "INPUT_VERBOSE": "false", "INPUT_NO_COLOR": "true",
	}
	fake := &fakeExecutor{codes: []int{0, 1, 0}, summary: `{"summary":{"credential_count":2,"high":1,"critical":1,"highest_score":97}}`}
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), func(key string) string { return env[key] }, &stdout, &stderr, fake)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1; stderr=%s", code, stderr.String())
	}
	if len(fake.commands) != 3 || fake.commands[1].Args[1] != env["INPUT_PATH"] {
		t.Fatalf("commands = %#v", fake.commands)
	}
	data, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, expected := range []string{"report-path=report with spaces.sarif", "highest-score=97", "highest-severity=critical", "credentials-analyzed=2", "threshold-exceeded=true"} {
		if !strings.Contains(text, expected+"\n") {
			t.Fatalf("outputs missing %q: %s", expected, text)
		}
	}
	knownRaw := "FAKE_RAW_" + "SECRET_FOR_TESTS_ONLY"
	if strings.Contains(stdout.String()+stderr.String()+text, knownRaw) {
		t.Fatal("raw secret leaked from Action runner")
	}
}

func TestRunReturnsUsageBeforeExecutionForInvalidFormat(t *testing.T) {
	fake := &fakeExecutor{}
	var stderr bytes.Buffer
	code := run(context.Background(), func(key string) string {
		if key == "INPUT_FORMAT" {
			return "xml"
		}
		return ""
	}, ioDiscard{}, &stderr, fake)
	if code != exitUsage || len(fake.commands) != 0 {
		t.Fatalf("code=%d commands=%d stderr=%s", code, len(fake.commands), stderr.String())
	}
}

func TestRunPreservesMalformedInputAndClassifiesBuildFailure(t *testing.T) {
	root := t.TempDir()
	outputFile := filepath.Join(root, "github-output")
	if err := os.WriteFile(outputFile, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{
		"GITHUB_ACTION_PATH": root, "GITHUB_WORKSPACE": root, "RUNNER_TEMP": filepath.Join(root, "runner"), "GITHUB_OUTPUT": outputFile,
		"INPUT_PATH": ".", "INPUT_FORMAT": "json", "INPUT_FAIL_ON": "none", "INPUT_MINIMUM_SCORE": "0", "INPUT_VERBOSE": "false", "INPUT_NO_COLOR": "true",
	}
	get := func(key string) string { return env[key] }
	malformed := &fakeExecutor{codes: []int{0, 3}}
	if code := run(context.Background(), get, ioDiscard{}, ioDiscard{}, malformed); code != 3 {
		t.Fatalf("malformed input exit = %d, want 3", code)
	}
	if len(malformed.commands) != 2 {
		t.Fatalf("malformed input unexpectedly triggered summary scan: %d commands", len(malformed.commands))
	}
	buildFailure := &fakeExecutor{codes: []int{1}}
	if code := run(context.Background(), get, ioDiscard{}, ioDiscard{}, buildFailure); code != exitInternal {
		t.Fatalf("build failure exit = %d, want %d", code, exitInternal)
	}
}

type ioDiscard struct{}

func (ioDiscard) Write(p []byte) (int, error) { return len(p), nil }

func TestReleaseBinarySuffixIsPlatformSafe(t *testing.T) {
	if runtime.GOOS == "windows" && filepath.Ext("credscope-action-bin.exe") != ".exe" {
		t.Fatal("unexpected Windows executable suffix")
	}
}
