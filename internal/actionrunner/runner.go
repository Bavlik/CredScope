// Package actionrunner implements the pre-release GitHub Action entrypoint.
// It converts untrusted Action inputs directly to argv entries and never asks a
// shell to interpret them.
package actionrunner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"unicode"
)

const (
	exitUsage    = 2
	exitInternal = 4
)

// Inputs is the validated GitHub Action input set.
type Inputs struct {
	Path           string
	GitleaksReport string
	Config         string
	Format         string
	Output         string
	FailOn         string
	MinimumScore   int
	Verbose        bool
	NoColor        bool
}

type command struct {
	Dir    string
	Name   string
	Args   []string
	Stdout io.Writer
	Stderr io.Writer
}

type executor interface {
	Run(context.Context, command) (int, error)
}

type osExecutor struct{}

func (osExecutor) Run(ctx context.Context, spec command) (int, error) {
	cmd := exec.CommandContext(ctx, spec.Name, spec.Args...)
	cmd.Dir = spec.Dir
	cmd.Stdout = spec.Stdout
	cmd.Stderr = spec.Stderr
	err := cmd.Run()
	if err == nil {
		return 0, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode(), nil
	}
	return exitInternal, err
}

// Run executes the composite Action and returns a CredScope-compatible exit
// code. Diagnostics are fixed strings or secret-safe CLI errors.
func Run(ctx context.Context, getenv func(string) string, stdout, stderr io.Writer) int {
	return run(ctx, getenv, stdout, stderr, osExecutor{})
}

func run(ctx context.Context, getenv func(string) string, stdout, stderr io.Writer, execer executor) int {
	inputs, err := ParseInputs(getenv)
	if err != nil {
		fmt.Fprintf(stderr, "credscope-action: invalid input: %v\n", err)
		return exitUsage
	}
	actionPath, err := requiredDirectory(getenv("GITHUB_ACTION_PATH"), "GITHUB_ACTION_PATH")
	if err != nil {
		fmt.Fprintf(stderr, "credscope-action: %v\n", err)
		return exitInternal
	}
	workspace, err := requiredDirectory(getenv("GITHUB_WORKSPACE"), "GITHUB_WORKSPACE")
	if err != nil {
		fmt.Fprintf(stderr, "credscope-action: %v\n", err)
		return exitInternal
	}
	runnerTemp := getenv("RUNNER_TEMP")
	if runnerTemp == "" || hasControl(runnerTemp) {
		fmt.Fprintln(stderr, "credscope-action: RUNNER_TEMP is missing or invalid")
		return exitInternal
	}
	if err := os.MkdirAll(runnerTemp, 0o700); err != nil {
		fmt.Fprintln(stderr, "credscope-action: could not prepare the runner temporary directory")
		return exitInternal
	}
	binary := filepath.Join(runnerTemp, "credscope-action-bin")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	build := command{Dir: actionPath, Name: "go", Args: []string{"build", "-trimpath", "-o", binary, "./cmd/credscope"}, Stdout: stderr, Stderr: stderr}
	if code, buildErr := execer.Run(ctx, build); buildErr != nil || code != 0 {
		fmt.Fprintln(stderr, "credscope-action: CredScope build failed")
		return exitInternal
	}

	primary := command{Dir: workspace, Name: binary, Args: Arguments(inputs), Stdout: stdout, Stderr: stderr}
	primaryCode, primaryErr := execer.Run(ctx, primary)
	if primaryErr != nil {
		fmt.Fprintln(stderr, "credscope-action: could not start CredScope")
		return exitInternal
	}
	thresholdExceeded := primaryCode == 1
	outputs := actionOutputs{
		ReportPath:        inputs.Output,
		HighestScore:      0,
		HighestSeverity:   "none",
		Credentials:       0,
		ThresholdExceeded: thresholdExceeded,
	}
	if primaryCode == 0 || primaryCode == 1 {
		var summary bytes.Buffer
		summarySpec := command{Dir: workspace, Name: binary, Args: SummaryArguments(inputs), Stdout: &summary, Stderr: io.Discard}
		if code, summaryErr := execer.Run(ctx, summarySpec); summaryErr == nil && code == 0 {
			if parsed, parseErr := parseSummary(summary.Bytes()); parseErr == nil {
				outputs.HighestScore = parsed.HighestScore
				outputs.HighestSeverity = parsed.HighestSeverity
				outputs.Credentials = parsed.Credentials
			} else {
				fmt.Fprintln(stderr, "credscope-action: warning: report summary could not be parsed")
			}
		} else {
			fmt.Fprintln(stderr, "credscope-action: warning: report summary could not be generated")
		}
	}
	if err := appendOutputs(getenv("GITHUB_OUTPUT"), outputs); err != nil {
		fmt.Fprintln(stderr, "credscope-action: could not write Action outputs")
		return exitInternal
	}
	return primaryCode
}

// ParseInputs validates all user-controllable Action inputs.
func ParseInputs(getenv func(string) string) (Inputs, error) {
	result := Inputs{
		Path:           valueOr(getenv("INPUT_PATH"), "."),
		GitleaksReport: getenv("INPUT_GITLEAKS_REPORT"),
		Config:         getenv("INPUT_CONFIG"),
		Format:         valueOr(getenv("INPUT_FORMAT"), "sarif"),
		Output:         getenv("INPUT_OUTPUT"),
		FailOn:         valueOr(getenv("INPUT_FAIL_ON"), "high"),
	}
	for name, value := range map[string]string{
		"path": result.Path, "gitleaks-report": result.GitleaksReport, "config": result.Config,
		"format": result.Format, "output": result.Output, "fail-on": result.FailOn,
	} {
		if hasControl(value) {
			return Inputs{}, fmt.Errorf("%s contains a control character", name)
		}
	}
	if !oneOf(result.Format, "terminal", "json", "sarif", "html", "mermaid") {
		return Inputs{}, fmt.Errorf("unsupported format %q", result.Format)
	}
	if !oneOf(result.FailOn, "none", "informational", "low", "medium", "high", "critical") {
		return Inputs{}, fmt.Errorf("unsupported fail-on threshold %q", result.FailOn)
	}
	minimum := valueOr(getenv("INPUT_MINIMUM_SCORE"), "0")
	parsedMinimum, err := strconv.Atoi(minimum)
	if err != nil || parsedMinimum < 0 || parsedMinimum > 100 {
		return Inputs{}, errors.New("minimum-score must be an integer from 0 to 100")
	}
	result.MinimumScore = parsedMinimum
	result.Verbose, err = parseBool(valueOr(getenv("INPUT_VERBOSE"), "false"), "verbose")
	if err != nil {
		return Inputs{}, err
	}
	result.NoColor, err = parseBool(valueOr(getenv("INPUT_NO_COLOR"), "true"), "no-color")
	if err != nil {
		return Inputs{}, err
	}
	return result, nil
}

// Arguments returns the exact argv passed to the primary CredScope scan.
func Arguments(input Inputs) []string {
	args := []string{"scan", input.Path}
	args = appendOptional(args, "--gitleaks-report", input.GitleaksReport)
	args = appendOptional(args, "--config", input.Config)
	args = append(args, "--format", input.Format, "--fail-on", input.FailOn, "--minimum-score", strconv.Itoa(input.MinimumScore))
	args = appendOptional(args, "--output", input.Output)
	args = append(args, "--verbose="+strconv.FormatBool(input.Verbose), "--no-color="+strconv.FormatBool(input.NoColor))
	return args
}

// SummaryArguments returns a second, non-failing JSON scan used only to expose
// numeric Action outputs. An explicit empty output keeps this scan on stdout
// even when a configuration file specifies an output path.
func SummaryArguments(input Inputs) []string {
	args := []string{"scan", input.Path}
	args = appendOptional(args, "--gitleaks-report", input.GitleaksReport)
	args = appendOptional(args, "--config", input.Config)
	return append(args, "--format=json", "--output=", "--fail-on=none", "--minimum-score=0", "--no-color", "--quiet=false", "--verbose=false")
}

type actionOutputs struct {
	ReportPath        string
	HighestScore      int
	HighestSeverity   string
	Credentials       int
	ThresholdExceeded bool
}

type summaryDocument struct {
	Summary struct {
		CredentialCount int `json:"credential_count"`
		Informational   int `json:"informational"`
		Low             int `json:"low"`
		Medium          int `json:"medium"`
		High            int `json:"high"`
		Critical        int `json:"critical"`
		HighestScore    int `json:"highest_score"`
	} `json:"summary"`
}

type parsedSummary struct {
	HighestScore    int
	HighestSeverity string
	Credentials     int
}

func parseSummary(data []byte) (parsedSummary, error) {
	var document summaryDocument
	if err := json.Unmarshal(data, &document); err != nil {
		return parsedSummary{}, err
	}
	severity := "none"
	for _, candidate := range []struct {
		name  string
		count int
	}{{"critical", document.Summary.Critical}, {"high", document.Summary.High}, {"medium", document.Summary.Medium}, {"low", document.Summary.Low}, {"informational", document.Summary.Informational}} {
		if candidate.count > 0 {
			severity = candidate.name
			break
		}
	}
	return parsedSummary{HighestScore: document.Summary.HighestScore, HighestSeverity: severity, Credentials: document.Summary.CredentialCount}, nil
}

func appendOutputs(path string, output actionOutputs) error {
	if path == "" || hasControl(path) {
		return errors.New("GITHUB_OUTPUT is missing or invalid")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("GITHUB_OUTPUT is not a regular file")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = fmt.Fprintf(file, "report-path=%s\nhighest-score=%d\nhighest-severity=%s\ncredentials-analyzed=%d\nthreshold-exceeded=%t\n", output.ReportPath, output.HighestScore, output.HighestSeverity, output.Credentials, output.ThresholdExceeded)
	return err
}

func requiredDirectory(value, name string) (string, error) {
	if value == "" || hasControl(value) {
		return "", fmt.Errorf("%s is missing or invalid", name)
	}
	info, err := os.Stat(value)
	if err != nil || !info.IsDir() {
		return "", fmt.Errorf("%s is not an accessible directory", name)
	}
	return value, nil
}

func appendOptional(args []string, flag, value string) []string {
	if value == "" {
		return args
	}
	return append(args, flag, value)
}

func parseBool(value, name string) (bool, error) {
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return false, fmt.Errorf("%s must be true or false", name)
	}
	return parsed, nil
}

func valueOr(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func oneOf(value string, options ...string) bool {
	for _, option := range options {
		if value == option {
			return true
		}
	}
	return false
}

func hasControl(value string) bool {
	return strings.IndexFunc(value, unicode.IsControl) >= 0
}
