// Command generate-examples deterministically refreshes the checked-in safe
// report examples. It is a maintainer tool and is not part of the CredScope CLI.
package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/Bavlik/CredScope/internal/analysis"
	"github.com/Bavlik/CredScope/internal/config"
	"github.com/Bavlik/CredScope/internal/ingest"
	"github.com/Bavlik/CredScope/internal/reporters"
	htmlreport "github.com/Bavlik/CredScope/internal/reporters/html"
	"github.com/Bavlik/CredScope/internal/reporters/jsonreport"
	"github.com/Bavlik/CredScope/internal/reporters/mermaid"
	"github.com/Bavlik/CredScope/internal/reporters/sarif"
)

func main() {
	root, err := projectRoot()
	if err != nil {
		fatal(err)
	}
	fixture := filepath.Join(root, "testdata", "vulnerable", "write-all")
	parsed, err := ingest.Repository(context.Background(), fixture, config.Default(), "")
	if err != nil {
		fatal(err)
	}
	result, err := analysis.Analyze(context.Background(), parsed, analysis.Options{})
	if err != nil {
		fatal(err)
	}
	started := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	base := reporters.Input{
		Tool:     reporters.Tool{Name: "CredScope", Version: "dev", Commit: "none"},
		Scan:     reporters.Scan{Repository: "write-all", StartedAt: started, CompletedAt: started.Add(time.Second), FailOn: "none"},
		Analysis: result,
	}
	examples := []struct {
		name     string
		format   string
		reporter reporters.Reporter
		pretty   bool
	}{
		{"credscope-report.json", "json", jsonreport.New(), true},
		{"credscope.sarif", "sarif", sarif.New(), true},
		{"credscope-report.html", "html", htmlreport.New(), false},
		{"blast-radius.md", "mermaid", mermaid.New(), false},
	}
	for _, example := range examples {
		input := base
		input.Scan.Format = example.format
		var output bytes.Buffer
		if err := example.reporter.Render(&output, input, reporters.Options{Pretty: example.pretty}); err != nil {
			fatal(fmt.Errorf("render %s: %w", example.format, err))
		}
		path := filepath.Join(root, "docs", "examples", example.name)
		if err := os.WriteFile(path, output.Bytes(), 0o600); err != nil {
			fatal(fmt.Errorf("write %s: %w", example.name, err))
		}
	}
}

func projectRoot() (string, error) {
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("locate source file")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(source), "..", "..")), nil
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "generate examples:", err)
	os.Exit(1)
}
