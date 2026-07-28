package corpustest

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// GoldenDiff describes a mismatch between a case's committed golden file and
// freshly rendered output. It never carries a declared canary value.
type GoldenDiff struct {
	CaseID     string
	File       string // "expected.json" or "expected.sarif"
	Path       string // absolute path to the golden file
	Detail     string // first meaningful mismatch, canary-redacted
	ActualPath string // absolute path to a temp file holding actual output, when safe to write
}

func (d GoldenDiff) String() string {
	message := fmt.Sprintf("case %s: %s mismatch\n  expected: %s\n  detail:   %s", d.CaseID, d.File, d.Path, d.Detail)
	if d.ActualPath != "" {
		message += fmt.Sprintf("\n  actual:   %s", d.ActualPath)
	}
	message += fmt.Sprintf("\n  to regenerate intentionally: go test ./internal/corpustest -run \"TestCorpus/%s\" -update", d.CaseID)
	return message
}

// compareGolden compares actual bytes against the case's committed golden
// file. When they differ it writes actual to actualDir for inspection,
// unless actual contains a declared canary, in which case no file is
// written and only the redacted violation is reported.
func compareGolden(c Case, file string, actual []byte, actualDir string) (*GoldenDiff, error) {
	goldenPath := filepath.Join(c.Dir, file)
	expected, err := os.ReadFile(goldenPath)
	if err != nil {
		return nil, fmt.Errorf("case %s: read golden %s: %w", c.ID, goldenPath, err)
	}
	if bytes.Equal(expected, actual) {
		return nil, nil
	}
	diff := &GoldenDiff{CaseID: c.ID, File: file, Path: goldenPath, Detail: firstMismatch(expected, actual, c.Manifest.Canaries)}
	if len(scanForCanaries(c.ID, file, c.Manifest.Canaries, actual)) == 0 {
		actualPath := filepath.Join(actualDir, c.ID+"."+file+".actual")
		if writeErr := os.WriteFile(actualPath, actual, 0o644); writeErr == nil {
			diff.ActualPath = actualPath
		}
	}
	return diff, nil
}

// updateGolden atomically replaces file's committed content with actual via
// write-to-temp-then-rename within the case directory.
func updateGolden(c Case, file string, actual []byte) error {
	goldenPath := filepath.Join(c.Dir, file)
	tmp, err := os.CreateTemp(c.Dir, "."+file+".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(actual); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return err
	}
	return os.Rename(tmpPath, goldenPath)
}

func firstMismatch(expected, actual []byte, canaries []string) string {
	limit := len(expected)
	if len(actual) < limit {
		limit = len(actual)
	}
	for i := 0; i < limit; i++ {
		if expected[i] != actual[i] {
			return fmt.Sprintf("first difference at byte %d (expected %q, actual %q)", i, redactCanaries(snippet(expected, i), canaries), redactCanaries(snippet(actual, i), canaries))
		}
	}
	if len(expected) != len(actual) {
		return fmt.Sprintf("length differs: expected %d bytes, actual %d bytes", len(expected), len(actual))
	}
	return "byte-equal comparison found no difference (unexpected)"
}

func snippet(data []byte, at int) string {
	end := at + 24
	if end > len(data) {
		end = len(data)
	}
	return string(data[at:end])
}

func redactCanaries(text string, canaries []string) string {
	for _, canary := range canaries {
		for _, form := range representations(canary) {
			if form != "" {
				text = strings.ReplaceAll(text, form, "[REDACTED_CANARY]")
			}
		}
	}
	return text
}
