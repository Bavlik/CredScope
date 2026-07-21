//go:build ignore

// verify-reports validates generated smoke-test reports without requiring
// Python, Node.js, or a network connection.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
)

func main() {
	if len(os.Args) != 2 {
		fail("usage: go run ./scripts/verify-reports.go REPORT_DIRECTORY")
	}
	dir := os.Args[1]
	jsonPath := firstExisting(filepath.Join(dir, "credscope.json"), filepath.Join(dir, "action-smoke.json"))
	if jsonPath == "" {
		fail("JSON report is missing")
	}
	primary := read(jsonPath)
	var jsonDoc map[string]any
	if err := json.Unmarshal(primary, &jsonDoc); err != nil {
		fail("JSON report is invalid")
	}
	if jsonDoc["schema_version"] != "1" {
		fail("JSON schema version is not 1")
	}
	assertNoRaw(primary)

	repeatPath := filepath.Join(dir, "credscope-repeat.json")
	if _, err := os.Stat(repeatPath); err == nil {
		var repeat map[string]any
		if json.Unmarshal(read(repeatPath), &repeat) != nil {
			fail("repeat JSON report is invalid")
		}
		normalizeScan(jsonDoc)
		normalizeScan(repeat)
		if !reflect.DeepEqual(jsonDoc, repeat) {
			fail("normalized JSON security data is not deterministic")
		}
	}

	sarifPath := filepath.Join(dir, "credscope.sarif")
	if _, err := os.Stat(sarifPath); err == nil {
		data := read(sarifPath)
		var document struct {
			Version string `json:"version"`
			Runs    []any  `json:"runs"`
		}
		if json.Unmarshal(data, &document) != nil || document.Version != "2.1.0" || len(document.Runs) != 1 {
			fail("SARIF report structure is invalid")
		}
		assertNoRaw(data)
	}

	htmlPath := filepath.Join(dir, "credscope.html")
	if _, err := os.Stat(htmlPath); err == nil {
		data := read(htmlPath)
		lower := strings.ToLower(string(data))
		if !bytes.HasPrefix(bytes.ToLower(data), []byte("<!doctype html>")) || !strings.Contains(lower, "content-security-policy") || !strings.Contains(lower, "<main") {
			fail("HTML report lacks required standalone structure")
		}
		if strings.Contains(lower, "src=\"http") || strings.Contains(lower, "href=\"http") {
			fail("HTML report references an external network resource")
		}
		assertNoRaw(data)
	}

	mermaidPath := filepath.Join(dir, "blast-radius.md")
	if _, err := os.Stat(mermaidPath); err == nil {
		data := read(mermaidPath)
		if !bytes.Contains(data, []byte("```mermaid")) || !bytes.Contains(data, []byte("graph TD")) || bytes.Contains(bytes.ToLower(data), []byte("click ")) {
			fail("Mermaid report structure is invalid")
		}
		assertNoRaw(data)
	}
	fmt.Println("report validation passed")
}

func normalizeScan(document map[string]any) {
	scan, ok := document["scan"].(map[string]any)
	if !ok {
		return
	}
	delete(scan, "started_at")
	delete(scan, "completed_at")
	delete(scan, "duration_ms")
}

func assertNoRaw(data []byte) {
	rawOne := "FAKE_RAW_" + "SECRET_FOR_TESTS_ONLY"
	rawTwo := "DEMO_DATABASE_PASSWORD_" + "VALUE_FOR_TESTS_ONLY"
	if bytes.Contains(data, []byte(rawOne)) || bytes.Contains(data, []byte(rawTwo)) {
		fail("raw synthetic value appears in generated report")
	}
}

func firstExisting(paths ...string) string {
	for _, path := range paths {
		if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() {
			return path
		}
	}
	return ""
}

func read(path string) []byte {
	data, err := os.ReadFile(path)
	if err != nil {
		fail("could not read generated report")
	}
	return data
}

func fail(message string) {
	fmt.Fprintln(os.Stderr, "verify-reports:", message)
	os.Exit(1)
}
