package gitleaks

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const knownRawSecret = "FAKE_RAW_SECRET_FOR_TESTS_ONLY"

func FuzzDecodeNeverReturnsInputInErrors(f *testing.F) {
	f.Add([]byte(`{"RuleID":"demo","File":"demo.env","Secret":"SYNTHETIC_FUZZ_SECRET"}`))
	f.Add([]byte(`[{"RuleID":"demo"}]`))
	f.Add([]byte(`{"broken":`))
	f.Add([]byte(`{"Secret":"SYNTHETIC_FUZZ_SECRET","broken":`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		_, err := decode(data, "report.json")
		if err != nil && bytes.Contains(data, []byte("SYNTHETIC_FUZZ_SECRET")) && strings.Contains(err.Error(), "SYNTHETIC_FUZZ_SECRET") {
			t.Fatal("error reflected synthetic secret marker")
		}
	})
}

func TestNormalizeFindingPathWithExactContainerPrefix(t *testing.T) {
	got, err := normalizeFindingPath("/repo/services/api/.env", "/repo")
	if err != nil || got != "services/api/.env" {
		t.Fatalf("got %q, %v", got, err)
	}
	for _, unsafe := range []string{"/repository/secret.env", "/repo/../outside", "/outside/secret.env"} {
		if _, err := normalizeFindingPath(unsafe, "/repo"); err == nil {
			t.Fatalf("unsafe path accepted: %s", unsafe)
		}
	}
	if _, err := normalizeFindingPath("/repo/file", ""); err == nil {
		t.Fatal("absolute path accepted without prefix")
	}
	for _, prefix := range []string{"/", "/repo/..", "relative", "C:/"} {
		if _, err := normalizeFindingPath("/repo/file", prefix); err == nil {
			t.Fatalf("unsafe configured prefix accepted: %q", prefix)
		}
	}
}

func TestTestFixtureCandidateIsOnlyMetadata(t *testing.T) {
	raw := rawFinding{RuleID: "generic", File: "tests/fixtures/example.env", StartLine: 1, Secret: "test-only"}
	got, err := convert(raw, "gitleaks.json", 0)
	if err != nil {
		t.Fatal(err)
	}
	if !got.TestFixtureCandidate {
		t.Fatal("test fixture candidate hint missing")
	}
}

func vulnerableRoot() string { return filepath.Join("..", "..", "..", "testdata", "vulnerable") }

func TestAdapterImportsDeduplicatesAndNormalizes(t *testing.T) {
	findings, err := New(vulnerableRoot(), "gitleaks.json").Findings(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2", len(findings))
	}
	if findings[0].Location.Path != ".env.example" || findings[1].Location.Path != "config/demo.env" {
		t.Fatalf("paths were not normalized and sorted: %#v", findings)
	}
	if findings[0].Credential.Label != "FAKE_PRODUCTION_TOKEN" || findings[0].Location.Line != 8 {
		t.Fatalf("finding fields not imported: %#v", findings[0])
	}
	if findings[0].CommitInfo == nil || findings[0].CommitInfo.Author != "Demo Author" || findings[0].CommitInfo.MessageFingerprint == "" {
		t.Fatalf("commit metadata missing: %#v", findings[0].CommitInfo)
	}
	if !reflect.DeepEqual(findings[0].Tags, []string{"credential", "example"}) {
		t.Fatalf("tags not deduplicated and sorted: %#v", findings[0].Tags)
	}
}

func TestAdapterNeverReturnsOrSerializesRawSecret(t *testing.T) {
	var logs bytes.Buffer
	original := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(original) })
	findings, err := New(vulnerableRoot(), "gitleaks.json").Findings(context.Background())
	if err != nil {
		t.Fatal("adapter returned an error for valid synthetic fixture")
	}
	encoded, err := json.Marshal(findings)
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]string{"models": string(encoded), "formatted models": fmt.Sprint(findings), "logs": logs.String()} {
		if strings.Contains(value, knownRawSecret) || strings.Contains(value, "DEMO_DATABASE_PASSWORD_VALUE_FOR_TESTS_ONLY") {
			t.Fatalf("%s contains known fake raw secret", name)
		}
	}
}

func TestAdapterRedactsKnownSecretFromMetadataAndErrors(t *testing.T) {
	root := t.TempDir()
	content := `[{"RuleID":"demo","Description":"found FAKE_RAW_SECRET_FOR_TESTS_ONLY","File":"safe.txt","StartLine":-1,"Tags":["FAKE_RAW_SECRET_FOR_TESTS_ONLY"],"Secret":"FAKE_RAW_SECRET_FOR_TESTS_ONLY"}]`
	if err := os.WriteFile(filepath.Join(root, "report.json"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := New(root, "report.json").Findings(context.Background())
	if err == nil {
		t.Fatal("expected invalid line error")
	}
	if strings.Contains(err.Error(), knownRawSecret) {
		t.Fatal("typed error contains known raw secret")
	}
}

func TestAdapterFingerprintIsDeterministic(t *testing.T) {
	first, err := New(vulnerableRoot(), "gitleaks.json").Findings(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	second, err := New(vulnerableRoot(), "gitleaks.json").Findings(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatal("adapter output changed between identical imports")
	}
}

func TestAdapterAcceptsSingleObjectAndMissingOptionalFields(t *testing.T) {
	root := t.TempDir()
	content := `{"RuleID":"demo-rule","File":"src\\config.txt","Secret":"OBVIOUSLY_FAKE_TEST_VALUE"}`
	if err := os.WriteFile(filepath.Join(root, "report.json"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	findings, err := New(root, "report.json").Findings(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Location.Path != "src/config.txt" || findings[0].Description == "" {
		t.Fatalf("unexpected finding: %#v", findings)
	}
}

func TestAdapterMalformedJSONErrorDoesNotLeak(t *testing.T) {
	root := filepath.Join("..", "..", "..", "testdata", "malformed")
	_, err := New(root, "gitleaks.json").Findings(context.Background())
	if err == nil {
		t.Fatal("expected malformed JSON error")
	}
	var parseErr *ParseError
	if !errors.As(err, &parseErr) || parseErr.Kind != ErrorMalformedJSON {
		t.Fatalf("unexpected error type: %T", err)
	}
	if strings.Contains(err.Error(), knownRawSecret) {
		t.Fatal("error contains known fake raw secret")
	}
}

func TestAdapterRejectsInvalidEntriesAndTraversal(t *testing.T) {
	tests := []struct {
		name, content string
		kind          ErrorKind
	}{
		{"null entry", `[null]`, ErrorInvalidStructure},
		{"traversal", `[{"RuleID":"demo","File":"../outside","Secret":"SAFE_FAKE"}]`, ErrorUnsafePath},
		{"absolute windows", `[{"RuleID":"demo","File":"C:\\repo\\secret.txt","Secret":"SAFE_FAKE"}]`, ErrorUnsafePath},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.WriteFile(filepath.Join(root, "report.json"), []byte(test.content), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := New(root, "report.json").Findings(context.Background())
			var parseErr *ParseError
			if !errors.As(err, &parseErr) || parseErr.Kind != test.kind {
				t.Fatalf("error = %#v", err)
			}
		})
	}
}

func TestAdapterStableModelSerialization(t *testing.T) {
	findings, err := New(vulnerableRoot(), "gitleaks.json").Findings(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	first, _ := json.Marshal(findings)
	second, _ := json.Marshal(findings)
	if !bytes.Equal(first, second) {
		t.Fatal("JSON serialization is not stable")
	}
}
