package corpustest

import (
	"encoding/base64"
	"net/url"
	"strings"
	"testing"
)

// These are pure, in-memory unit tests of the secret-safety scanning logic
// itself (no fixture execution, no analysis pipeline) — fast and safe to
// run anywhere, including while the full corpus pipeline is unavailable.

func TestScanForCanariesDetectsRawForm(t *testing.T) {
	canary := "CREDSCOPE_TEST_CANARY_UNIT_RAW"
	content := []byte(`{"label":"` + canary + `"}`)
	violations := scanForCanaries("case", "unit.json", []string{canary}, content)
	if len(violations) == 0 {
		t.Fatal("expected a raw-form violation to be detected")
	}
	found := false
	for _, v := range violations {
		if v.Representation == "raw" {
			found = true
		}
		if strings.Contains(v.String(), canary) {
			t.Fatalf("violation message must never contain the canary value itself: %q", v.String())
		}
	}
	if !found {
		t.Fatal("expected a violation tagged with the raw representation")
	}
}

func TestScanForCanariesDetectsJSONEscapedForm(t *testing.T) {
	canary := `CANARY_WITH_"QUOTE`
	escaped := strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(canary)
	content := []byte(`{"label":"` + escaped + `"}`)
	violations := scanForCanaries("case", "unit.json", []string{canary}, content)
	if len(violations) == 0 {
		t.Fatal("expected a json_escaped-form violation to be detected")
	}
}

func TestScanForCanariesDetectsURLEncodedForm(t *testing.T) {
	canary := "CREDSCOPE TEST CANARY WITH SPACES"
	content := []byte(url.QueryEscape(canary))
	violations := scanForCanaries("case", "unit.txt", []string{canary}, content)
	if len(violations) == 0 {
		t.Fatal("expected a url_encoded-form violation to be detected")
	}
}

func TestScanForCanariesDetectsBase64Form(t *testing.T) {
	canary := "CREDSCOPE_TEST_CANARY_BASE64_UNIT"
	content := []byte(base64.StdEncoding.EncodeToString([]byte(canary)))
	violations := scanForCanaries("case", "unit.txt", []string{canary}, content)
	if len(violations) == 0 {
		t.Fatal("expected a base64-form violation to be detected")
	}
}

func TestScanForCanariesCleanContentProducesNoViolations(t *testing.T) {
	violations := scanForCanaries("case", "unit.json", []string{"CREDSCOPE_TEST_CANARY_ABSENT"}, []byte(`{"label":"nothing_suspicious"}`))
	if len(violations) != 0 {
		t.Fatalf("expected no violations for clean content, got %#v", violations)
	}
}

func TestViolationStringNeverContainsCanaryEvenWhenRedacting(t *testing.T) {
	canary := "CREDSCOPE_TEST_CANARY_REDACTION_CHECK"
	v := CanaryViolation{CaseID: "case", Representation: "raw", Location: "somewhere"}
	if strings.Contains(v.String(), canary) {
		t.Fatal("CanaryViolation.String must never embed the canary value")
	}
}

func TestRedactCanariesReplacesEveryRepresentation(t *testing.T) {
	canary := "CREDSCOPE_TEST_CANARY_REDACT_ME"
	text := "prefix " + canary + " suffix " + base64.StdEncoding.EncodeToString([]byte(canary)) + " end"
	redacted := redactCanaries(text, []string{canary})
	if strings.Contains(redacted, canary) {
		t.Fatalf("redactCanaries left the raw canary in place: %q", redacted)
	}
}
