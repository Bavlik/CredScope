package sanitizer

import (
	"strings"
	"testing"
)

func TestFingerprintDoesNotLeakSecretAndIsDeterministic(t *testing.T) {
	const secret = "FAKE_SECRET_MATERIAL_DO_NOT_USE"
	first := Fingerprint(secret)
	second := Fingerprint(secret)
	if first != second {
		t.Fatalf("fingerprints differ: %q != %q", first, second)
	}
	if strings.Contains(first, secret) {
		t.Fatal("fingerprint contains secret material")
	}
	if !strings.HasPrefix(first, "sha256:") || len(first) != len("sha256:")+64 {
		t.Fatalf("unexpected fingerprint format: %q", first)
	}
}

func TestFingerprintUsesDomainSeparation(t *testing.T) {
	if Fingerprint("a") == Fingerprint("b") {
		t.Fatal("different inputs produced identical fingerprints")
	}
}

func TestTerminalTextRemovesControlsAndANSI(t *testing.T) {
	input := "safe\x1b[31mRED\x1b[0m\nnext\x00\titem"
	got := TerminalText(input)
	if strings.ContainsAny(got, "\x1b\x00\n\t") {
		t.Fatalf("control character survived: %q", got)
	}
	if got != "safeRED next item" {
		t.Fatalf("TerminalText() = %q", got)
	}
}

func TestIdentifierSanitizesSyntax(t *testing.T) {
	if got := Identifier("prod\n]-->evil<script>"); got != "prod__--_evil_script" {
		t.Fatalf("Identifier() = %q", got)
	}
}

func TestRedactedReferenceOmitsSecret(t *testing.T) {
	const secret = "EXAMPLE_ONLY_SECRET_VALUE"
	got := RedactedReference("DEPLOY TOKEN", secret)
	if strings.Contains(got, secret) {
		t.Fatal("redacted reference contains raw secret")
	}
	if !strings.Contains(got, "DEPLOY_TOKEN") {
		t.Fatalf("redacted reference omitted label: %q", got)
	}
}
