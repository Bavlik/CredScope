package githubactions

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Bavlik/CredScope/internal/domain"
)

func TestReusableSecretsInheritScalarEvidence(t *testing.T) {
	content := "name: c\non: push\njobs:\n  deploy:\n    uses: ./.github/workflows/deploy.yml\n    secrets: inherit\n"
	workflow, err := parseInlineWorkflow(t, content)
	if err != nil {
		t.Fatal(err)
	}
	job := findJob(t, workflow, "deploy")

	if !job.ReusableSecretsInherit {
		t.Fatal("expected ReusableSecretsInherit = true")
	}
	if job.ReusableSecretsInheritEvidence == nil {
		t.Fatal("expected non-nil ReusableSecretsInheritEvidence")
	}
	ev := *job.ReusableSecretsInheritEvidence
	if ev.Location.Path != workflow.File {
		t.Fatalf("evidence path = %q, want caller workflow file %q", ev.Location.Path, workflow.File)
	}
	if ev.Field != "jobs.deploy.secrets" {
		t.Fatalf("evidence field = %q, want %q", ev.Field, "jobs.deploy.secrets")
	}
	wantLine := strings.Count(content[:strings.Index(content, "secrets: inherit")], "\n") + 1
	if ev.Location.Line != wantLine {
		t.Fatalf("evidence line = %d, want %d (the secrets: inherit declaration line)", ev.Location.Line, wantLine)
	}
	if len(job.ReusableWorkflowSecrets) != 0 {
		t.Fatalf("expected no explicit secret bindings alongside inherit, got %#v", job.ReusableWorkflowSecrets)
	}
}

func TestReusableSecretsInheritExplicitMappingUnaffected(t *testing.T) {
	content := "name: c\non: push\njobs:\n  deploy:\n    uses: ./.github/workflows/deploy.yml\n    secrets:\n      token: ${{ secrets.PROD_TOKEN }}\n"
	workflow, err := parseInlineWorkflow(t, content)
	if err != nil {
		t.Fatal(err)
	}
	job := findJob(t, workflow, "deploy")

	if job.ReusableSecretsInherit {
		t.Fatal("explicit mapping must not set ReusableSecretsInherit")
	}
	if job.ReusableSecretsInheritEvidence != nil {
		t.Fatalf("explicit mapping must not set inherit evidence, got %#v", job.ReusableSecretsInheritEvidence)
	}
	if len(job.ReusableWorkflowSecrets) != 1 || job.ReusableWorkflowSecrets[0].Name != "token" {
		t.Fatalf("explicit secret mapping not parsed as before: %#v", job.ReusableWorkflowSecrets)
	}
	if !containsReference(job.ReusableWorkflowSecrets[0].References, domain.ReferenceSecret, "PROD_TOKEN") {
		t.Fatalf("caller-side secret reference not preserved: %#v", job.ReusableWorkflowSecrets[0].References)
	}
}

func TestReusableSecretsInheritNoSecretsKey(t *testing.T) {
	content := "name: c\non: push\njobs:\n  deploy:\n    uses: ./.github/workflows/deploy.yml\n"
	workflow, err := parseInlineWorkflow(t, content)
	if err != nil {
		t.Fatal(err)
	}
	job := findJob(t, workflow, "deploy")

	if job.ReusableSecretsInherit {
		t.Fatal("no secrets key must not set ReusableSecretsInherit")
	}
	if job.ReusableSecretsInheritEvidence != nil {
		t.Fatalf("no secrets key must not set inherit evidence, got %#v", job.ReusableSecretsInheritEvidence)
	}
}

func TestReusableSecretsInheritInvalidScalarValueStillRejected(t *testing.T) {
	content := "name: c\non: push\njobs:\n  deploy:\n    uses: ./.github/workflows/deploy.yml\n    secrets: something_else\n"
	_, err := parseInlineWorkflow(t, content)
	if err == nil {
		t.Fatal("expected parse error for invalid secrets scalar value")
	}
	if !strings.Contains(err.Error(), "secrets") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestReusableSecretsInheritParsingIsDeterministic(t *testing.T) {
	content := "name: c\non: push\njobs:\n  deploy:\n    uses: ./.github/workflows/deploy.yml\n    secrets: inherit\n"

	first, err := parseInlineWorkflow(t, content)
	if err != nil {
		t.Fatal(err)
	}
	second, err := parseInlineWorkflow(t, content)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatal("repeated parsing of identical inherit YAML is not deterministic")
	}
	firstJSON, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	secondJSON, err := json.Marshal(second)
	if err != nil {
		t.Fatal(err)
	}
	if string(firstJSON) != string(secondJSON) {
		t.Fatal("repeated parsing of identical inherit YAML produced different JSON")
	}
}

func TestReusableSecretsInheritParserDoesNotMutateInputFile(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, ".github", "workflows", "caller.yml")
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	content := "name: c\non: push\njobs:\n  deploy:\n    uses: ./.github/workflows/deploy.yml\n    secrets: inherit\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := New().Parse(context.Background(), root, path); err != nil {
		t.Fatal(err)
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("parsing must not mutate the source workflow file on disk")
	}
}
