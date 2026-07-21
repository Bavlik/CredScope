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

func fixtureRoot(kind string) string { return filepath.Join("..", "..", "..", "testdata", kind) }

func parseDeploy(t *testing.T) domain.Workflow {
	t.Helper()
	workflow, err := New().Parse(context.Background(), fixtureRoot("vulnerable"), filepath.Join(".github", "workflows", "deploy.yml"))
	if err != nil {
		t.Fatal(err)
	}
	return workflow
}

func TestParseWorkflowTriggersPermissionsAndJobs(t *testing.T) {
	workflow := parseDeploy(t)
	if workflow.Name != "Production deployment" || workflow.File != ".github/workflows/deploy.yml" {
		t.Fatalf("workflow metadata = %#v", workflow)
	}
	if !hasTrigger(workflow.Triggers, "pull_request_target") || !hasTrigger(workflow.Triggers, "workflow_dispatch") {
		t.Fatalf("triggers = %#v", workflow.Triggers)
	}
	if workflow.MissingExplicitPermissions {
		t.Fatal("explicit permissions were not recognized")
	}
	if len(workflow.Jobs) != 3 || workflow.Jobs[0].ID != "deploy" || workflow.Jobs[1].ID != "prepare" {
		t.Fatalf("jobs not sorted: %#v", workflow.Jobs)
	}
	if !containsPermission(workflow.Permissions, "contents", "write") || !containsPermission(workflow.Permissions, "id-token", "write") {
		t.Fatalf("permissions = %#v", workflow.Permissions)
	}
	if !containsSignal(workflow.Signals, "pull_request_target") || !containsSignal(workflow.Signals, "write_permission") {
		t.Fatalf("signals = %#v", workflow.Signals)
	}
}

func TestParseSecretEnvironmentAndShellReferences(t *testing.T) {
	workflow := parseDeploy(t)
	if !containsReference(workflow.References, domain.ReferenceSecret, "FAKE_PRODUCTION_TOKEN") || !containsReference(workflow.References, domain.ReferenceSecret, "EXAMPLE_AWS_DEPLOY_KEY") {
		t.Fatalf("secret references = %#v", workflow.References)
	}
	prepare := findJob(t, workflow, "prepare")
	if !containsReference(prepare.References, domain.ReferenceGitHubContext, "github.event.pull_request.title") {
		t.Fatalf("GitHub context reference missing: %#v", prepare.References)
	}
	if !containsSignal(prepare.Signals, "secret_passed_to_shell") || !containsSignal(prepare.Signals, "github_context_in_shell") || !containsSignal(prepare.Signals, "secret_propagated_through_output") {
		t.Fatalf("job signals = %#v", prepare.Signals)
	}
	command := prepare.Steps[0].Run
	if command == nil || !strings.HasPrefix(command.RedactedText, "<redacted>") || strings.Contains(command.RedactedText, "deploy --token") {
		t.Fatalf("shell command not safely represented: %#v", command)
	}
	if command.LineCount != 3 {
		t.Fatalf("line count = %d", command.LineCount)
	}
}

func TestEnvironmentScopeSignals(t *testing.T) {
	workflow := parseDeploy(t)
	if !containsSignal(workflow.Signals, "secret_copied_to_environment") {
		t.Fatal("workflow-level secret environment scope was not represented")
	}
	prepare := findJob(t, workflow, "prepare")
	if !containsSignal(prepare.Signals, "secret_copied_to_environment") {
		t.Fatal("job-level secret environment scope was not represented")
	}
}

func TestThirdPartyActionClassificationAndArtifacts(t *testing.T) {
	workflow := parseDeploy(t)
	prepare := findJob(t, workflow, "prepare")
	thirdParty := prepare.Steps[1].Action
	if thirdParty == nil || !thirdParty.ThirdParty || !thirdParty.Mutable || thirdParty.PinnedSHA {
		t.Fatalf("third-party classification = %#v", thirdParty)
	}
	if !containsSignal(prepare.Signals, "mutable_third_party_action") || !containsSignal(prepare.Signals, "secret_passed_to_third_party_action") {
		t.Fatalf("action signals = %#v", prepare.Signals)
	}
	if prepare.Steps[2].Action == nil || prepare.Steps[2].Action.ArtifactKind != "upload" {
		t.Fatal("upload-artifact was not classified")
	}
	deploy := findJob(t, workflow, "deploy")
	if deploy.Steps[0].Action == nil || deploy.Steps[0].Action.ArtifactKind != "download" {
		t.Fatal("download-artifact was not classified")
	}
}

func TestReusableWorkflowIsUnresolved(t *testing.T) {
	job := findJob(t, parseDeploy(t), "reusable")
	if job.ReusableWorkflow == nil || !job.ReusableWorkflow.Local || job.ReusableResolved {
		t.Fatalf("reusable workflow = %#v", job)
	}
}

func TestSafeWorkflowPinnedActionAndNoMissingPermissions(t *testing.T) {
	workflow, err := New().Parse(context.Background(), fixtureRoot("safe"), filepath.Join(".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	action := workflow.Jobs[0].Steps[0].Action
	if action == nil || !action.PinnedSHA || action.Mutable || action.ThirdParty {
		t.Fatalf("safe action classification = %#v", action)
	}
	if workflow.MissingExplicitPermissions {
		t.Fatal("safe workflow permissions marked missing")
	}
}

func TestSingleWorkflowSingleCredentialFixture(t *testing.T) {
	root := filepath.Join(fixtureRoot("vulnerable"), "one-workflow")
	workflow, err := New().Parse(context.Background(), root, filepath.Join(".github", "workflows", "one.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var secrets []domain.Reference
	for _, ref := range workflow.References {
		if ref.Kind == domain.ReferenceSecret {
			secrets = append(secrets, ref)
		}
	}
	if len(secrets) != 1 || secrets[0].Name != "FAKE_SINGLE_WORKFLOW_TOKEN" {
		t.Fatalf("secret references = %#v", secrets)
	}
}

func TestMalformedWorkflowReturnsTypedSafeError(t *testing.T) {
	_, err := New().Parse(context.Background(), fixtureRoot("malformed"), filepath.Join(".github", "workflows", "bad.yml"))
	if err == nil {
		t.Fatal("expected parse error")
	}
	if !strings.Contains(err.Error(), "github-actions parse error") || strings.Contains(err.Error(), "FAKE_RAW_SECRET") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestHostileWorkflowControlsAreRemoved(t *testing.T) {
	workflow, err := New().Parse(context.Background(), fixtureRoot("vulnerable"), filepath.Join(".github", "workflows", "hostile.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(workflow)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), `\u001b`) || strings.Contains(workflow.Name, "\x1b") {
		t.Fatalf("terminal control survived: %s", encoded)
	}
	if !strings.Contains(workflow.Name, "<script>") {
		t.Fatal("parser should preserve non-control text for later context-specific escaping")
	}
	if !workflow.MissingExplicitPermissions || !containsSignal(workflow.Signals, "missing_explicit_permissions") {
		t.Fatal("missing workflow permissions were not represented")
	}
}

func TestWriteAllPermissionIsRepresented(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, ".github", "workflows", "write-all.yml")
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	content := "name: write all\non: push\npermissions: write-all\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo test\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	workflow, err := New().Parse(context.Background(), root, path)
	if err != nil {
		t.Fatal(err)
	}
	if !containsPermission(workflow.Permissions, "all", "write-all") || !containsSignal(workflow.Signals, "write_permission") {
		t.Fatalf("write-all was not represented: %#v", workflow)
	}
}

func TestParserDoesNotExecuteShellText(t *testing.T) {
	root := t.TempDir()
	workflowPath := filepath.Join(root, ".github", "workflows", "no-exec.yml")
	if err := os.MkdirAll(filepath.Dir(workflowPath), 0o750); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(root, "must-not-exist")
	content := "name: no execution\non: push\njobs:\n  test:\n    runs-on: windows-latest\n    steps:\n      - run: New-Item -Path '" + strings.ReplaceAll(marker, "\\", "/") + "'\n"
	if err := os.WriteFile(workflowPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New().Parse(context.Background(), root, workflowPath); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("shell content was executed")
	}
}

func TestWorkflowOutputAndSerializationAreDeterministic(t *testing.T) {
	first := parseDeploy(t)
	second := parseDeploy(t)
	if !reflect.DeepEqual(first, second) {
		t.Fatal("workflow parsing is not deterministic")
	}
	left, _ := json.Marshal(first)
	right, _ := json.Marshal(second)
	if string(left) != string(right) {
		t.Fatal("workflow serialization changed")
	}
}

func containsPermission(items []domain.Permission, scope, level string) bool {
	for _, item := range items {
		if item.Scope == scope && item.Level == level {
			return true
		}
	}
	return false
}
func containsSignal(items []domain.StructuralSignal, kind string) bool {
	for _, item := range items {
		if item.Kind == kind {
			return true
		}
	}
	return false
}
func containsReference(items []domain.Reference, kind domain.ReferenceKind, name string) bool {
	for _, item := range items {
		if item.Kind == kind && item.Name == name {
			return true
		}
	}
	return false
}
func findJob(t *testing.T, workflow domain.Workflow, id string) domain.WorkflowJob {
	t.Helper()
	for _, job := range workflow.Jobs {
		if job.ID == id {
			return job
		}
	}
	t.Fatalf("job %q not found", id)
	return domain.WorkflowJob{}
}
