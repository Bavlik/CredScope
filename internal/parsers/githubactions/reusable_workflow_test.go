package githubactions

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Bavlik/CredScope/internal/domain"
)

func parseInlineWorkflow(t *testing.T, content string) (domain.Workflow, error) {
	t.Helper()
	root := t.TempDir()
	path := filepath.Join(root, ".github", "workflows", "caller.yml")
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return New().Parse(context.Background(), root, path)
}

func TestReusableWorkflowLocalJobLevelUses(t *testing.T) {
	workflow, err := parseInlineWorkflow(t, "name: local\non: push\njobs:\n  call:\n    uses: ./.github/workflows/build.yml\n")
	if err != nil {
		t.Fatal(err)
	}
	job := findJob(t, workflow, "call")
	if job.ReusableWorkflow == nil || !job.ReusableWorkflow.Local || job.ReusableWorkflow.ThirdParty {
		t.Fatalf("local reusable workflow = %#v", job.ReusableWorkflow)
	}
}

func TestReusableWorkflowExternalJobLevelUses(t *testing.T) {
	workflow, err := parseInlineWorkflow(t, "name: external\non: push\njobs:\n  call:\n    uses: octo/repo/.github/workflows/deploy.yml@v1\n")
	if err != nil {
		t.Fatal(err)
	}
	job := findJob(t, workflow, "call")
	if job.ReusableWorkflow == nil || job.ReusableWorkflow.Local || !job.ReusableWorkflow.ThirdParty {
		t.Fatalf("external reusable workflow = %#v", job.ReusableWorkflow)
	}
}

func TestReusableWorkflowUsesWithExpression(t *testing.T) {
	workflow, err := parseInlineWorkflow(t, "name: expr\non: push\njobs:\n  call:\n    uses: ${{ github.repository }}/.github/workflows/deploy.yml@main\n")
	if err != nil {
		t.Fatal(err)
	}
	job := findJob(t, workflow, "call")
	if job.ReusableWorkflow == nil {
		t.Fatal("expected reusable workflow reference to be recorded")
	}
	if !containsReference(job.References, domain.ReferenceGitHubContext, "github.repository") {
		t.Fatalf("expression reference not captured: %#v", job.References)
	}
}

func TestReusableWorkflowWithMapping(t *testing.T) {
	workflow, err := parseInlineWorkflow(t, "name: with\non: push\njobs:\n  call:\n    uses: ./.github/workflows/build.yml\n    with:\n      environment: staging\n      config-path: .github/config.yml\n")
	if err != nil {
		t.Fatal(err)
	}
	job := findJob(t, workflow, "call")
	if len(job.ReusableWorkflowInputs) != 2 {
		t.Fatalf("with inputs = %#v", job.ReusableWorkflowInputs)
	}
	if job.ReusableWorkflowInputs[0].Name != "config-path" || job.ReusableWorkflowInputs[1].Name != "environment" {
		t.Fatalf("with inputs not sorted by name: %#v", job.ReusableWorkflowInputs)
	}
}

func TestReusableWorkflowExplicitSecretsMapping(t *testing.T) {
	workflow, err := parseInlineWorkflow(t, "name: secrets\non: push\njobs:\n  call:\n    uses: ./.github/workflows/build.yml\n    secrets:\n      deployment_token: ${{ secrets.PROD_TOKEN }}\n      registry_user: ${{ secrets.REGISTRY_USER }}\n")
	if err != nil {
		t.Fatal(err)
	}
	job := findJob(t, workflow, "call")
	if job.ReusableSecretsInherit {
		t.Fatal("explicit secrets mapping must not set inherit")
	}
	if len(job.ReusableWorkflowSecrets) != 2 {
		t.Fatalf("reusable secrets = %#v", job.ReusableWorkflowSecrets)
	}
	if job.ReusableWorkflowSecrets[0].Name != "deployment_token" || job.ReusableWorkflowSecrets[1].Name != "registry_user" {
		t.Fatalf("secrets not sorted by name: %#v", job.ReusableWorkflowSecrets)
	}
	deploymentToken := job.ReusableWorkflowSecrets[0]
	if !containsReference(deploymentToken.References, domain.ReferenceSecret, "PROD_TOKEN") {
		t.Fatalf("caller-side secret reference not preserved: %#v", deploymentToken.References)
	}
}

func TestReusableWorkflowSecretsInherit(t *testing.T) {
	workflow, err := parseInlineWorkflow(t, "name: inherit\non: push\njobs:\n  call:\n    uses: ./.github/workflows/build.yml\n    secrets: inherit\n")
	if err != nil {
		t.Fatal(err)
	}
	job := findJob(t, workflow, "call")
	if !job.ReusableSecretsInherit {
		t.Fatal("secrets: inherit was not recognized")
	}
	if len(job.ReusableWorkflowSecrets) != 0 {
		t.Fatalf("secrets: inherit must not populate explicit secrets: %#v", job.ReusableWorkflowSecrets)
	}
}

func TestReusableWorkflowInvalidScalarSecretsValueIsRejected(t *testing.T) {
	_, err := parseInlineWorkflow(t, "name: bad-secrets\non: push\njobs:\n  call:\n    uses: ./.github/workflows/build.yml\n    secrets: yes-please\n")
	if err == nil {
		t.Fatal("expected parse error for invalid secrets scalar value")
	}
	if !strings.Contains(err.Error(), "secrets") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestReusableWorkflowLocalTargetYmlAndYamlExtensions(t *testing.T) {
	ymlWorkflow, err := parseInlineWorkflow(t, "name: yml\non: push\njobs:\n  call:\n    uses: ./.github/workflows/build.yml\n")
	if err != nil {
		t.Fatal(err)
	}
	yamlWorkflow, err := parseInlineWorkflow(t, "name: yaml\non: push\njobs:\n  call:\n    uses: ./.github/workflows/build.yaml\n")
	if err != nil {
		t.Fatal(err)
	}
	if job := findJob(t, ymlWorkflow, "call"); job.ReusableWorkflow == nil || !job.ReusableWorkflow.Local {
		t.Fatalf(".yml target = %#v", job.ReusableWorkflow)
	}
	if job := findJob(t, yamlWorkflow, "call"); job.ReusableWorkflow == nil || !job.ReusableWorkflow.Local {
		t.Fatalf(".yaml target = %#v", job.ReusableWorkflow)
	}
}

func TestReusableWorkflowJobLevelFieldsNotConfusedWithStepFields(t *testing.T) {
	workflow, err := parseInlineWorkflow(t, "name: no-confusion\non: push\njobs:\n  call:\n    runs-on: ubuntu-latest\n    steps:\n      - name: unrelated step\n        uses: actions/checkout@"+strings.Repeat("a", 40)+"\n        with:\n          path: sub\n")
	if err != nil {
		t.Fatal(err)
	}
	job := findJob(t, workflow, "call")
	if job.ReusableWorkflow != nil {
		t.Fatalf("job-level uses should be absent, got %#v", job.ReusableWorkflow)
	}
	if len(job.ReusableWorkflowInputs) != 0 {
		t.Fatalf("step-level with must not populate job-level reusable inputs: %#v", job.ReusableWorkflowInputs)
	}
	if job.Steps[0].Action == nil || !job.Steps[0].Action.PinnedSHA {
		t.Fatalf("step action classification unaffected = %#v", job.Steps[0].Action)
	}
}

func TestReusableWorkflowWithAndSecretsDeterministicOrdering(t *testing.T) {
	content := "name: order\non: push\njobs:\n  call:\n    uses: ./.github/workflows/build.yml\n    with:\n      zeta: 1\n      alpha: 2\n      mu: 3\n    secrets:\n      zeta_secret: ${{ secrets.Z }}\n      alpha_secret: ${{ secrets.A }}\n"
	first, err := parseInlineWorkflow(t, content)
	if err != nil {
		t.Fatal(err)
	}
	job := findJob(t, first, "call")
	wantInputs := []string{"alpha", "mu", "zeta"}
	for i, name := range wantInputs {
		if job.ReusableWorkflowInputs[i].Name != name {
			t.Fatalf("with ordering = %#v", job.ReusableWorkflowInputs)
		}
	}
	wantSecrets := []string{"alpha_secret", "zeta_secret"}
	for i, name := range wantSecrets {
		if job.ReusableWorkflowSecrets[i].Name != name {
			t.Fatalf("secrets ordering = %#v", job.ReusableWorkflowSecrets)
		}
	}
}
