package githubactions

import (
	"strings"
	"testing"
)

func TestWorkflowCallEmptyMapping(t *testing.T) {
	workflow, err := parseInlineWorkflow(t, "name: c\non:\n  workflow_call: {}\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n")
	if err != nil {
		t.Fatal(err)
	}
	if workflow.WorkflowCall == nil {
		t.Fatal("expected non-nil empty contract")
	}
	if len(workflow.WorkflowCall.Inputs) != 0 || len(workflow.WorkflowCall.Secrets) != 0 {
		t.Fatalf("expected empty contract, got %#v", workflow.WorkflowCall)
	}
}

func TestWorkflowCallNullValue(t *testing.T) {
	workflow, err := parseInlineWorkflow(t, "name: c\non:\n  workflow_call:\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n")
	if err != nil {
		t.Fatal(err)
	}
	if workflow.WorkflowCall == nil {
		t.Fatal("expected non-nil empty contract for null workflow_call value")
	}
}

func TestWorkflowCallBareScalarOn(t *testing.T) {
	workflow, err := parseInlineWorkflow(t, "name: c\non: workflow_call\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n")
	if err != nil {
		t.Fatal(err)
	}
	if workflow.WorkflowCall == nil {
		t.Fatal("expected contract for bare scalar `on: workflow_call`")
	}
	if !hasTrigger(workflow.Triggers, "workflow_call") {
		t.Fatal("trigger not recorded for bare scalar on")
	}
}

func TestWorkflowCallListForm(t *testing.T) {
	workflow, err := parseInlineWorkflow(t, "name: c\non: [push, workflow_call]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n")
	if err != nil {
		t.Fatal(err)
	}
	if workflow.WorkflowCall == nil {
		t.Fatal("expected contract for list-form on")
	}
}

func TestWorkflowCallWithInputs(t *testing.T) {
	content := "name: c\non:\n  workflow_call:\n    inputs:\n      environment:\n        description: Deployment environment\n        required: true\n        type: string\n      dry_run:\n        required: false\n        type: boolean\n        default: false\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
	workflow, err := parseInlineWorkflow(t, content)
	if err != nil {
		t.Fatal(err)
	}
	inputs := workflow.WorkflowCall.Inputs
	if len(inputs) != 2 {
		t.Fatalf("inputs = %#v", inputs)
	}
	if inputs[0].Name != "dry_run" || inputs[1].Name != "environment" {
		t.Fatalf("inputs not sorted by name: %#v", inputs)
	}
	dryRun := inputs[0]
	if dryRun.Required || dryRun.Type != "boolean" {
		t.Fatalf("dry_run definition = %#v", dryRun)
	}
	if dryRun.Default == nil || dryRun.Default.Type != "boolean" || dryRun.Default.Boolean == nil || *dryRun.Default.Boolean != false {
		t.Fatalf("dry_run default = %#v", dryRun.Default)
	}
	env := inputs[1]
	if !env.Required || env.Type != "string" || env.Description != "Deployment environment" {
		t.Fatalf("environment definition = %#v", env)
	}
	if env.Default != nil {
		t.Fatalf("environment should have no default: %#v", env.Default)
	}
}

func TestWorkflowCallWithSecrets(t *testing.T) {
	content := "name: c\non:\n  workflow_call:\n    secrets:\n      deployment_token:\n        description: Deployment credential\n        required: true\n      registry_password:\n        required: false\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
	workflow, err := parseInlineWorkflow(t, content)
	if err != nil {
		t.Fatal(err)
	}
	secrets := workflow.WorkflowCall.Secrets
	if len(secrets) != 2 {
		t.Fatalf("secrets = %#v", secrets)
	}
	if secrets[0].Name != "deployment_token" || secrets[1].Name != "registry_password" {
		t.Fatalf("secrets not sorted by name: %#v", secrets)
	}
	if !secrets[0].Required || secrets[0].Description != "Deployment credential" {
		t.Fatalf("deployment_token = %#v", secrets[0])
	}
	if secrets[1].Required {
		t.Fatalf("registry_password should default to not required: %#v", secrets[1])
	}
}

func TestWorkflowCallInputsAndSecretsTogether(t *testing.T) {
	content := "name: c\non:\n  workflow_call:\n    inputs:\n      environment:\n        required: true\n        type: string\n    secrets:\n      deployment_token:\n        required: true\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
	workflow, err := parseInlineWorkflow(t, content)
	if err != nil {
		t.Fatal(err)
	}
	if len(workflow.WorkflowCall.Inputs) != 1 || len(workflow.WorkflowCall.Secrets) != 1 {
		t.Fatalf("contract = %#v", workflow.WorkflowCall)
	}
}

func TestWorkflowCallNumberInputWithDefault(t *testing.T) {
	content := "name: c\non:\n  workflow_call:\n    inputs:\n      retries:\n        required: false\n        type: number\n        default: 3\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
	workflow, err := parseInlineWorkflow(t, content)
	if err != nil {
		t.Fatal(err)
	}
	retries := workflow.WorkflowCall.Inputs[0]
	if retries.Type != "number" || retries.Default == nil || retries.Default.Type != "number" || retries.Default.Number == nil || *retries.Default.Number != 3 {
		t.Fatalf("retries = %#v default=%#v", retries, retries.Default)
	}
}

func TestWorkflowCallStringInputWithDefault(t *testing.T) {
	content := "name: c\non:\n  workflow_call:\n    inputs:\n      environment:\n        required: false\n        type: string\n        default: staging\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
	workflow, err := parseInlineWorkflow(t, content)
	if err != nil {
		t.Fatal(err)
	}
	environment := workflow.WorkflowCall.Inputs[0]
	if environment.Default == nil || environment.Default.Type != "string" || environment.Default.String == nil || *environment.Default.String != "staging" {
		t.Fatalf("environment default = %#v", environment.Default)
	}
}

func TestWorkflowCallDeterministicMapOrdering(t *testing.T) {
	content := "name: c\non:\n  workflow_call:\n    inputs:\n      zeta:\n        required: false\n        type: string\n      alpha:\n        required: false\n        type: string\n    secrets:\n      zeta_secret:\n        required: false\n      alpha_secret:\n        required: false\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
	workflow, err := parseInlineWorkflow(t, content)
	if err != nil {
		t.Fatal(err)
	}
	if workflow.WorkflowCall.Inputs[0].Name != "alpha" || workflow.WorkflowCall.Inputs[1].Name != "zeta" {
		t.Fatalf("inputs ordering = %#v", workflow.WorkflowCall.Inputs)
	}
	if workflow.WorkflowCall.Secrets[0].Name != "alpha_secret" || workflow.WorkflowCall.Secrets[1].Name != "zeta_secret" {
		t.Fatalf("secrets ordering = %#v", workflow.WorkflowCall.Secrets)
	}
}

func TestWorkflowCallYmlAndYamlFiles(t *testing.T) {
	for _, ext := range []string{"yml", "yaml"} {
		content := "name: c\non:\n  workflow_call: {}\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
		workflow, err := parseInlineWorkflowNamed(t, "caller."+ext, content)
		if err != nil {
			t.Fatalf("%s: %v", ext, err)
		}
		if workflow.WorkflowCall == nil {
			t.Fatalf("%s: expected contract", ext)
		}
	}
}

func TestWorkflowCallMalformedInputsStructure(t *testing.T) {
	content := "name: c\non:\n  workflow_call:\n    inputs: not-a-mapping\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
	_, err := parseInlineWorkflow(t, content)
	if err == nil {
		t.Fatal("expected error for malformed inputs")
	}
	if !strings.Contains(err.Error(), "inputs") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestWorkflowCallMalformedSecretsStructure(t *testing.T) {
	content := "name: c\non:\n  workflow_call:\n    secrets: not-a-mapping\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
	_, err := parseInlineWorkflow(t, content)
	if err == nil {
		t.Fatal("expected error for malformed secrets")
	}
	if !strings.Contains(err.Error(), "secrets") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestWorkflowCallUnsupportedInputType(t *testing.T) {
	content := "name: c\non:\n  workflow_call:\n    inputs:\n      payload:\n        required: false\n        type: object\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
	_, err := parseInlineWorkflow(t, content)
	if err == nil {
		t.Fatal("expected error for unsupported input type")
	}
	if !strings.Contains(err.Error(), "type") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestOrdinaryWorkflowHasNoContract(t *testing.T) {
	workflow, err := parseInlineWorkflow(t, "name: c\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n")
	if err != nil {
		t.Fatal(err)
	}
	if workflow.WorkflowCall != nil {
		t.Fatalf("expected nil contract, got %#v", workflow.WorkflowCall)
	}
}

func TestWorkflowCallNoRegressionInTriggerParsing(t *testing.T) {
	workflow := parseDeploy(t)
	if !hasTrigger(workflow.Triggers, "pull_request_target") || !hasTrigger(workflow.Triggers, "workflow_dispatch") {
		t.Fatalf("regression: triggers = %#v", workflow.Triggers)
	}
	if workflow.WorkflowCall != nil {
		t.Fatalf("deploy fixture must not declare workflow_call: %#v", workflow.WorkflowCall)
	}
}
