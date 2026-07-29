package analysis

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/Bavlik/CredScope/internal/domain"
)

func rwCallerJobWithSecrets(file, id, uses string, secrets ...domain.ReusableWorkflowSecret) domain.WorkflowJob {
	return domain.WorkflowJob{
		ID:                      id,
		Evidence:                rwEvidence(file, 2, "jobs."+id),
		ReusableWorkflow:        &domain.ActionReference{Reference: uses, Local: true, Evidence: rwEvidence(file, 2, "jobs."+id+".uses")},
		ReusableWorkflowSecrets: secrets,
	}
}

func rwSecretBinding(alias, file string, line int, sourceName string) domain.ReusableWorkflowSecret {
	return domain.ReusableWorkflowSecret{
		Name:       alias,
		References: []domain.Reference{rwReference(sourceName, file, line)},
		Evidence:   rwEvidence(file, line, "jobs.call.secrets."+alias),
	}
}

func rwCalleeWorkflowWithContract(file, alias string) domain.Workflow {
	usage := domain.WorkflowJob{ID: "use", Evidence: rwEvidence(file, 2, "jobs.use"), References: []domain.Reference{rwReference(alias, file, 3)}}
	return domain.Workflow{
		Name: file, File: file, Evidence: rwEvidence(file, 1, "workflow"),
		Triggers:     []domain.WorkflowTrigger{{Name: "workflow_call", Evidence: rwEvidence(file, 1, "on")}},
		WorkflowCall: &domain.ReusableWorkflowContract{Secrets: []domain.ReusableWorkflowSecretDefinition{{Name: alias, Required: true, Evidence: rwEvidence(file, 2, "on.workflow_call.secrets."+alias)}}},
		Jobs:         []domain.WorkflowJob{usage},
		References:   usage.References,
	}
}

func forwardingEdgeInResult(result domain.AnalysisResult, fromLabel, toLabel string) bool {
	fromID, toID := "", ""
	for _, c := range result.Graph.Nodes {
		if c.Type != domain.NodeCredential {
			continue
		}
		if c.Label == fromLabel {
			fromID = c.ID
		}
		if c.Label == toLabel {
			toID = c.ID
		}
	}
	if fromID == "" || toID == "" {
		return false
	}
	for _, e := range result.Graph.Edges {
		if e.From == fromID && e.To == toID && e.Type == domain.EdgeExplicitlyForwardedTo {
			return true
		}
	}
	return false
}

func TestAnalyzeForwardsExplicitAliasThroughRealPipeline(t *testing.T) {
	caller := rwWorkflow(".github/workflows/caller.yml", []string{"push"},
		rwCallerJobWithSecrets(".github/workflows/caller.yml", "call", "./.github/workflows/callee.yml",
			rwSecretBinding("deployment_token", ".github/workflows/caller.yml", 3, "PROD_TOKEN")))
	callee := rwCalleeWorkflowWithContract(".github/workflows/callee.yml", "deployment_token")
	result := analyzeOrFatal(t, domain.ParsedRepository{Workflows: []domain.Workflow{caller, callee}})

	if !forwardingEdgeInResult(result, "PROD_TOKEN", "deployment_token") {
		t.Fatal("expected PROD_TOKEN -> deployment_token forwarding edge through the real Analyze pipeline")
	}
	credential := findCredential(result, "PROD_TOKEN")
	if credential == nil {
		t.Fatalf("PROD_TOKEN credential missing; labels = %v", credentialLabels(result))
	}
}

func TestAnalyzeUndeclaredAliasProducesWarningNoForwarding(t *testing.T) {
	caller := rwWorkflow(".github/workflows/caller.yml", []string{"push"},
		rwCallerJobWithSecrets(".github/workflows/caller.yml", "call", "./.github/workflows/callee.yml",
			rwSecretBinding("not_declared", ".github/workflows/caller.yml", 3, "PROD_TOKEN")))
	callee := rwCalleeWorkflowWithContract(".github/workflows/callee.yml", "deployment_token")
	result := analyzeOrFatal(t, domain.ParsedRepository{Workflows: []domain.Workflow{caller, callee}})

	if forwardingEdgeInResult(result, "PROD_TOKEN", "deployment_token") {
		t.Fatal("undeclared alias must not forward")
	}
	found := false
	for _, w := range result.Warnings {
		if strings.Contains(w, "not_declared") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a warning about the undeclared alias: %v", result.Warnings)
	}
}

func TestAnalyzeNestedForwardingThroughRealResolver(t *testing.T) {
	fileA := ".github/workflows/a.yml"
	fileB := ".github/workflows/b.yml"
	fileC := ".github/workflows/c.yml"

	a := rwWorkflow(fileA, []string{"push"}, rwCallerJobWithSecrets(fileA, "call", "./.github/workflows/b.yml", rwSecretBinding("middle_token", fileA, 3, "ROOT_TOKEN")))
	bJob := rwCallerJobWithSecrets(fileB, "call", "./.github/workflows/c.yml", rwSecretBinding("final_token", fileB, 3, "middle_token"))
	b := domain.Workflow{
		Name: fileB, File: fileB, Evidence: rwEvidence(fileB, 1, "workflow"),
		Triggers:     []domain.WorkflowTrigger{{Name: "workflow_call", Evidence: rwEvidence(fileB, 1, "on")}},
		WorkflowCall: &domain.ReusableWorkflowContract{Secrets: []domain.ReusableWorkflowSecretDefinition{{Name: "middle_token", Required: true, Evidence: rwEvidence(fileB, 2, "on.workflow_call.secrets.middle_token")}}},
		Jobs:         []domain.WorkflowJob{bJob},
		References:   []domain.Reference{rwReference("middle_token", fileB, 3)},
	}
	c := rwCalleeWorkflowWithContract(fileC, "final_token")

	result := analyzeOrFatal(t, domain.ParsedRepository{Workflows: []domain.Workflow{a, b, c}})

	if !forwardingEdgeInResult(result, "ROOT_TOKEN", "middle_token") {
		t.Fatal("missing ROOT_TOKEN -> middle_token forwarding edge")
	}
	if !forwardingEdgeInResult(result, "middle_token", "final_token") {
		t.Fatal("missing middle_token -> final_token forwarding edge")
	}
	credential := findCredential(result, "ROOT_TOKEN")
	if credential == nil {
		t.Fatalf("ROOT_TOKEN missing; labels = %v", credentialLabels(result))
	}
	reachedFinal := false
	for _, path := range credential.EvidencePaths {
		for _, node := range path.Nodes {
			if node.Label == "final_token" {
				reachedFinal = true
			}
		}
	}
	if !reachedFinal {
		t.Fatal("ROOT_TOKEN's evidence paths must reach final_token through the two-hop forwarding chain")
	}
}

func TestAnalyzeSecretForwardingTwiceIsByteIdentical(t *testing.T) {
	caller := rwWorkflow(".github/workflows/caller.yml", []string{"push"},
		rwCallerJobWithSecrets(".github/workflows/caller.yml", "call", "./.github/workflows/callee.yml",
			rwSecretBinding("deployment_token", ".github/workflows/caller.yml", 3, "PROD_TOKEN")))
	callee := rwCalleeWorkflowWithContract(".github/workflows/callee.yml", "deployment_token")
	parsed := domain.ParsedRepository{Workflows: []domain.Workflow{caller, callee}}

	first := analyzeOrFatal(t, parsed)
	second := analyzeOrFatal(t, parsed)
	firstJSON, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	secondJSON, err := json.Marshal(second)
	if err != nil {
		t.Fatal(err)
	}
	if string(firstJSON) != string(secondJSON) {
		t.Fatal("secret-forwarding analysis is not deterministic across repeated runs")
	}
}

func TestAnalyzeSecretForwardingDoesNotMutateInput(t *testing.T) {
	caller := rwWorkflow(".github/workflows/caller.yml", []string{"push"},
		rwCallerJobWithSecrets(".github/workflows/caller.yml", "call", "./.github/workflows/callee.yml",
			rwSecretBinding("deployment_token", ".github/workflows/caller.yml", 3, "PROD_TOKEN")))
	callee := rwCalleeWorkflowWithContract(".github/workflows/callee.yml", "deployment_token")
	parsed := domain.ParsedRepository{Workflows: []domain.Workflow{caller, callee}}

	before, err := json.Marshal(parsed)
	if err != nil {
		t.Fatal(err)
	}
	beforeCopy := domain.ParsedRepository{Workflows: append([]domain.Workflow(nil), parsed.Workflows...)}

	analyzeOrFatal(t, parsed)

	after, err := json.Marshal(parsed)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("Analyze mutated its input ParsedRepository during secret forwarding (JSON diverged)")
	}
	if !reflect.DeepEqual(beforeCopy.Workflows, parsed.Workflows) {
		t.Fatal("Analyze mutated its input ParsedRepository during secret forwarding (DeepEqual diverged)")
	}
}
