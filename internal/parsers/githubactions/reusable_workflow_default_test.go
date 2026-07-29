package githubactions

import (
	"testing"

	"github.com/Bavlik/CredScope/internal/domain"
)

func TestWorkflowCallInputDefaultScalarValues(t *testing.T) {
	cases := []struct {
		name        string
		yamlType    string
		yamlDefault string
		wantType    string
		check       func(t *testing.T, def *domain.ReusableWorkflowInputDefault)
	}{
		{"boolean false", "boolean", "false", "boolean", func(t *testing.T, def *domain.ReusableWorkflowInputDefault) {
			if def.Boolean == nil || *def.Boolean != false {
				t.Fatalf("boolean false not preserved: %#v", def)
			}
		}},
		{"boolean true", "boolean", "true", "boolean", func(t *testing.T, def *domain.ReusableWorkflowInputDefault) {
			if def.Boolean == nil || *def.Boolean != true {
				t.Fatalf("boolean true not preserved: %#v", def)
			}
		}},
		{"number zero", "number", "0", "number", func(t *testing.T, def *domain.ReusableWorkflowInputDefault) {
			if def.Number == nil || *def.Number != 0 {
				t.Fatalf("number 0 not preserved: %#v", def)
			}
		}},
		{"number fractional", "number", "1.5", "number", func(t *testing.T, def *domain.ReusableWorkflowInputDefault) {
			if def.Number == nil || *def.Number != 1.5 {
				t.Fatalf("number 1.5 not preserved: %#v", def)
			}
		}},
		{"string empty", "string", `""`, "string", func(t *testing.T, def *domain.ReusableWorkflowInputDefault) {
			if def.String == nil || *def.String != "" {
				t.Fatalf("empty string not preserved: %#v", def)
			}
		}},
		{"string production", "string", "production", "string", func(t *testing.T, def *domain.ReusableWorkflowInputDefault) {
			if def.String == nil || *def.String != "production" {
				t.Fatalf("string production not preserved: %#v", def)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			content := "name: c\non:\n  workflow_call:\n    inputs:\n      value:\n        required: false\n        type: " + tc.yamlType + "\n        default: " + tc.yamlDefault + "\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
			workflow, err := parseInlineWorkflow(t, content)
			if err != nil {
				t.Fatal(err)
			}
			input := workflow.WorkflowCall.Inputs[0]
			if input.Default == nil {
				t.Fatal("expected non-nil default")
			}
			if input.Default.Type != tc.wantType {
				t.Fatalf("default type = %q, want %q", input.Default.Type, tc.wantType)
			}
			tc.check(t, input.Default)
		})
	}
}
