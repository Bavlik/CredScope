package mermaid

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	"github.com/Bavlik/CredScope/internal/domain"
	"github.com/Bavlik/CredScope/internal/reporters"
)

func TestMermaidStableSanitizedAndNoDirectives(t *testing.T) {
	input := reporters.Input{Scan: reporters.Scan{Repository: "demo`\n%%{init:evil}"}, Analysis: domain.AnalysisResult{PolicyVersion: "v2", RuleCatalogVersion: "v2", Profile: domain.ProfileSelection{Requested: domain.ProfileAuto, Selected: domain.ProfileAuto, Source: "conservative_fallback", Reason: "test context", Assumptions: []string{"runtime unknown"}}, Graph: domain.Graph{Nodes: []domain.Node{{ID: "a", Type: domain.NodeCredential, Label: `TOKEN\"] --> X\nclick a "https://evil" %%{init}`}, {ID: "b", Type: domain.NodeWorkflow, Label: "deploy"}}, Edges: []domain.Edge{{ID: "e", From: "a", To: "b", Type: domain.EdgeReferencedBy}}}}}
	var first, second bytes.Buffer
	if err := New().Render(&first, input, reporters.Options{}); err != nil {
		t.Fatal(err)
	}
	if err := New().Render(&second, input, reporters.Options{}); err != nil {
		t.Fatal(err)
	}
	if first.String() != second.String() {
		t.Fatal("Mermaid differs")
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(first.Bytes())); got != "967b7148e166ce4dc0b4e8660f8a5589dfe3853278aec80fa98262e7ff8113d1" {
		t.Fatalf("Mermaid golden hash = %s", got)
	}
	output := first.String()
	if !strings.Contains(output, "```mermaid\ngraph TD") || !strings.Contains(output, "-->|configured_in · confirmed_static_data_flow|") {
		t.Fatal(output)
	}
	if strings.Contains(output, "%%{init") || strings.Contains(output, "click a") || strings.Contains(output, "https://") || strings.Contains(output, "RAW_SECRET_NOT_IN_MODEL") {
		t.Fatalf("injection survived:\n%s", output)
	}
}

func TestMermaidEmptyAndBounded(t *testing.T) {
	var empty bytes.Buffer
	if err := New().Render(&empty, reporters.Input{}, reporters.Options{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(empty.String(), `empty_graph["No graph nodes"]`) {
		t.Fatal(empty.String())
	}
	input := reporters.Input{Analysis: domain.AnalysisResult{Graph: domain.Graph{}}}
	for index := 0; index < MaxNodes+2; index++ {
		input.Analysis.Graph.Nodes = append(input.Analysis.Graph.Nodes, domain.Node{ID: fmt.Sprintf("node:%03d", index), Type: domain.NodeFile, Label: "node"})
	}
	var bounded bytes.Buffer
	if err := New().Render(&bounded, input, reporters.Options{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(bounded.String(), "Graph summarized at 250 nodes") {
		t.Fatal("missing bound warning")
	}
}

func TestMermaidDeduplicatesEquivalentRelationships(t *testing.T) {
	input := reporters.Input{Analysis: domain.AnalysisResult{Graph: domain.Graph{
		Nodes: []domain.Node{{ID: "a", Type: domain.NodeCredential, Label: "TOKEN"}, {ID: "b", Type: domain.NodeWorkflow, Label: "workflow"}},
		Edges: []domain.Edge{{ID: "edge:one", From: "a", To: "b", Type: domain.EdgeReferencedBy}, {ID: "edge:two", From: "a", To: "b", Type: domain.EdgeReferencedBy}},
	}}}
	var output bytes.Buffer
	if err := New().Render(&output, input, reporters.Options{}); err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(output.String(), "-->|configured_in · confirmed_static_data_flow|"); got != 1 {
		t.Fatalf("equivalent edges emitted %d times:\n%s", got, output.String())
	}
}

func FuzzMermaidLabelDoesNotCreateDirectives(f *testing.F) {
	for _, seed := range []string{`safe`, `"]\nclick x "https://example.invalid"`, `%%{init: {}}`, "```mermaid", `</script>`} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		if len(value) > 1<<16 {
			t.Skip()
		}
		got := label(value)
		lower := strings.ToLower(got)
		for _, forbidden := range []string{"%%{", "click", "http://", "https://", "\n", "\r"} {
			if strings.Contains(lower, forbidden) {
				t.Fatalf("unsafe Mermaid token %q survived in %q", forbidden, got)
			}
		}
	})
}
