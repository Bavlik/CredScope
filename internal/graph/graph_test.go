package graph

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/credscope/credscope/internal/domain"
)

func TestBuildStableIDsDeduplicationAndOrdering(t *testing.T) {
	parsed := domain.ParsedRepository{
		Findings: []domain.Finding{
			{ID: "finding:b", RuleID: "demo", Credential: domain.CredentialIdentity{Label: "DEMO_TOKEN", Fingerprint: "sha256:b"}, Location: domain.Location{Path: "b.env", Line: 2}, Source: "test"},
			{ID: "finding:a", RuleID: "demo", Credential: domain.CredentialIdentity{Label: "DEMO_TOKEN", Fingerprint: "sha256:a"}, Location: domain.Location{Path: "a.env", Line: 1}, Source: "test"},
		},
		Workflows: []domain.Workflow{{Name: "build", File: ".github/workflows/build.yml", Evidence: testEvidence(".github/workflows/build.yml", 1, "workflow"), References: []domain.Reference{testReference("DEMO_TOKEN", ".github/workflows/build.yml", 3)}}},
	}
	first := Build(parsed)
	second := Build(parsed)
	if !reflect.DeepEqual(first, second) {
		t.Fatal("repeated graph build was not deterministic")
	}
	if len(first.Credentials) != 1 {
		t.Fatalf("credentials = %d, want 1", len(first.Credentials))
	}
	if got := first.Credentials[0].Fingerprints; !reflect.DeepEqual(got, []string{"sha256:a", "sha256:b"}) {
		t.Fatalf("fingerprints = %#v", got)
	}
	seenNodes := map[string]bool{}
	for index, node := range first.Graph.Nodes {
		if seenNodes[node.ID] {
			t.Fatalf("duplicate node ID %q", node.ID)
		}
		seenNodes[node.ID] = true
		if index > 0 && first.Graph.Nodes[index-1].ID > node.ID {
			t.Fatal("nodes are not sorted")
		}
	}
	seenEdges := map[string]bool{}
	for index, edge := range first.Graph.Edges {
		if edge.ID == "" || seenEdges[edge.ID] {
			t.Fatalf("missing or duplicate edge ID %q", edge.ID)
		}
		seenEdges[edge.ID] = true
		if index > 0 && first.Graph.Edges[index-1].ID > edge.ID {
			t.Fatal("edges are not sorted")
		}
	}
}

func TestMutableGraphDeduplicatesEquivalentNodesAndEdges(t *testing.T) {
	g := newMutable()
	ev := testEvidence("compose.yml", 4, "services.api")
	a := g.addNode(domain.NodeCredential, "token", "TOKEN", nil, nil, []domain.Evidence{ev}, domain.ConfidenceConfirmed)
	aAgain := g.addNode(domain.NodeCredential, "token", "TOKEN", nil, nil, []domain.Evidence{ev}, domain.ConfidenceConfirmed)
	b := g.addNode(domain.NodeComposeService, "compose.yml\x00api", "api", &ev.Location, nil, []domain.Evidence{ev}, domain.ConfidenceConfirmed)
	firstEdge := g.addEdge(a, b, domain.EdgePassedTo, []domain.Evidence{ev}, domain.ConfidenceConfirmed)
	secondEdge := g.addEdge(aAgain, b, domain.EdgePassedTo, []domain.Evidence{ev}, domain.ConfidenceConfirmed)
	finished := g.finish()
	if a != aAgain || firstEdge != secondEdge {
		t.Fatal("equivalent graph identities differed")
	}
	if len(finished.Nodes) != 2 || len(finished.Edges) != 1 {
		t.Fatalf("nodes=%d edges=%d", len(finished.Nodes), len(finished.Edges))
	}
}

func TestTraverseCycleSafeDistinctPathsAndDepth(t *testing.T) {
	nodes := []domain.Node{
		{ID: "cred", Type: domain.NodeCredential, Label: "TOKEN", Confidence: domain.ConfidenceConfirmed},
		{ID: "a", Type: domain.NodeJob, Label: "a", Confidence: domain.ConfidenceConfirmed},
		{ID: "b", Type: domain.NodeJob, Label: "b", Confidence: domain.ConfidenceConfirmed},
		{ID: "c", Type: domain.NodeEnvironment, Label: "production", Confidence: domain.ConfidenceMedium},
	}
	edges := []domain.Edge{
		{ID: "1", From: "cred", To: "a", Type: domain.EdgePassedTo, Confidence: domain.ConfidenceConfirmed},
		{ID: "2", From: "cred", To: "b", Type: domain.EdgePassedTo, Confidence: domain.ConfidenceHigh},
		{ID: "3", From: "a", To: "c", Type: domain.EdgeUsesEnvironment, Confidence: domain.ConfidenceMedium},
		{ID: "4", From: "b", To: "c", Type: domain.EdgeUsesEnvironment, Confidence: domain.ConfidenceMedium},
		{ID: "5", From: "c", To: "a", Type: domain.EdgeDependsOn, Confidence: domain.ConfidenceLow},
	}
	paths := Traverse(domain.Graph{Nodes: nodes, Edges: edges}, "cred", 8)
	if len(paths) != 5 {
		t.Fatalf("paths = %d, want 5 distinct cycle-safe prefixes", len(paths))
	}
	var toC int
	for _, path := range paths {
		if path.Nodes[len(path.Nodes)-1].ID == "c" {
			toC++
			if path.Confidence != domain.ConfidenceMedium {
				t.Fatalf("path confidence = %q, want medium", path.Confidence)
			}
		}
	}
	if toC != 2 {
		t.Fatalf("paths to c = %d, want 2", toC)
	}
	limited := Traverse(domain.Graph{Nodes: nodes, Edges: edges}, "cred", 1)
	if len(limited) != 2 || !limited[0].Truncated || !limited[1].Truncated {
		t.Fatalf("depth-limited paths = %#v", limited)
	}
}

func TestBuildAndMarshalNeverContainRawSecret(t *testing.T) {
	const raw = "PHASE3_RAW_SECRET_MUST_NOT_APPEAR"
	parsed := domain.ParsedRepository{Findings: []domain.Finding{{ID: "finding:safe", RuleID: "demo", Credential: domain.CredentialIdentity{Label: "DEMO_TOKEN", Fingerprint: "sha256:safe"}, Source: "test"}}}
	data, err := json.Marshal(Build(parsed))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), raw) {
		t.Fatal("raw secret leaked into graph serialization")
	}
}

func testEvidence(path string, line int, field string) domain.Evidence {
	return domain.Evidence{Location: domain.Location{Path: path, Line: line}, Field: field, Source: "test", Confidence: domain.ConfidenceConfirmed}
}

func testReference(name, path string, line int) domain.Reference {
	return domain.Reference{Kind: domain.ReferenceSecret, Name: name, Expression: "${{ secrets." + name + " }}", Evidence: testEvidence(path, line, "secret")}
}
