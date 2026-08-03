package graph

import (
	"fmt"
	"testing"

	"github.com/Bavlik/CredScope/internal/domain"
)

// linearGraph builds a straight-line chain n0 -> n1 -> ... -> n{length}, all
// EdgeExplicitlyForwardedTo/EvidenceConfirmedDataFlow/ConfidenceConfirmed.
// metadataFor(i), if non-nil, supplies edge i's (1-indexed) metadata; a nil
// return for a given i leaves that edge's Metadata unset (an ordinary edge).
func linearGraph(length int, metadataFor func(i int) map[string]string) domain.Graph {
	nodes := []domain.Node{{ID: "n0", Type: domain.NodeCredential}}
	var edges []domain.Edge
	for i := 1; i <= length; i++ {
		id := fmt.Sprintf("n%d", i)
		nodes = append(nodes, domain.Node{ID: id, Type: domain.NodeCredential})
		e := domain.Edge{
			ID: fmt.Sprintf("e%d", i), From: fmt.Sprintf("n%d", i-1), To: id,
			Type: domain.EdgeExplicitlyForwardedTo, EvidenceKind: domain.EvidenceConfirmedDataFlow, Confidence: domain.ConfidenceConfirmed,
		}
		if metadataFor != nil {
			e.Metadata = metadataFor(i)
		}
		edges = append(edges, e)
	}
	return domain.Graph{Nodes: nodes, Edges: edges}
}

func maxReachableIndexAtDepth(graph domain.Graph, start string, length, maxDepth int) int {
	paths := Traverse(graph, start, maxDepth)
	max := -1
	for i := 0; i <= length; i++ {
		if reachesNode(paths, fmt.Sprintf("n%d", i)) && i > max {
			max = i
		}
	}
	return max
}

// 12/13/14/15. The composite-forwarding-edge exemption activates only for
// the exact metadata value "true" on composite_action_forwarding_edge — a
// missing marker, the value "false", the wrong-case value "TRUE", and an
// ordinary edge with no such key at all must all behave identically to a
// fully untagged chain (no exemption granted, no normalization introduced).
func TestTraversalMarkerStrictnessNoExemptionWithoutExactMarker(t *testing.T) {
	const length = DefaultMaxDepth + 2
	baseline := linearGraph(length, nil)
	baselineMax := maxReachableIndexAtDepth(baseline, "n0", length, DefaultMaxDepth)
	if baselineMax != DefaultMaxDepth {
		t.Fatalf("sanity check failed: untagged baseline should reach exactly node %d, got %d", DefaultMaxDepth, baselineMax)
	}

	cases := map[string]map[string]string{
		"missing_marker":   nil,
		"empty_metadata":   {},
		"value_false":      {compositeActionForwardingEdgeMetadataKey: "false"},
		"value_wrong_case": {compositeActionForwardingEdgeMetadataKey: "TRUE"},
	}
	for name, edge1Metadata := range cases {
		t.Run(name, func(t *testing.T) {
			g := linearGraph(length, func(i int) map[string]string {
				if i == 1 {
					return edge1Metadata
				}
				return nil
			})
			got := maxReachableIndexAtDepth(g, "n0", length, DefaultMaxDepth)
			if got != baselineMax {
				t.Fatalf("%s: expected no exemption (max reachable %d, same as untagged baseline), got %d", name, baselineMax, got)
			}
		})
	}
}

// Same strictness proof for the hop marker specifically: a wrong/missing
// composite_action_forwarding_hop value must never consume the composite hop
// budget, and must not by itself grant the general-depth exemption either
// (the two markers are independent; an edge tagged only with a malformed hop
// value and no valid edge marker is simply an ordinary edge).
func TestTraversalHopMarkerStrictnessNoExemptionWithoutExactMarker(t *testing.T) {
	const length = DefaultMaxDepth + 2
	cases := map[string]map[string]string{
		"missing_marker":   nil,
		"value_false":      {compositeActionForwardingHopMetadataKey: "false"},
		"value_wrong_case": {compositeActionForwardingHopMetadataKey: "TRUE"},
	}
	baseline := maxReachableIndexAtDepth(linearGraph(length, nil), "n0", length, DefaultMaxDepth)
	for name, edge1Metadata := range cases {
		t.Run(name, func(t *testing.T) {
			g := linearGraph(length, func(i int) map[string]string {
				if i == 1 {
					return edge1Metadata
				}
				return nil
			})
			got := maxReachableIndexAtDepth(g, "n0", length, DefaultMaxDepth)
			if got != baseline {
				t.Fatalf("%s: expected no exemption/hop consumption, max reachable should stay %d, got %d", name, baseline, got)
			}
		})
	}
}

// 16. a reusable-workflow forwarding edge remains governed only by its
// existing reusable-workflow counter (9 hops) and general-depth behavior —
// it must never receive the CA3B general-depth exemption.
func TestTraversalReusableWorkflowEdgeNotExemptFromGeneralDepth(t *testing.T) {
	const length = DefaultMaxDepth + 2
	g := linearGraph(length, func(i int) map[string]string {
		return map[string]string{reusableWorkflowHopMetadataKey: reusableWorkflowHopMetadataValue}
	})
	// MaxReusableWorkflowHops (9) is smaller than DefaultMaxDepth (12), so
	// the reusable-hop cap is the binding constraint here — exactly the
	// pre-existing, unchanged behavior.
	got := maxReachableIndexAtDepth(g, "n0", length, DefaultMaxDepth)
	if got != MaxReusableWorkflowHops {
		t.Fatalf("expected reusable-workflow chain to stop at its own hop cap (%d), got %d", MaxReusableWorkflowHops, got)
	}
}

// 17. child-binding -> child-usage (composite_action_forwarding_edge only,
// no hop tag): exempt from general depth, and does not consume a composite
// nesting hop — proven by a chain far longer than both DefaultMaxDepth and
// MaxCompositeActionForwardingHops, bounded on each side by two ordinary
// edges whose own generalDepth consumption (2, not 2+N) proves the tagged
// middle section contributes nothing to either counter.
func TestTraversalChildBindingUsageEdgeExemptNoHopConsumed(t *testing.T) {
	const taggedCount = MaxCompositeActionForwardingHops + DefaultMaxDepth + 5 // deliberately exceeds both caps
	const length = taggedCount + 4                                             // 2 ordinary edges on each side
	g := linearGraph(length, func(i int) map[string]string {
		if i <= 2 || i > length-2 {
			return nil // ordinary edge
		}
		return map[string]string{compositeActionForwardingEdgeMetadataKey: compositeActionForwardingEdgeMetadataValue}
	})
	got := maxReachableIndexAtDepth(g, "n0", length, DefaultMaxDepth)
	if got != length {
		t.Fatalf("expected the entire chain (length %d) reachable — the tagged middle section must consume neither general depth nor a composite hop, got max reachable %d", length, got)
	}
}

// 18. parent-usage -> child-binding (both markers set): exempt from general
// depth, but consumes exactly one composite nesting hop — a run of tagged
// edges longer than MaxCompositeActionForwardingHops must stop exactly at
// the hop boundary, even though the chain is far shorter than DefaultMaxDepth
// would otherwise allow were the exemption not in effect (isolated via
// leading/trailing ordinary edges whose own count stays far under
// DefaultMaxDepth).
func TestTraversalParentUsageChildBindingEdgeExemptExactlyOneHop(t *testing.T) {
	const taggedCount = MaxCompositeActionForwardingHops + 3 // deliberately exceeds the hop cap
	const length = taggedCount + 4
	g := linearGraph(length, func(i int) map[string]string {
		if i <= 2 || i > length-2 {
			return nil
		}
		return map[string]string{
			compositeActionForwardingEdgeMetadataKey: compositeActionForwardingEdgeMetadataValue,
			compositeActionForwardingHopMetadataKey:  compositeActionForwardingHopMetadataValue,
		}
	})
	got := maxReachableIndexAtDepth(g, "n0", length, DefaultMaxDepth)
	// 2 leading ordinary edges + MaxCompositeActionForwardingHops tagged
	// edges (the hop cap, exactly) is as far as the tagged run may proceed;
	// the trailing ordinary edges are never reached because the hop cap
	// blocks the tagged run first.
	want := 2 + MaxCompositeActionForwardingHops
	if got != want {
		t.Fatalf("expected the tagged run to stop exactly at the composite hop boundary (node %d), got %d", want, got)
	}
}

// 19. no other edge shape receives either marker: an ordinary edge with an
// unrelated metadata key set must still consume general depth exactly like
// any other untagged edge.
func TestTraversalUnrelatedMetadataKeyGrantsNoExemption(t *testing.T) {
	const length = DefaultMaxDepth + 2
	baseline := maxReachableIndexAtDepth(linearGraph(length, nil), "n0", length, DefaultMaxDepth)
	g := linearGraph(length, func(i int) map[string]string {
		if i == 1 {
			return map[string]string{"some_other_key": "true"}
		}
		return nil
	})
	got := maxReachableIndexAtDepth(g, "n0", length, DefaultMaxDepth)
	if got != baseline {
		t.Fatalf("an unrelated metadata key must grant no exemption, expected %d, got %d", baseline, got)
	}
}

// General-depth behavioral equivalence: maxDepth=0 (public "defaults to
// DefaultMaxDepth" contract), maxDepth=1, maxDepth=DefaultMaxDepth, one edge
// below/at/above the limit — all on a fully untagged chain, proving CA3B
// introduced no change to pre-existing boundary semantics.
func TestTraversalGeneralDepthBoundaryUnchanged(t *testing.T) {
	const length = DefaultMaxDepth + 3
	g := linearGraph(length, nil)

	cases := []struct {
		name             string
		maxDepth         int
		wantMaxReachable int
	}{
		{"maxDepth_zero_defaults_to_DefaultMaxDepth", 0, DefaultMaxDepth},
		{"maxDepth_one", 1, 1},
		{"maxDepth_DefaultMaxDepth_explicit", DefaultMaxDepth, DefaultMaxDepth},
		{"one_edge_below_limit", DefaultMaxDepth - 1, DefaultMaxDepth - 1},
		{"exactly_at_limit", DefaultMaxDepth, DefaultMaxDepth},
		{"one_edge_above_limit", DefaultMaxDepth + 1, DefaultMaxDepth + 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := maxReachableIndexAtDepth(g, "n0", length, c.maxDepth)
			if got != c.wantMaxReachable {
				t.Fatalf("maxDepth=%d: expected max reachable node %d, got %d", c.maxDepth, c.wantMaxReachable, got)
			}
		})
	}
}

// Mixed path proof: ordinary -> reusable-workflow hop -> CA3B parent-usage/
// child-binding hop -> CA3B child-binding/child-usage -> ordinary. Proves
// every counter is independently and correctly applied along one path, and
// that EvidencePath.Edges retains every edge, in order.
func TestTraversalMixedPathAllCountersIndependent(t *testing.T) {
	nodes := []domain.Node{
		{ID: "n0", Type: domain.NodeCredential},
		{ID: "n1", Type: domain.NodeCredential},
		{ID: "n2", Type: domain.NodeCredential},
		{ID: "n3", Type: domain.NodeCompositeActionInputBinding},
		{ID: "n4", Type: domain.NodeCompositeActionInputUsage},
		{ID: "n5", Type: domain.NodeCredential},
	}
	edges := []domain.Edge{
		{ID: "e1-ordinary", From: "n0", To: "n1", Type: domain.EdgeExplicitlyForwardedTo, EvidenceKind: domain.EvidenceConfirmedDataFlow, Confidence: domain.ConfidenceConfirmed},
		{ID: "e2-reusable", From: "n1", To: "n2", Type: domain.EdgeExplicitlyForwardedTo, EvidenceKind: domain.EvidenceConfirmedDataFlow, Confidence: domain.ConfidenceConfirmed, Metadata: map[string]string{reusableWorkflowHopMetadataKey: reusableWorkflowHopMetadataValue}},
		{ID: "e3-composite-hop", From: "n2", To: "n3", Type: domain.EdgeExplicitlyForwardedTo, EvidenceKind: domain.EvidenceConfirmedDataFlow, Confidence: domain.ConfidenceConfirmed, Metadata: map[string]string{compositeActionForwardingEdgeMetadataKey: compositeActionForwardingEdgeMetadataValue, compositeActionForwardingHopMetadataKey: compositeActionForwardingHopMetadataValue}},
		{ID: "e4-composite-edge", From: "n3", To: "n4", Type: domain.EdgeExplicitlyForwardedTo, EvidenceKind: domain.EvidenceConfirmedDataFlow, Confidence: domain.ConfidenceConfirmed, Metadata: map[string]string{compositeActionForwardingEdgeMetadataKey: compositeActionForwardingEdgeMetadataValue}},
		{ID: "e5-ordinary", From: "n4", To: "n5", Type: domain.EdgeExplicitlyForwardedTo, EvidenceKind: domain.EvidenceConfirmedDataFlow, Confidence: domain.ConfidenceConfirmed},
	}
	g := domain.Graph{Nodes: nodes, Edges: edges}

	paths := Traverse(g, "n0", DefaultMaxDepth)
	var winning *domain.EvidencePath
	for i := range paths {
		if paths[i].Nodes[len(paths[i].Nodes)-1].ID == "n5" {
			winning = &paths[i]
		}
	}
	if winning == nil {
		t.Fatal("expected the full mixed path to reach n5")
	}
	wantOrder := []string{"e1-ordinary", "e2-reusable", "e3-composite-hop", "e4-composite-edge", "e5-ordinary"}
	if len(winning.Edges) != len(wantOrder) {
		t.Fatalf("expected all 5 edges retained in the winning path, got %d: %#v", len(winning.Edges), winning.Edges)
	}
	for i, id := range wantOrder {
		if winning.Edges[i].ID != id {
			t.Fatalf("edge %d: expected %q, got %q — EvidencePath.Edges must preserve traversal order", i, id, winning.Edges[i].ID)
		}
	}
}

// No counter is repository-global: two independent sibling branches off the
// same root, each individually exhausting the composite hop budget, must
// each reach their own full 9-hop depth — a shared/global counter would
// incorrectly block the second branch after the first exhausts it.
func TestTraversalCompositeHopCounterNotGlobalAcrossSiblingBranches(t *testing.T) {
	nodes := []domain.Node{{ID: "root", Type: domain.NodeCredential}}
	var edges []domain.Edge
	branch := func(prefix string) {
		prev := "root"
		for i := 1; i <= MaxCompositeActionForwardingHops; i++ {
			id := fmt.Sprintf("%s%d", prefix, i)
			nodes = append(nodes, domain.Node{ID: id, Type: domain.NodeCredential})
			edges = append(edges, domain.Edge{
				ID: fmt.Sprintf("%s-e%d", prefix, i), From: prev, To: id,
				Type: domain.EdgeExplicitlyForwardedTo, EvidenceKind: domain.EvidenceConfirmedDataFlow, Confidence: domain.ConfidenceConfirmed,
				Metadata: map[string]string{compositeActionForwardingEdgeMetadataKey: compositeActionForwardingEdgeMetadataValue, compositeActionForwardingHopMetadataKey: compositeActionForwardingHopMetadataValue},
			})
			prev = id
		}
	}
	branch("a")
	branch("b")
	g := domain.Graph{Nodes: nodes, Edges: edges}

	paths := Traverse(g, "root", DefaultMaxDepth)
	lastA := fmt.Sprintf("a%d", MaxCompositeActionForwardingHops)
	lastB := fmt.Sprintf("b%d", MaxCompositeActionForwardingHops)
	if !reachesNode(paths, lastA) {
		t.Fatal("branch a must independently reach its own 9th hop")
	}
	if !reachesNode(paths, lastB) {
		t.Fatal("branch b must independently reach its own 9th hop — a global hop counter would have blocked it after branch a exhausted the budget")
	}
}
