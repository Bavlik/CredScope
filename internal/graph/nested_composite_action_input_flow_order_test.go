package graph

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"testing"

	"github.com/Bavlik/CredScope/internal/compositeactionflow"
	"github.com/Bavlik/CredScope/internal/domain"
	"github.com/Bavlik/CredScope/internal/nestedcompositeactionflow"
)

// buildThreeLevelChainFlows builds the canonical three-composite-action chain
// (A -> B -> C) used to prove rendering order independence and edge
// completeness: root credential PROD_TOKEN confirmed into A's "token" input
// (CA2), A forwards into B (CA3B level 1), B forwards into C (CA3B level 2).
func buildThreeLevelChainFlows() (compositeactionflow.ConfirmedInputFlow, []nestedcompositeactionflow.ConfirmedNestedInputFlow) {
	dirA, dirB, dirC := ".github/actions/a", ".github/actions/b", ".github/actions/c"
	root := confirmedFlow("caller.yml", "deploy", 0, "call-step", dirA, "token", "PROD_TOKEN", usage(0, "stepA", 10))
	level1 := nestedInputFlow("caller.yml", "deploy", 0, "token", "PROD_TOKEN",
		[]nestedcompositeactionflow.CallPathSegment{{ParentCanonicalDirectory: dirA, ParentActionStepIndex: 0, ChildCanonicalDirectory: dirB}},
		dirA, "token", 0, "stepA", dirB, "token", nestedInputUsage(0, "stepB", 20))
	level2 := nestedInputFlow("caller.yml", "deploy", 0, "token", "PROD_TOKEN",
		[]nestedcompositeactionflow.CallPathSegment{
			{ParentCanonicalDirectory: dirA, ParentActionStepIndex: 0, ChildCanonicalDirectory: dirB},
			{ParentCanonicalDirectory: dirB, ParentActionStepIndex: 0, ChildCanonicalDirectory: dirC},
		},
		dirB, "token", 0, "stepB", dirC, "token", nestedInputUsage(0, "login", 30))
	return root, []nestedcompositeactionflow.ConfirmedNestedInputFlow{level1, level2}
}

// chainFlows builds an actionCount-deep chain (chain0 -> chain1 -> ... ->
// chain{actionCount-1}) without building the graph, so callers can freely
// reorder the returned nested flows before rendering.
func chainFlows(actionCount int) (compositeactionflow.ConfirmedInputFlow, []nestedcompositeactionflow.ConfirmedNestedInputFlow) {
	dir := func(i int) string { return fmt.Sprintf(".github/actions/chain%d", i) }
	root := confirmedFlow("caller.yml", "deploy", 0, "call-step", dir(0), "token", "PROD_TOKEN", usage(0, "step0", 10))
	var nested []nestedcompositeactionflow.ConfirmedNestedInputFlow
	var callPath []nestedcompositeactionflow.CallPathSegment
	for i := 0; i < actionCount-1; i++ {
		seg := nestedcompositeactionflow.CallPathSegment{ParentCanonicalDirectory: dir(i), ParentActionStepIndex: 0, ChildCanonicalDirectory: dir(i + 1)}
		callPath = append(append([]nestedcompositeactionflow.CallPathSegment(nil), callPath...), seg)
		nested = append(nested, nestedInputFlow("caller.yml", "deploy", 0, "token", "PROD_TOKEN", callPath,
			dir(i), "token", 0, "step0", dir(i+1), "token", nestedInputUsage(0, "step0", 10)))
	}
	return root, nested
}

func buildWithFlowOrder(root compositeactionflow.ConfirmedInputFlow, nested []nestedcompositeactionflow.ConfirmedNestedInputFlow) BuildResult {
	return BuildWithOptions(domain.ParsedRepository{}, BuildOptions{
		CompositeActionInputFlows:       compositeactionflow.Result{Flows: []compositeactionflow.ConfirmedInputFlow{root}},
		NestedCompositeActionInputFlows: nestedcompositeactionflow.Result{Flows: nested},
	})
}

func graphJSON(t *testing.T, built BuildResult) string {
	t.Helper()
	encoded, err := json.Marshal(built.Graph)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func reversedFlows(flows []nestedcompositeactionflow.ConfirmedNestedInputFlow) []nestedcompositeactionflow.ConfirmedNestedInputFlow {
	result := make([]nestedcompositeactionflow.ConfirmedNestedInputFlow, len(flows))
	for i, f := range flows {
		result[len(flows)-1-i] = f
	}
	return result
}

// 1. reversing NestedCompositeActionInputFlows.Flows produces byte-identical
// graph JSON.
func TestNestedInputFlowRenderingOrderIndependentReversed(t *testing.T) {
	root, nested := chainFlows(6)
	canonical := buildWithFlowOrder(root, nested)
	reversed := buildWithFlowOrder(root, reversedFlows(nested))
	if graphJSON(t, canonical) != graphJSON(t, reversed) {
		t.Fatal("reversing NestedCompositeActionInputFlows.Flows must not change the rendered graph")
	}
}

// 2. deepest-first ordering produces the same graph as root-to-leaf ordering.
func TestNestedInputFlowRenderingOrderIndependentDeepestFirst(t *testing.T) {
	root, nested := chainFlows(6)
	canonical := buildWithFlowOrder(root, nested)

	deepestFirst := make([]nestedcompositeactionflow.ConfirmedNestedInputFlow, len(nested))
	for i, f := range nested {
		deepestFirst[len(nested)-1-i] = f // deepest CallPath (longest) first
	}
	built := buildWithFlowOrder(root, deepestFirst)
	if graphJSON(t, canonical) != graphJSON(t, built) {
		t.Fatal("deepest-first ordering must produce the same graph as root-to-leaf ordering")
	}
}

// 3. randomly shuffling a multi-level flow set for at least 20 deterministic
// seeds produces identical graph nodes and edges.
func TestNestedInputFlowRenderingOrderIndependentShuffle(t *testing.T) {
	root, nested := chainFlows(8) // 7 nested flows, enough entropy to shuffle meaningfully
	canonical := buildWithFlowOrder(root, nested)
	canonicalJSON := graphJSON(t, canonical)

	for seed := int64(0); seed < 20; seed++ {
		shuffled := append([]nestedcompositeactionflow.ConfirmedNestedInputFlow(nil), nested...)
		rng := rand.New(rand.NewSource(seed))
		rng.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
		built := buildWithFlowOrder(root, shuffled)
		if got := graphJSON(t, built); got != canonicalJSON {
			t.Fatalf("seed %d: shuffled flow order produced a different graph", seed)
		}
	}
}

// grouped by child alias rather than depth: two independent chains sharing a
// root, interleaved by alias rather than kept in depth order, must still
// render identically to depth order.
func TestNestedInputFlowRenderingOrderIndependentGroupedByAlias(t *testing.T) {
	dirA, dirB, dirC := ".github/actions/a", ".github/actions/b", ".github/actions/c"
	root := confirmedFlow("caller.yml", "deploy", 0, "call-step", dirA, "token", "PROD_TOKEN", usage(0, "stepA", 10))
	// A forwards into two aliases on B; each alias then forwards into C.
	level1User := nestedInputFlow("caller.yml", "deploy", 0, "token", "PROD_TOKEN",
		[]nestedcompositeactionflow.CallPathSegment{{ParentCanonicalDirectory: dirA, ParentActionStepIndex: 0, ChildCanonicalDirectory: dirB}},
		dirA, "token", 0, "stepA", dirB, "user", nestedInputUsage(0, "stepUser", 20))
	level1Pass := nestedInputFlow("caller.yml", "deploy", 0, "token", "PROD_TOKEN",
		[]nestedcompositeactionflow.CallPathSegment{{ParentCanonicalDirectory: dirA, ParentActionStepIndex: 0, ChildCanonicalDirectory: dirB}},
		dirA, "token", 0, "stepA", dirB, "pass", nestedInputUsage(1, "stepPass", 21))
	level2User := nestedInputFlow("caller.yml", "deploy", 0, "token", "PROD_TOKEN",
		[]nestedcompositeactionflow.CallPathSegment{
			{ParentCanonicalDirectory: dirA, ParentActionStepIndex: 0, ChildCanonicalDirectory: dirB},
			{ParentCanonicalDirectory: dirB, ParentActionStepIndex: 0, ChildCanonicalDirectory: dirC},
		},
		dirB, "user", 0, "stepUser", dirC, "user", nestedInputUsage(0, "leafUser", 30))
	level2Pass := nestedInputFlow("caller.yml", "deploy", 0, "token", "PROD_TOKEN",
		[]nestedcompositeactionflow.CallPathSegment{
			{ParentCanonicalDirectory: dirA, ParentActionStepIndex: 0, ChildCanonicalDirectory: dirB},
			{ParentCanonicalDirectory: dirB, ParentActionStepIndex: 1, ChildCanonicalDirectory: dirC},
		},
		dirB, "pass", 1, "stepPass", dirC, "pass", nestedInputUsage(1, "leafPass", 31))

	depthOrder := []nestedcompositeactionflow.ConfirmedNestedInputFlow{level1User, level1Pass, level2User, level2Pass}
	aliasOrder := []nestedcompositeactionflow.ConfirmedNestedInputFlow{level1User, level2User, level1Pass, level2Pass}

	depthBuilt := buildWithFlowOrder(root, depthOrder)
	aliasBuilt := buildWithFlowOrder(root, aliasOrder)
	if graphJSON(t, depthBuilt) != graphJSON(t, aliasBuilt) {
		t.Fatal("grouping flows by child alias rather than depth must not change the rendered graph")
	}
}

// 4/5. a three-level chain contains every expected edge; no expected edge is
// silently absent regardless of Flows order.
func TestNestedInputFlowThreeLevelChainCompleteEdgeSet(t *testing.T) {
	root, nested := buildThreeLevelChainFlows()
	orderings := map[string][]nestedcompositeactionflow.ConfirmedNestedInputFlow{
		"root-to-leaf": nested,
		"reversed":     reversedFlows(nested),
	}
	for name, order := range orderings {
		t.Run(name, func(t *testing.T) {
			built := buildWithFlowOrder(root, order)
			credentialID := credentialIDByLabel(built, "PROD_TOKEN")
			// A's binding/usage nodes are CA2-created (root-level); their
			// metadata carries the CA2-only "caller_workflow" key. CA3B's
			// own level-1 binding for B happens to share the label "token"
			// too (ChildInputName == "token"), so a bare label lookup would
			// be ambiguous — disambiguate by the CA2-only metadata key.
			var aBinding, aUsage *domain.Node
			for _, b := range nodesByType(built.Graph.Nodes, domain.NodeCompositeActionInputBinding) {
				bCopy := b
				if _, isCA2 := bCopy.Metadata["caller_workflow"]; isCA2 && bCopy.Label == "token" {
					aBinding = &bCopy
				}
			}
			for _, u := range nodesByType(built.Graph.Nodes, domain.NodeCompositeActionInputUsage) {
				uCopy := u
				if _, isCA2 := uCopy.Metadata["caller_workflow"]; isCA2 && uCopy.Label == "stepA" {
					aUsage = &uCopy
				}
			}
			var bBinding, bUsage, cBinding, cUsage *domain.Node
			for _, b := range nodesByType(built.Graph.Nodes, domain.NodeCompositeActionInputBinding) {
				bCopy := b
				if bCopy.Metadata["child_canonical_directory"] == ".github/actions/b" {
					bBinding = &bCopy
				}
				if bCopy.Metadata["child_canonical_directory"] == ".github/actions/c" {
					cBinding = &bCopy
				}
			}
			for _, u := range nodesByType(built.Graph.Nodes, domain.NodeCompositeActionInputUsage) {
				uCopy := u
				if uCopy.Metadata["child_canonical_directory"] == ".github/actions/b" {
					bUsage = &uCopy
				}
				if uCopy.Metadata["child_canonical_directory"] == ".github/actions/c" {
					cUsage = &uCopy
				}
			}
			if credentialID == "" || aBinding == nil || aUsage == nil || bBinding == nil || bUsage == nil || cBinding == nil || cUsage == nil {
				t.Fatalf("missing expected node: cred=%q aBinding=%v aUsage=%v bBinding=%v bUsage=%v cBinding=%v cUsage=%v",
					credentialID, aBinding, aUsage, bBinding, bUsage, cBinding, cUsage)
			}
			required := []struct {
				name, from, to string
			}{
				{"credential->A binding", credentialID, aBinding.ID},
				{"A binding->A usage", aBinding.ID, aUsage.ID},
				{"A usage->B binding", aUsage.ID, bBinding.ID},
				{"B binding->B usage", bBinding.ID, bUsage.ID},
				{"B usage->C binding", bUsage.ID, cBinding.ID},
				{"C binding->C usage", cBinding.ID, cUsage.ID},
			}
			for _, req := range required {
				if forwardingEdge(built, req.from, req.to) == nil {
					t.Fatalf("%s: expected edge %s missing (from=%s to=%s)", name, req.name, req.from, req.to)
				}
			}
		})
	}
}

// 6. warnings remain identical across ordering changes.
func TestNestedInputFlowWarningsIdenticalAcrossOrdering(t *testing.T) {
	root, nested := chainFlows(6)
	diagnostics := []nestedcompositeactionflow.Diagnostic{
		nestedInputDiagnostic(nestedcompositeactionflow.DiagnosticUndeclaredInput, "caller.yml", "deploy", 0, ".github/actions/chain0", 0, ".github/actions/chain1", "mystery"),
	}
	options := func(order []nestedcompositeactionflow.ConfirmedNestedInputFlow) BuildOptions {
		return BuildOptions{
			CompositeActionInputFlows:       compositeactionflow.Result{Flows: []compositeactionflow.ConfirmedInputFlow{root}},
			NestedCompositeActionInputFlows: nestedcompositeactionflow.Result{Flows: order, Diagnostics: diagnostics},
		}
	}
	canonical := BuildWithOptions(domain.ParsedRepository{}, options(nested))
	reversed := BuildWithOptions(domain.ParsedRepository{}, options(reversedFlows(nested)))
	shuffled := append([]nestedcompositeactionflow.ConfirmedNestedInputFlow(nil), nested...)
	rand.New(rand.NewSource(7)).Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
	shuffledBuilt := BuildWithOptions(domain.ParsedRepository{}, options(shuffled))

	if len(canonical.Warnings) != len(reversed.Warnings) || len(canonical.Warnings) != len(shuffledBuilt.Warnings) {
		t.Fatalf("warning counts differ across ordering: canonical=%d reversed=%d shuffled=%d", len(canonical.Warnings), len(reversed.Warnings), len(shuffledBuilt.Warnings))
	}
	for i := range canonical.Warnings {
		if canonical.Warnings[i] != reversed.Warnings[i] || canonical.Warnings[i] != shuffledBuilt.Warnings[i] {
			t.Fatalf("warning %d differs across ordering: canonical=%q reversed=%q shuffled=%q", i, canonical.Warnings[i], reversed.Warnings[i], shuffledBuilt.Warnings[i])
		}
	}
}

// 7. the first nested edge's source ID equals the existing CA2 usage ID.
func TestNestedInputFlowLevelOneSourceIsExistingCA2UsageID(t *testing.T) {
	built := oneHopScenario()
	ca2Usage := findByLabel(built.Graph.Nodes, domain.NodeCompositeActionInputUsage, "authenticate")
	if ca2Usage == nil {
		t.Fatal("expected CA2's own usage node to exist")
	}
	var hopEdge *domain.Edge
	for i := range built.Graph.Edges {
		e := &built.Graph.Edges[i]
		if e.Metadata[compositeActionForwardingHopMetadataKey] == compositeActionForwardingHopMetadataValue {
			hopEdge = e
		}
	}
	if hopEdge == nil {
		t.Fatal("expected the level-1 forwarding-hop edge to exist")
	}
	if hopEdge.From != ca2Usage.ID {
		t.Fatalf("level-1 nested edge source %q must equal CA2's own usage node ID %q", hopEdge.From, ca2Usage.ID)
	}
	// no duplicate A-usage node is fabricated: exactly one usage node labeled
	// "authenticate" exists.
	count := 0
	for _, n := range nodesByType(built.Graph.Nodes, domain.NodeCompositeActionInputUsage) {
		if n.Label == "authenticate" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected exactly one CA2 usage node labeled %q, got %d", "authenticate", count)
	}
}

// 8. a second-level nested edge's source ID equals the first child usage ID.
func TestNestedInputFlowLevelTwoSourceIsFirstChildUsageID(t *testing.T) {
	root, nested := buildThreeLevelChainFlows()
	built := buildWithFlowOrder(root, nested)

	var bUsage *domain.Node
	for _, u := range nodesByType(built.Graph.Nodes, domain.NodeCompositeActionInputUsage) {
		uCopy := u
		if uCopy.Metadata["child_canonical_directory"] == ".github/actions/b" {
			bUsage = &uCopy
		}
	}
	if bUsage == nil {
		t.Fatal("expected B's own CA3B usage node to exist")
	}
	var cBinding *domain.Node
	for _, b := range nodesByType(built.Graph.Nodes, domain.NodeCompositeActionInputBinding) {
		bCopy := b
		if bCopy.Metadata["child_canonical_directory"] == ".github/actions/c" {
			cBinding = &bCopy
		}
	}
	if cBinding == nil {
		t.Fatal("expected C's binding node to exist")
	}
	edge := forwardingEdge(built, bUsage.ID, cBinding.ID)
	if edge == nil {
		t.Fatal("expected the level-2 nested edge (B usage -> C binding) to exist with source == B's own usage node ID")
	}
}

// 9. the source ID is different for two root workflow calls.
func TestNestedInputFlowSourceIDDiffersAcrossRootCalls(t *testing.T) {
	dirA, dirB := ".github/actions/a", ".github/actions/b"
	prodRoot := confirmedFlow("caller.yml", "deploy", 0, "prod-step", dirA, "token", "PROD_TOKEN", usage(0, "stepA", 10))
	stagingRoot := confirmedFlow("caller.yml", "deploy", 1, "staging-step", dirA, "token", "STAGING_TOKEN", usage(0, "stepA", 10))
	prodNested := nestedInputFlow("caller.yml", "deploy", 0, "token", "PROD_TOKEN",
		[]nestedcompositeactionflow.CallPathSegment{{ParentCanonicalDirectory: dirA, ParentActionStepIndex: 0, ChildCanonicalDirectory: dirB}},
		dirA, "token", 0, "stepA", dirB, "token", nestedInputUsage(0, "login", 20))
	stagingNested := nestedInputFlow("caller.yml", "deploy", 1, "token", "STAGING_TOKEN",
		[]nestedcompositeactionflow.CallPathSegment{{ParentCanonicalDirectory: dirA, ParentActionStepIndex: 0, ChildCanonicalDirectory: dirB}},
		dirA, "token", 0, "stepA", dirB, "token", nestedInputUsage(0, "login", 20))

	built := BuildWithOptions(domain.ParsedRepository{}, BuildOptions{
		CompositeActionInputFlows:       compositeactionflow.Result{Flows: []compositeactionflow.ConfirmedInputFlow{prodRoot, stagingRoot}},
		NestedCompositeActionInputFlows: nestedcompositeactionflow.Result{Flows: []nestedcompositeactionflow.ConfirmedNestedInputFlow{prodNested, stagingNested}},
	})

	var prodHop, stagingHop *domain.Edge
	for i := range built.Graph.Edges {
		e := &built.Graph.Edges[i]
		if e.Metadata[compositeActionForwardingHopMetadataKey] != compositeActionForwardingHopMetadataValue {
			continue
		}
		if e.Metadata["root_caller_step_index"] == "0" {
			prodHop = e
		}
		if e.Metadata["root_caller_step_index"] == "1" {
			stagingHop = e
		}
	}
	if prodHop == nil || stagingHop == nil {
		t.Fatalf("expected both hop edges present: prod=%v staging=%v", prodHop, stagingHop)
	}
	if prodHop.From == stagingHop.From {
		t.Fatal("two root workflow calls must produce distinct parent-usage source node IDs")
	}
}

// 10. the source ID is different for two diamond paths reaching the same
// canonical child.
func TestNestedInputFlowSourceIDDiffersAcrossDiamondPaths(t *testing.T) {
	dirA, dirB, dirC, dirD := ".github/actions/a", ".github/actions/b", ".github/actions/c", ".github/actions/d"
	root := confirmedFlow("caller.yml", "deploy", 0, "call-step", dirA, "token", "PROD_TOKEN", usage(0, "stepB", 10), usage(1, "stepC", 11))
	intoB := nestedInputFlow("caller.yml", "deploy", 0, "token", "PROD_TOKEN",
		[]nestedcompositeactionflow.CallPathSegment{{ParentCanonicalDirectory: dirA, ParentActionStepIndex: 0, ChildCanonicalDirectory: dirB}},
		dirA, "token", 0, "stepB", dirB, "token", nestedInputUsage(0, "stepD", 20))
	intoC := nestedInputFlow("caller.yml", "deploy", 0, "token", "PROD_TOKEN",
		[]nestedcompositeactionflow.CallPathSegment{{ParentCanonicalDirectory: dirA, ParentActionStepIndex: 1, ChildCanonicalDirectory: dirC}},
		dirA, "token", 1, "stepC", dirC, "token", nestedInputUsage(0, "stepD", 20))
	viaB := nestedInputFlow("caller.yml", "deploy", 0, "token", "PROD_TOKEN",
		[]nestedcompositeactionflow.CallPathSegment{
			{ParentCanonicalDirectory: dirA, ParentActionStepIndex: 0, ChildCanonicalDirectory: dirB},
			{ParentCanonicalDirectory: dirB, ParentActionStepIndex: 0, ChildCanonicalDirectory: dirD},
		},
		dirB, "token", 0, "stepD", dirD, "secret", nestedInputUsage(0, "login", 30))
	viaC := nestedInputFlow("caller.yml", "deploy", 0, "token", "PROD_TOKEN",
		[]nestedcompositeactionflow.CallPathSegment{
			{ParentCanonicalDirectory: dirA, ParentActionStepIndex: 1, ChildCanonicalDirectory: dirC},
			{ParentCanonicalDirectory: dirC, ParentActionStepIndex: 0, ChildCanonicalDirectory: dirD},
		},
		dirC, "token", 0, "stepD", dirD, "secret", nestedInputUsage(0, "login", 30))

	built := BuildWithOptions(domain.ParsedRepository{}, BuildOptions{
		CompositeActionInputFlows:       compositeactionflow.Result{Flows: []compositeactionflow.ConfirmedInputFlow{root}},
		NestedCompositeActionInputFlows: nestedcompositeactionflow.Result{Flows: []nestedcompositeactionflow.ConfirmedNestedInputFlow{intoB, intoC, viaB, viaC}},
	})

	var dBindings []domain.Node
	for _, b := range nodesByType(built.Graph.Nodes, domain.NodeCompositeActionInputBinding) {
		if b.Metadata["child_canonical_directory"] == dirD {
			dBindings = append(dBindings, b)
		}
	}
	if len(dBindings) != 2 {
		t.Fatalf("expected two D binding nodes, got %d", len(dBindings))
	}
	edge0 := forwardingEdgesTo(built, dBindings[0].ID)
	edge1 := forwardingEdgesTo(built, dBindings[1].ID)
	if len(edge0) != 1 || len(edge1) != 1 {
		t.Fatalf("expected exactly one inbound forwarding edge per D binding, got %d and %d", len(edge0), len(edge1))
	}
	if edge0[0].From == edge1[0].From {
		t.Fatal("two diamond paths reaching the same canonical child D must have distinct parent-usage source node IDs")
	}
}

// 11. no duplicate semantic usage node is created under two IDs: a single
// parent usage node shared as the forwarding source for two sibling child
// aliases (the Part D two-alias pattern, one level deep) must render as
// exactly one usage node, referenced by both downstream edges.
func TestNestedInputFlowNoDuplicateUsageNodeUnderTwoIDs(t *testing.T) {
	dirA, dirB, dirC := ".github/actions/a", ".github/actions/b", ".github/actions/c"
	root := confirmedFlow("caller.yml", "deploy", 0, "call-step", dirA, "token", "PROD_TOKEN", usage(0, "stepA", 10))
	level1 := nestedInputFlow("caller.yml", "deploy", 0, "token", "PROD_TOKEN",
		[]nestedcompositeactionflow.CallPathSegment{{ParentCanonicalDirectory: dirA, ParentActionStepIndex: 0, ChildCanonicalDirectory: dirB}},
		dirA, "token", 0, "stepA", dirB, "token", nestedInputUsage(0, "stepB", 20))
	level2User := nestedInputFlow("caller.yml", "deploy", 0, "token", "PROD_TOKEN",
		[]nestedcompositeactionflow.CallPathSegment{
			{ParentCanonicalDirectory: dirA, ParentActionStepIndex: 0, ChildCanonicalDirectory: dirB},
			{ParentCanonicalDirectory: dirB, ParentActionStepIndex: 0, ChildCanonicalDirectory: dirC},
		},
		dirB, "token", 0, "stepB", dirC, "user", nestedInputUsage(0, "stepUser", 30))
	level2Pass := nestedInputFlow("caller.yml", "deploy", 0, "token", "PROD_TOKEN",
		[]nestedcompositeactionflow.CallPathSegment{
			{ParentCanonicalDirectory: dirA, ParentActionStepIndex: 0, ChildCanonicalDirectory: dirB},
			{ParentCanonicalDirectory: dirB, ParentActionStepIndex: 0, ChildCanonicalDirectory: dirC},
		},
		dirB, "token", 0, "stepB", dirC, "pass", nestedInputUsage(1, "stepPass", 31))

	built := BuildWithOptions(domain.ParsedRepository{}, BuildOptions{
		CompositeActionInputFlows:       compositeactionflow.Result{Flows: []compositeactionflow.ConfirmedInputFlow{root}},
		NestedCompositeActionInputFlows: nestedcompositeactionflow.Result{Flows: []nestedcompositeactionflow.ConfirmedNestedInputFlow{level1, level2User, level2Pass}},
	})

	var bUsages []domain.Node
	for _, u := range nodesByType(built.Graph.Nodes, domain.NodeCompositeActionInputUsage) {
		if u.Metadata["child_canonical_directory"] == dirB {
			bUsages = append(bUsages, u)
		}
	}
	if len(bUsages) != 1 {
		t.Fatalf("expected exactly one B usage node shared by both sibling child flows, got %d: %#v", len(bUsages), bUsages)
	}
	edgesFromB := forwardingEdgesFrom(built, bUsages[0].ID)
	if len(edgesFromB) != 2 {
		t.Fatalf("expected both C-user and C-pass bindings to be reached from the single shared B usage node, got %d edges", len(edgesFromB))
	}
}
