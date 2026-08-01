package compositeaction

import (
	"context"
	"path"
	"sort"
	"strings"

	"github.com/Bavlik/CredScope/internal/discovery"
	"github.com/Bavlik/CredScope/internal/domain"
	"github.com/Bavlik/CredScope/internal/parsers/githubactions"
)

// MaxCompositeActionNestingDepth is the maximum number of composite actions
// permitted on one root-to-leaf resolved nesting path, counting the
// top-level, workflow-resolved composite action as depth 1. This mirrors the
// currently GitHub-documented composite-action nesting limit. It is a wholly
// independent constant from reusableworkflow.MaxChainDepth /
// graph.MaxReusableWorkflowHops: those govern a different GitHub feature
// (reusable workflow calls) with its own independently documented limit that
// currently happens to share the same numeral — a coincidence, not shared
// semantics, so it is never reused here.
const MaxCompositeActionNestingDepth = 10

// resolveNested performs the repository-wide canonical nested composite-action
// expansion (CA3A). It is seeded by every canonical directory already
// resolved as a top-level workflow call (topLevelActions) and returns the
// complete, deduplicated set of every canonical action transitively
// reachable from those seeds (topLevelActions plus every action discovered
// during expansion), together with one NestedCompositeActionCall per
// composite-action-internal action-step reference encountered along the way.
//
// It maintains two deliberately separate concepts, per canonical directory:
// metadataCache (has this directory's action.yml/action.yaml been parsed?)
// and expanded (have this action's own Runs.Steps been inspected for further
// nested uses: references?). A directory can be cached without being
// expanded — every topLevelActions entry starts exactly in that state, since
// CA1 already parsed it but never looked inside its Runs.Steps for further
// local uses: references. Conflating the two would either re-parse metadata
// that is already safely cached, or silently skip expanding a top-level
// action's own nested calls merely because its metadata already exists in
// the cache.
//
// The work queue performs no cycle or depth classification: it has no
// notion of "the current root-to-here path," only "has this canonical
// directory been expanded yet, repository-wide." A canonical directory is
// parsed and expanded at most once no matter how many different parents or
// paths reference it, which is exactly what makes the queue provably finite
// (repository directories are finite) and is also exactly why it cannot
// answer "is this specific path cyclic or too deep" — that question requires
// a specific root-to-current path, which the queue does not carry. Cycle and
// depth are computed afterward, by computeNestedDiagnostics, as a separate
// per-path walk over the complete, finite result this function returns.
func resolveNested(ctx context.Context, finder *discovery.Finder, parser *githubactions.Parser, topLevelActions []domain.ActionMetadata) ([]domain.ActionMetadata, []domain.NestedCompositeActionCall, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}

	metadataCache := make(map[string]domain.ActionMetadata, len(topLevelActions))
	for _, action := range topLevelActions {
		metadataCache[action.Directory] = action
	}
	expanded := make(map[string]bool, len(topLevelActions))
	queued := make(map[string]bool, len(topLevelActions))

	queue := make([]string, 0, len(metadataCache))
	for directory := range metadataCache {
		queue = append(queue, directory)
	}
	sort.Strings(queue)
	for _, directory := range queue {
		queued[directory] = true
	}

	var nestedCalls []domain.NestedCompositeActionCall

	for len(queue) > 0 {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		directory := queue[0]
		queue = queue[1:]
		if expanded[directory] {
			continue
		}
		action, ok := metadataCache[directory]
		if !ok {
			// Every directory ever enqueued was placed into metadataCache
			// first, below; this branch should be unreachable.
			expanded[directory] = true
			continue
		}
		for stepIndex, step := range action.Runs.Steps {
			if err := ctx.Err(); err != nil {
				return nil, nil, err
			}
			if step.Action == nil {
				continue
			}
			call := domain.NestedCompositeActionCall{
				ParentCanonicalDirectory: directory,
				ParentMetadataFile:       path.Base(action.File),
				ParentActionStepIndex:    stepIndex,
				ParentActionStepID:       step.ID,
				RawReference:             step.Action.Reference,
				Evidence:                 step.Action.Evidence,
			}
			raw := step.Action.Reference
			switch {
			case strings.Contains(raw, "${{"):
				// Expression classification runs before any other
				// classification, matching the top-level workflow-call
				// resolver's own ordering exactly.
				call.Status = domain.CompositeActionUnsupportedExpression
			case strings.HasPrefix(raw, "docker://"):
				call.Status = domain.CompositeActionOpaqueDocker
			case isLocalAttempt(raw):
				normalized, reason, pathOK := validateLocalPath(raw)
				if !pathOK {
					call.Status = domain.CompositeActionRejectedPath
					call.Reason = reason
					break
				}
				call.CanonicalDirectory = normalized
				if cached, isCached := metadataCache[normalized]; isCached {
					// Cache hit: this directory was already parsed, either
					// as a top-level seed or as an earlier nested
					// discovery (a diamond's shared child, or a cycle back
					// to an already-processed ancestor). Never re-parse.
					call.Status = domain.CompositeActionResolvedLocalComposite
					call.MetadataFile = path.Base(cached.File)
				} else {
					outcome := resolveDirectory(ctx, finder, parser, normalized)
					call.Status = outcome.status
					call.Reason = outcome.reason
					call.MetadataFile = outcome.metadataFile
					if outcome.status == domain.CompositeActionResolvedLocalComposite {
						metadataCache[normalized] = outcome.action
					}
				}
				if call.Status == domain.CompositeActionResolvedLocalComposite && !expanded[normalized] && !queued[normalized] {
					queue = append(queue, normalized)
					queued[normalized] = true
				}
			default:
				call.Status = domain.CompositeActionOpaqueExternal
			}
			nestedCalls = append(nestedCalls, call)
		}
		expanded[directory] = true
	}

	actions := make([]domain.ActionMetadata, 0, len(metadataCache))
	for _, action := range metadataCache {
		actions = append(actions, action)
	}
	sort.Slice(actions, func(i, j int) bool { return actions[i].Directory < actions[j].Directory })
	sort.Slice(nestedCalls, func(i, j int) bool { return lessNestedCall(nestedCalls[i], nestedCalls[j]) })

	return actions, nestedCalls, nil
}

func lessNestedCall(a, b domain.NestedCompositeActionCall) bool {
	if a.ParentCanonicalDirectory != b.ParentCanonicalDirectory {
		return a.ParentCanonicalDirectory < b.ParentCanonicalDirectory
	}
	if a.ParentActionStepIndex != b.ParentActionStepIndex {
		return a.ParentActionStepIndex < b.ParentActionStepIndex
	}
	return a.RawReference < b.RawReference
}

// computeNestedDiagnostics builds deterministic adjacency from every
// resolved_local_composite NestedCompositeActionCall (a call-site-specific
// edge: parent canonical directory + parent internal step index -> child
// canonical directory) and separately walks it, once per unique top-level
// resolved canonical directory, to detect cycles and excessive depth. This
// mirrors reusableworkflow's own two-phase "build a small edge set once,
// then separately walk it for cycles/depth from every potential root"
// algorithm shape exactly (per-path onStack tracking for cycles, a
// depth-bounded recursive walk for depth), deliberately without sharing any
// type or code with that package: the two features are independently
// documented GitHub behaviors with their own call graphs (canonical
// directories here, workflow files there) that only coincidentally share a
// numeric limit. Both detectNestedCycles and detectNestedDepthExceeded
// independently maintain their own per-path onStack/onPath set; neither
// consults the other, and depth classification simply does not descend into
// a child already on the current path, leaving cycle reporting exclusively
// to detectNestedCycles.
func computeNestedDiagnostics(rootDirectories []string, nestedCalls []domain.NestedCompositeActionCall) []domain.NestedCompositeActionDiagnostic {
	edgesByParent := make(map[string][]domain.NestedCompositeActionCall)
	for _, call := range nestedCalls {
		if call.Status != domain.CompositeActionResolvedLocalComposite {
			continue
		}
		edgesByParent[call.ParentCanonicalDirectory] = append(edgesByParent[call.ParentCanonicalDirectory], call)
	}
	for parent := range edgesByParent {
		edges := edgesByParent[parent]
		sort.Slice(edges, func(i, j int) bool {
			if edges[i].CanonicalDirectory != edges[j].CanonicalDirectory {
				return edges[i].CanonicalDirectory < edges[j].CanonicalDirectory
			}
			return edges[i].ParentActionStepIndex < edges[j].ParentActionStepIndex
		})
		edgesByParent[parent] = edges
	}

	roots := uniqueSortedStrings(rootDirectories)

	var diagnostics []domain.NestedCompositeActionDiagnostic
	diagnostics = append(diagnostics, detectNestedCycles(roots, edgesByParent)...)
	diagnostics = append(diagnostics, detectNestedDepthExceeded(roots, edgesByParent)...)
	sort.Slice(diagnostics, func(i, j int) bool { return lessNestedDiagnostic(diagnostics[i], diagnostics[j]) })
	return diagnostics
}

// detectNestedCycles walks the resolved-call adjacency from every root,
// tracking onStack — the current path only, never a repository-global
// visited set — so a diamond (a shared descendant reached by two separate
// branches, never appearing in its own ancestor stack) is never
// misclassified as a cycle, while a genuine repeat within one path always is.
func detectNestedCycles(roots []string, edgesByParent map[string][]domain.NestedCompositeActionCall) []domain.NestedCompositeActionDiagnostic {
	seen := make(map[string]domain.NestedCompositeActionDiagnostic)
	for _, root := range roots {
		var stack []string
		onStack := make(map[string]int, len(roots))
		var walk func(node string)
		walk = func(node string) {
			stack = append(stack, node)
			onStack[node] = len(stack) - 1
			for _, edge := range edgesByParent[node] {
				child := edge.CanonicalDirectory
				if idx, inStack := onStack[child]; inStack {
					cycle := append([]string(nil), stack[idx:]...)
					canonical := canonicalizeNestedCycle(cycle)
					key := strings.Join(canonical, "\x00")
					if _, exists := seen[key]; !exists {
						closed := append(append([]string(nil), canonical...), canonical[0])
						seen[key] = domain.NestedCompositeActionDiagnostic{
							Kind:                   domain.NestedCompositeActionDiagnosticCycle,
							RootCanonicalDirectory: root,
							Path:                   closed,
							Evidence:               edge.Evidence,
						}
					}
					continue
				}
				walk(child)
			}
			delete(onStack, node)
			stack = stack[:len(stack)-1]
		}
		walk(root)
	}
	result := make([]domain.NestedCompositeActionDiagnostic, 0, len(seen))
	for _, diag := range seen {
		result = append(result, diag)
	}
	return result
}

// canonicalizeNestedCycle rotates a cycle so it starts at its
// lexicographically smallest node, making the representation independent of
// which node the traversal happened to start from.
func canonicalizeNestedCycle(cycle []string) []string {
	minIndex := 0
	for i, node := range cycle {
		if node < cycle[minIndex] {
			minIndex = i
		}
	}
	canonical := make([]string, 0, len(cycle))
	canonical = append(canonical, cycle[minIndex:]...)
	canonical = append(canonical, cycle[:minIndex]...)
	return canonical
}

// detectNestedDepthExceeded walks the resolved-call adjacency from every
// root, counting the root itself as depth 1, considering only acyclic
// root-to-leaf path expansion. It maintains onPath — the current root-to-here
// path only, never a repository-global visited set, exactly mirroring
// detectNestedCycles' own onStack discipline — so a diamond's shared child
// (reached by two separate branches, never appearing in its own ancestor
// path) is still walked and depth-checked on each branch independently,
// while a child already present on the current path is never descended into
// a second time. Cycle classification remains exclusively owned by
// detectNestedCycles: a child already on the current path is simply not
// followed here, so a cyclic path never accumulates artificial depth and
// never emits its own depth-exceeded diagnostic merely because the depth
// walk would otherwise keep re-entering the cycle until the cap.
func detectNestedDepthExceeded(roots []string, edgesByParent map[string][]domain.NestedCompositeActionCall) []domain.NestedCompositeActionDiagnostic {
	var result []domain.NestedCompositeActionDiagnostic
	for _, root := range roots {
		currentPath := []string{root}
		onPath := map[string]bool{root: true}
		var walk func(node string, depth int)
		walk = func(node string, depth int) {
			for _, edge := range edgesByParent[node] {
				child := edge.CanonicalDirectory
				if onPath[child] {
					continue
				}
				childDepth := depth + 1
				childPath := append(append([]string(nil), currentPath...), child)
				if childDepth > MaxCompositeActionNestingDepth {
					result = append(result, domain.NestedCompositeActionDiagnostic{
						Kind:                   domain.NestedCompositeActionDiagnosticDepthExceeded,
						RootCanonicalDirectory: root,
						Path:                   childPath,
						Depth:                  childDepth,
						Limit:                  MaxCompositeActionNestingDepth,
						Evidence:               edge.Evidence,
					})
					continue
				}
				currentPath = childPath
				onPath[child] = true
				walk(child, childDepth)
				delete(onPath, child)
				currentPath = currentPath[:len(currentPath)-1]
			}
		}
		walk(root, 1)
	}
	return result
}

func lessNestedDiagnostic(a, b domain.NestedCompositeActionDiagnostic) bool {
	if a.Kind != b.Kind {
		return a.Kind < b.Kind
	}
	if a.RootCanonicalDirectory != b.RootCanonicalDirectory {
		return a.RootCanonicalDirectory < b.RootCanonicalDirectory
	}
	na, nb := len(a.Path), len(b.Path)
	for i := 0; i < na && i < nb; i++ {
		if a.Path[i] != b.Path[i] {
			return a.Path[i] < b.Path[i]
		}
	}
	if na != nb {
		return na < nb
	}
	return a.Depth < b.Depth
}

func uniqueSortedStrings(items []string) []string {
	seen := make(map[string]bool, len(items))
	result := make([]string, 0, len(items))
	for _, item := range items {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}
	sort.Strings(result)
	return result
}
