package graph

import (
	"sort"
	"strings"

	"github.com/Bavlik/CredScope/internal/domain"
)

const (
	DefaultMaxDepth         = 12
	DefaultMaxEvidencePaths = 10000
	// MaxReusableWorkflowHops mirrors the resolver's maximum reusable
	// workflow chain of 10 total workflows, expressed as a hop count: 10
	// workflows means at most 9 caller-to-callee forwarding transitions.
	// This is enforced per traversal path, independently of DefaultMaxDepth,
	// because the same forwarding edge can be shallow from one credential
	// and over-depth from another — it is never deleted or globally
	// suppressed, only refused past the ninth transition on a given path.
	MaxReusableWorkflowHops = 9
)

// Traverse returns every distinct path prefix reachable from start. A node may
// occur only once in a path, so cyclic graphs terminate without losing distinct
// acyclic evidence paths.
func Traverse(input domain.Graph, start string, maxDepth int) []domain.EvidencePath {
	paths, _ := TraverseLimited(input, start, maxDepth, DefaultMaxEvidencePaths)
	return paths
}

// TraverseLimited additionally bounds the number of path prefixes retained.
// The boolean result reports that the bound was reached.
func TraverseLimited(input domain.Graph, start string, maxDepth, maxPaths int) ([]domain.EvidencePath, bool) {
	if maxDepth <= 0 {
		maxDepth = DefaultMaxDepth
	}
	if maxPaths <= 0 {
		maxPaths = DefaultMaxEvidencePaths
	}
	nodes := make(map[string]domain.Node, len(input.Nodes))
	adjacent := make(map[string][]domain.Edge)
	for _, node := range input.Nodes {
		nodes[node.ID] = node
	}
	if _, ok := nodes[start]; !ok {
		return []domain.EvidencePath{}, false
	}
	for _, edge := range input.Edges {
		if edge.EvidenceKind == domain.EvidenceNetworkTopology || edge.EvidenceKind == domain.EvidenceStructuralCallOnly {
			continue
		}
		if _, fromOK := nodes[edge.From]; !fromOK {
			continue
		}
		if _, toOK := nodes[edge.To]; !toOK {
			continue
		}
		adjacent[edge.From] = append(adjacent[edge.From], edge)
	}
	for key := range adjacent {
		sort.Slice(adjacent[key], func(i, j int) bool { return adjacent[key][i].ID < adjacent[key][j].ID })
	}
	startNode := pathNode(nodes[start])
	var paths []domain.EvidencePath
	limitExceeded := false
	var walk func(string, []domain.PathNode, []domain.PathEdge, map[string]bool, domain.Confidence, domain.EvidenceKind, int)
	walk = func(current string, pathNodes []domain.PathNode, pathEdges []domain.PathEdge, visited map[string]bool, confidence domain.Confidence, pathKind domain.EvidenceKind, reusableHops int) {
		for _, edge := range adjacent[current] {
			if limitExceeded {
				return
			}
			if visited[edge.To] {
				continue
			}
			nextReusableHops := reusableHops
			if isReusableWorkflowHop(edge) {
				nextReusableHops++
				if nextReusableHops > MaxReusableWorkflowHops {
					// Refuse this specific transition on this specific path;
					// the edge itself is untouched and may still be walked
					// from a shallower starting point in a different Traverse
					// call.
					continue
				}
			}
			nextNodes := appendCopy(pathNodes, pathNode(nodes[edge.To]))
			nextEdges := appendEdge(pathEdges, domain.PathEdge{ID: edge.ID, From: edge.From, To: edge.To, Relationship: edge.Type, EvidenceKind: edge.EvidenceKind, Evidence: edge.Evidence, Confidence: edge.Confidence})
			nextConfidence := weakest(confidence, edge.Confidence)
			nextKind := combineEvidenceKind(pathKind, edge.EvidenceKind)
			truncated := len(nextEdges) >= maxDepth && hasUnvisited(adjacent[edge.To], visited, edge.To)
			path := domain.EvidencePath{CredentialID: start, Nodes: nextNodes, Edges: nextEdges, Confidence: nextConfidence, EvidenceKind: nextKind, Truncated: truncated}
			path.ID = stableID("path", pathKey(path))
			paths = append(paths, path)
			if len(paths) >= maxPaths {
				limitExceeded = true
				return
			}
			if len(nextEdges) >= maxDepth {
				continue
			}
			nextVisited := cloneVisited(visited)
			nextVisited[edge.To] = true
			walk(edge.To, nextNodes, nextEdges, nextVisited, nextConfidence, nextKind, nextReusableHops)
		}
	}
	walk(start, []domain.PathNode{startNode}, nil, map[string]bool{start: true}, domain.ConfidenceConfirmed, domain.EvidenceConfirmedDataFlow, 0)
	byID := make(map[string]domain.EvidencePath, len(paths))
	for _, path := range paths {
		byID[path.ID] = path
	}
	paths = paths[:0]
	for _, path := range byID {
		paths = append(paths, path)
	}
	sort.Slice(paths, func(i, j int) bool { return paths[i].ID < paths[j].ID })
	return paths, limitExceeded
}

// isReusableWorkflowHop reports whether edge is a confirmed reusable-workflow
// secret-forwarding transition (set only by builder's
// forwardReusableWorkflowSecret), as opposed to an ordinary
// EdgeExplicitlyForwardedTo edge unrelated to reusable workflows.
func isReusableWorkflowHop(edge domain.Edge) bool {
	return edge.Metadata[reusableWorkflowHopMetadataKey] == reusableWorkflowHopMetadataValue
}

func combineEvidenceKind(current, next domain.EvidenceKind) domain.EvidenceKind {
	rank := func(value domain.EvidenceKind) int {
		switch value {
		case domain.EvidenceUnknownRuntime:
			return 4
		case domain.EvidenceNetworkTopology:
			return 3
		case domain.EvidenceExposureContext:
			return 2
		default:
			return 1
		}
	}
	if rank(next) > rank(current) {
		return next
	}
	return current
}

func pathNode(node domain.Node) domain.PathNode {
	return domain.PathNode{ID: node.ID, Type: node.Type, Label: node.Label, Location: node.Location, Confidence: node.Confidence}
}

func pathKey(path domain.EvidencePath) string {
	parts := make([]string, 0, len(path.Nodes)+len(path.Edges))
	for _, node := range path.Nodes {
		parts = append(parts, node.ID)
	}
	for _, edge := range path.Edges {
		parts = append(parts, edge.ID)
	}
	return strings.Join(parts, "\x00")
}

func appendCopy(items []domain.PathNode, item domain.PathNode) []domain.PathNode {
	result := make([]domain.PathNode, len(items), len(items)+1)
	copy(result, items)
	return append(result, item)
}

func appendEdge(items []domain.PathEdge, item domain.PathEdge) []domain.PathEdge {
	result := make([]domain.PathEdge, len(items), len(items)+1)
	copy(result, items)
	return append(result, item)
}

func cloneVisited(input map[string]bool) map[string]bool {
	result := make(map[string]bool, len(input)+1)
	for key, value := range input {
		result[key] = value
	}
	return result
}

func hasUnvisited(edges []domain.Edge, visited map[string]bool, current string) bool {
	for _, edge := range edges {
		if edge.To != current && !visited[edge.To] {
			return true
		}
	}
	return false
}
