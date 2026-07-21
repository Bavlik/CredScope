package graph

import (
	"sort"
	"strings"

	"github.com/credscope/credscope/internal/domain"
)

const DefaultMaxDepth = 12

// Traverse returns every distinct path prefix reachable from start. A node may
// occur only once in a path, so cyclic graphs terminate without losing distinct
// acyclic evidence paths.
func Traverse(input domain.Graph, start string, maxDepth int) []domain.EvidencePath {
	if maxDepth <= 0 {
		maxDepth = DefaultMaxDepth
	}
	nodes := make(map[string]domain.Node, len(input.Nodes))
	adjacent := make(map[string][]domain.Edge)
	for _, node := range input.Nodes {
		nodes[node.ID] = node
	}
	if _, ok := nodes[start]; !ok {
		return []domain.EvidencePath{}
	}
	for _, edge := range input.Edges {
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
	var walk func(string, []domain.PathNode, []domain.PathEdge, map[string]bool, domain.Confidence)
	walk = func(current string, pathNodes []domain.PathNode, pathEdges []domain.PathEdge, visited map[string]bool, confidence domain.Confidence) {
		for _, edge := range adjacent[current] {
			if visited[edge.To] {
				continue
			}
			nextNodes := appendCopy(pathNodes, pathNode(nodes[edge.To]))
			nextEdges := appendEdge(pathEdges, domain.PathEdge{ID: edge.ID, From: edge.From, To: edge.To, Relationship: edge.Type, Evidence: edge.Evidence, Confidence: edge.Confidence})
			nextConfidence := weakest(confidence, edge.Confidence)
			truncated := len(nextEdges) >= maxDepth && hasUnvisited(adjacent[edge.To], visited, edge.To)
			path := domain.EvidencePath{CredentialID: start, Nodes: nextNodes, Edges: nextEdges, Confidence: nextConfidence, Truncated: truncated}
			path.ID = stableID("path", pathKey(path))
			paths = append(paths, path)
			if len(nextEdges) >= maxDepth {
				continue
			}
			nextVisited := cloneVisited(visited)
			nextVisited[edge.To] = true
			walk(edge.To, nextNodes, nextEdges, nextVisited, nextConfidence)
		}
	}
	walk(start, []domain.PathNode{startNode}, nil, map[string]bool{start: true}, domain.ConfidenceConfirmed)
	byID := make(map[string]domain.EvidencePath, len(paths))
	for _, path := range paths {
		byID[path.ID] = path
	}
	paths = paths[:0]
	for _, path := range byID {
		paths = append(paths, path)
	}
	sort.Slice(paths, func(i, j int) bool { return paths[i].ID < paths[j].ID })
	return paths
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
