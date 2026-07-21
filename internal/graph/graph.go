// Package graph builds and traverses CredScope's deterministic reachability graph.
package graph

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/Bavlik/CredScope/internal/domain"
)

type mutableGraph struct {
	nodes         map[string]domain.Node
	edges         map[string]domain.Edge
	maxNodes      int
	maxEdges      int
	limitExceeded bool
}

const (
	DefaultMaxGraphNodes = 100000
	DefaultMaxGraphEdges = 250000
)

func newMutable() *mutableGraph {
	return newMutableWithLimits(DefaultMaxGraphNodes, DefaultMaxGraphEdges)

}

func newMutableWithLimits(maxNodes, maxEdges int) *mutableGraph {
	return &mutableGraph{nodes: make(map[string]domain.Node), edges: make(map[string]domain.Edge), maxNodes: maxNodes, maxEdges: maxEdges}
}

func stableID(kind, key string) string {
	sum := sha256.Sum256([]byte("credscope:graph:v1\x00" + kind + "\x00" + key))
	return kind + ":" + hex.EncodeToString(sum[:])
}

func (g *mutableGraph) addNode(kind domain.NodeType, key, label string, location *domain.Location, metadata map[string]string, evidence []domain.Evidence, confidence domain.Confidence) string {
	id := stableID("node:"+string(kind), key)
	node := domain.Node{ID: id, Type: kind, Label: label, Location: location, Metadata: cloneMap(metadata), Evidence: uniqueEvidence(evidence), Confidence: confidence}
	if current, ok := g.nodes[id]; ok {
		current.Evidence = uniqueEvidence(append(current.Evidence, evidence...))
		current.Confidence = strongest(current.Confidence, confidence)
		g.nodes[id] = current
		return id
	}
	if len(g.nodes) >= g.maxNodes {
		g.limitExceeded = true
		return ""
	}
	g.nodes[id] = node
	return id
}

func (g *mutableGraph) addEdge(from, to string, kind domain.EdgeType, evidence []domain.Evidence, confidence domain.Confidence) string {
	return g.addTypedEdge(from, to, kind, defaultEvidenceKind(kind), evidence, confidence)
}

func (g *mutableGraph) addTypedEdge(from, to string, kind domain.EdgeType, evidenceKind domain.EvidenceKind, evidence []domain.Evidence, confidence domain.Confidence) string {
	if from == "" || to == "" {
		return ""
	}
	evidence = uniqueEvidence(evidence)
	key := from + "\x00" + to + "\x00" + string(kind) + "\x00" + string(evidenceKind) + "\x00" + evidenceKey(evidence)
	id := stableID("edge", key)
	if _, ok := g.edges[id]; ok {
		return id
	}
	if len(g.edges) >= g.maxEdges {
		g.limitExceeded = true
		return ""
	}
	if _, ok := g.edges[id]; !ok {
		g.edges[id] = domain.Edge{ID: id, From: from, To: to, Type: kind, EvidenceKind: evidenceKind, Evidence: evidence, Confidence: confidence}
	}
	return id
}

func defaultEvidenceKind(kind domain.EdgeType) domain.EvidenceKind {
	switch kind {
	case domain.EdgeDependsOn, domain.EdgeNetworkReachable:
		return domain.EvidenceNetworkTopology
	case domain.EdgeExposesPort, domain.EdgeMountsVolume, domain.EdgeReadsEnvFile, domain.EdgeHasPermission, domain.EdgeTriggeredBy, domain.EdgeUsesEnvironment, domain.EdgeRunsAction, domain.EdgeCallsWorkflow, domain.EdgeDetectedIn, domain.EdgeBelongsTo:
		return domain.EvidenceExposureContext
	default:
		return domain.EvidenceConfirmedDataFlow
	}
}

func (g *mutableGraph) finish() domain.Graph {
	result := domain.Graph{Nodes: make([]domain.Node, 0, len(g.nodes)), Edges: make([]domain.Edge, 0, len(g.edges))}
	for _, node := range g.nodes {
		result.Nodes = append(result.Nodes, node)
	}
	for _, edge := range g.edges {
		result.Edges = append(result.Edges, edge)
	}
	sort.Slice(result.Nodes, func(i, j int) bool { return result.Nodes[i].ID < result.Nodes[j].ID })
	sort.Slice(result.Edges, func(i, j int) bool { return result.Edges[i].ID < result.Edges[j].ID })
	return result
}

func cloneMap(input map[string]string) map[string]string {
	if len(input) == 0 {
		return nil
	}
	result := make(map[string]string, len(input))
	for key, value := range input {
		result[key] = value
	}
	return result
}

func locationPtr(e domain.Evidence) *domain.Location {
	if e.Location.Path == "" && e.Location.Line == 0 && e.Location.Column == 0 {
		return nil
	}
	loc := e.Location
	return &loc
}

func evidenceKey(items []domain.Evidence) string {
	var parts []string
	for _, item := range items {
		parts = append(parts, strings.Join([]string{item.Type, item.RuleID, item.Description, item.Location.Path, strconv.Itoa(item.Location.Line), strconv.Itoa(item.Location.Column), item.Field, item.Source, string(item.Confidence)}, "\x1f"))
	}
	return strings.Join(parts, "\x1e")
}

func uniqueEvidence(items []domain.Evidence) []domain.Evidence {
	byKey := make(map[string]domain.Evidence, len(items))
	for _, item := range items {
		byKey[evidenceKey([]domain.Evidence{item})] = item
	}
	result := make([]domain.Evidence, 0, len(byKey))
	for _, item := range byKey {
		result = append(result, item)
	}
	sort.Slice(result, func(i, j int) bool {
		return evidenceKey([]domain.Evidence{result[i]}) < evidenceKey([]domain.Evidence{result[j]})
	})
	return result
}

func confidenceRank(value domain.Confidence) int {
	switch value {
	case domain.ConfidenceConfirmed:
		return 4
	case domain.ConfidenceHigh:
		return 3
	case domain.ConfidenceMedium:
		return 2
	case domain.ConfidenceLow:
		return 1
	default:
		return 0
	}
}

func strongest(a, b domain.Confidence) domain.Confidence {
	if confidenceRank(b) > confidenceRank(a) {
		return b
	}
	return a
}

func weakest(a, b domain.Confidence) domain.Confidence {
	if confidenceRank(b) < confidenceRank(a) {
		return b
	}
	return a
}

func evidence(kind string, source domain.Evidence, description string, confidence domain.Confidence) domain.Evidence {
	source.Type = kind
	if description != "" {
		source.Description = description
	}
	source.Confidence = confidence
	return source
}

func boolText(value bool) string { return strconv.FormatBool(value) }

func nodeKey(parts ...any) string {
	values := make([]string, len(parts))
	for index, part := range parts {
		values[index] = fmt.Sprint(part)
	}
	return strings.Join(values, "\x00")
}
