package reporters

import (
	"sort"
	"strings"

	"github.com/credscope/credscope/internal/domain"
)

const (
	DefaultEvidencePathLimit = 10
	VerboseEvidencePathLimit = 40
	HTMLEvidencePathLimit    = 20
)

// EvidenceSelection is a presentation-only view. The underlying analysis and
// graph remain unchanged so scoring and machine consumers retain all facts.
type EvidenceSelection struct {
	Paths   []domain.EvidencePath
	Total   int
	Omitted int
}

// SelectEvidencePaths chooses deterministic, security-relevant paths for
// human reports. It collapses longer cyclic variants that reach the same node,
// then prefers high-impact endpoints and shorter direct paths.
func SelectEvidencePaths(input domain.Graph, paths []domain.EvidencePath, limit int) EvidenceSelection {
	if limit < 0 {
		limit = 0
	}
	nodes := make(map[string]domain.Node, len(input.Nodes))
	for _, node := range input.Nodes {
		nodes[node.ID] = node
	}
	best := make(map[string]rankedPath)
	for _, path := range paths {
		if len(path.Nodes) < 2 {
			continue
		}
		end := path.Nodes[len(path.Nodes)-1]
		priority := evidencePriority(end, nodes[end.ID])
		if priority == 0 {
			continue
		}
		key := end.ID
		candidate := rankedPath{path: path, priority: priority}
		current, ok := best[key]
		if !ok || lessRanked(candidate, current) {
			best[key] = candidate
		}
	}
	ranked := make([]rankedPath, 0, len(best))
	for _, path := range best {
		ranked = append(ranked, path)
	}
	sort.Slice(ranked, func(i, j int) bool { return lessRanked(ranked[i], ranked[j]) })
	selection := EvidenceSelection{Total: len(ranked)}
	if limit > len(ranked) {
		limit = len(ranked)
	}
	selection.Paths = make([]domain.EvidencePath, limit)
	for index := 0; index < limit; index++ {
		selection.Paths[index] = ranked[index].path
	}
	selection.Omitted = selection.Total - len(selection.Paths)
	return selection
}

type rankedPath struct {
	path     domain.EvidencePath
	priority int
}

func lessRanked(left, right rankedPath) bool {
	if left.priority != right.priority {
		return left.priority > right.priority
	}
	if len(left.path.Edges) != len(right.path.Edges) {
		return len(left.path.Edges) < len(right.path.Edges)
	}
	return left.path.ID < right.path.ID
}

func evidencePriority(pathNode domain.PathNode, node domain.Node) int {
	switch pathNode.Type {
	case domain.NodePermission:
		return 100
	case domain.NodeEnvironment:
		return 98
	case domain.NodeVolumeMount:
		if node.Metadata["docker_socket"] == "true" {
			return 97
		}
		if node.Metadata["writable_host_bind"] == "true" {
			return 94
		}
		return 82
	case domain.NodeComposeService:
		if node.Metadata["privileged"] == "true" {
			return 96
		}
		if node.Metadata["host_network"] == "true" {
			return 95
		}
		return 78
	case domain.NodePortExposure:
		return 93
	case domain.NodeExternalAction:
		return 92
	case domain.NodeTrigger:
		if strings.EqualFold(node.Metadata["name"], "pull_request_target") {
			return 91
		}
		return 60
	case domain.NodeReusableWorkflow:
		return 88
	case domain.NodeJob:
		return 72
	case domain.NodeWorkflow:
		return 65
	case domain.NodeComposeSecret:
		return 62
	case domain.NodeEnvFile:
		return 58
	case domain.NodeStep:
		return 55
	default:
		return 0
	}
}
