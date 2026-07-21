package rules

import (
	"sort"
	"strconv"
	"strings"

	"github.com/Bavlik/CredScope/internal/domain"
)

type evaluation struct {
	catalog map[string]Rule
	graph   domain.Graph
	paths   []domain.EvidencePath
	nodes   map[string]domain.Node
	direct  []domain.Edge
	reach   map[string]bool
}

// Evaluate matches catalog rules against one credential's graph paths.
func Evaluate(graph domain.Graph, credentialID string, paths []domain.EvidencePath) []domain.RuleMatch {
	e := evaluation{catalog: make(map[string]Rule), graph: graph, paths: paths, nodes: make(map[string]domain.Node), reach: map[string]bool{credentialID: true}}
	for _, item := range Catalog() {
		e.catalog[item.ID] = item
	}
	for _, node := range graph.Nodes {
		e.nodes[node.ID] = node
	}
	for _, path := range paths {
		for _, node := range path.Nodes {
			e.reach[node.ID] = true
		}
	}
	for _, edge := range graph.Edges {
		if edge.From == credentialID {
			e.direct = append(e.direct, edge)
		}
	}
	var matches []domain.RuleMatch
	add := func(ruleID string, nodeIDs []string, evidence []domain.Evidence, confidence domain.Confidence) {
		item := e.catalog[ruleID]
		if !item.Enabled || len(nodeIDs) == 0 {
			return
		}
		nodeIDs = uniqueStrings(nodeIDs)
		evidence = uniqueEvidence(evidence)
		pathIDs := e.pathsFor(nodeIDs)
		matches = append(matches, domain.RuleMatch{RuleID: item.ID, Title: item.Title, Category: item.Category, Severity: item.DefaultSeverity, Confidence: confidence, Evidence: evidence, AffectedNodeIDs: nodeIDs, PathIDs: pathIDs, RemediationID: item.RemediationID})
	}

	findings := e.nodesOfType(domain.NodeFinding)
	add("CRD101", findings, e.nodeEvidence(findings), domain.ConfidenceConfirmed)
	workflows := e.nodesOfType(domain.NodeWorkflow)
	add("CRD102", workflows, e.nodeEvidence(workflows), domain.ConfidenceConfirmed)
	jobs := e.directTargets(domain.NodeJob, domain.EdgeConfiguredIn, domain.EdgeExplicitlyForwardedTo, domain.EdgeAvailableToProcess)
	if len(jobs) >= 2 {
		add("CRD103", jobs, e.nodeEvidence(jobs), domain.ConfidenceHigh)
	}
	pullTargets := e.nodesMatching(domain.NodeTrigger, func(node domain.Node) bool { return node.Metadata["name"] == "pull_request_target" })
	add("CRD104", pullTargets, e.nodeEvidence(pullTargets), domain.ConfidenceHigh)

	writePermissions := e.nodesMatching(domain.NodePermission, func(node domain.Node) bool {
		return node.Metadata["level"] == "write" || node.Metadata["level"] == "write-all"
	})
	add("CRD201", writePermissions, e.nodeEvidence(writePermissions), domain.ConfidenceConfirmed)
	writeAll := e.nodesMatching(domain.NodePermission, func(node domain.Node) bool { return node.Metadata["level"] == "write-all" })
	add("CRD202", writeAll, e.nodeEvidence(writeAll), domain.ConfidenceConfirmed)
	shellSteps, shellEvidence := e.directByEvidence(domain.NodeStep, "shell_credential_reference")
	add("CRD203", shellSteps, shellEvidence, domain.ConfidenceConfirmed)
	thirdParty := e.nodesMatching(domain.NodeExternalAction, func(node domain.Node) bool { return node.Metadata["third_party"] == "true" })
	add("CRD204", thirdParty, e.nodeEvidence(thirdParty), domain.ConfidenceConfirmed)
	mutableActions := e.nodesMatching(domain.NodeExternalAction, func(node domain.Node) bool {
		return node.Metadata["third_party"] == "true" && node.Metadata["mutable"] == "true"
	})
	add("CRD205", mutableActions, e.nodeEvidence(mutableActions), domain.ConfidenceConfirmed)
	outputJobs, outputEvidence := e.directByEvidence(domain.NodeJob, "job_output")
	add("CRD206", outputJobs, outputEvidence, domain.ConfidenceConfirmed)
	missingPermissions := e.nodesMatching(domain.NodeWorkflow, func(node domain.Node) bool { return node.Metadata["missing_explicit_permissions"] == "true" })
	add("CRD207", missingPermissions, e.nodeEvidence(missingPermissions), domain.ConfidenceHigh)
	productionEnvironments := e.nodesMatching(domain.NodeEnvironment, func(node domain.Node) bool { return node.Metadata["production_like"] == "true" })
	add("CRD208", productionEnvironments, e.nodeEvidence(productionEnvironments), domain.ConfidenceMedium)

	directServices := e.directTargets(domain.NodeComposeService, domain.EdgeAvailableToService, domain.EdgeMountedAsSecret, domain.EdgeExplicitlyForwardedTo)
	add("CRD301", directServices, e.nodeEvidence(directServices), domain.ConfidenceConfirmed)
	privileged := e.nodesMatching(domain.NodeComposeService, func(node domain.Node) bool { return node.Metadata["privileged"] == "true" })
	add("CRD302", privileged, e.nodeEvidence(privileged), domain.ConfidenceConfirmed)
	ports := e.nodesOfType(domain.NodePortExposure)
	nonLoopbackPorts := filterNodeIDs(ports, e.nodes, func(node domain.Node) bool { return !isLoopbackHost(node.Metadata["host_ip"]) })
	add("CRD303", nonLoopbackPorts, e.nodeEvidence(nonLoopbackPorts), domain.ConfidenceMedium)
	dockerSockets := e.nodesMatching(domain.NodeVolumeMount, func(node domain.Node) bool { return node.Metadata["docker_socket"] == "true" })
	add("CRD304", dockerSockets, e.nodeEvidence(dockerSockets), domain.ConfidenceConfirmed)
	hostNetwork := e.nodesMatching(domain.NodeComposeService, func(node domain.Node) bool { return node.Metadata["host_network"] == "true" })
	add("CRD305", hostNetwork, e.nodeEvidence(hostNetwork), domain.ConfidenceConfirmed)
	if len(directServices) >= 2 {
		add("CRD306", directServices, e.nodeEvidence(directServices), domain.ConfidenceConfirmed)
	}
	writableBinds := e.nodesMatching(domain.NodeVolumeMount, func(node domain.Node) bool { return node.Metadata["writable_host_bind"] == "true" })
	add("CRD307", writableBinds, e.nodeEvidence(writableBinds), domain.ConfidenceHigh)
	unverifiedUsers := e.nodesMatching(domain.NodeComposeService, func(node domain.Node) bool {
		return node.Metadata["user_specified"] != "true" || isRootUser(node.Metadata["user"])
	})
	confidence := domain.ConfidenceLow
	for _, nodeID := range unverifiedUsers {
		if isRootUser(e.nodes[nodeID].Metadata["user"]) {
			confidence = domain.ConfidenceConfirmed
			break
		}
	}
	add("CRD308", unverifiedUsers, e.nodeEvidence(unverifiedUsers), confidence)

	if len(workflows) > 0 && len(directServices) > 0 {
		add("CRD401", appendCopy(workflows, directServices...), e.nodeEvidence(appendCopy(workflows, directServices...)), domain.ConfidenceHigh)
	}
	productionServices := e.nodesMatching(domain.NodeComposeService, func(node domain.Node) bool { return node.Metadata["production_like"] == "true" })
	productionComponents := appendCopy(productionEnvironments, productionServices...)
	if len(uniqueStrings(productionComponents)) >= 2 {
		add("CRD402", productionComponents, e.nodeEvidence(productionComponents), domain.ConfidenceMedium)
	}
	allEnvironments := e.nodesOfType(domain.NodeEnvironment)
	if len(writePermissions) > 0 && len(allEnvironments) > 0 {
		nodes := appendCopy(writePermissions, allEnvironments...)
		add("CRD403", nodes, e.nodeEvidence(nodes), domain.ConfidenceHigh)
	}
	independent := e.independentComponents()
	if len(independent) >= 2 {
		add("CRD404", independent, e.nodeEvidence(independent), domain.ConfidenceHigh)
	}

	unresolved := e.nodesMatching(domain.NodeReusableWorkflow, func(node domain.Node) bool { return node.Metadata["unresolved"] == "true" })
	add("CRD501", unresolved, e.nodeEvidence(unresolved), domain.ConfidenceUnknown)
	services := e.nodesOfType(domain.NodeComposeService)
	add("CRD502", services, e.nodeEvidence(services), domain.ConfidenceUnknown)
	add("CRD503", ports, e.nodeEvidence(ports), domain.ConfidenceUnknown)

	sort.Slice(matches, func(i, j int) bool { return matches[i].RuleID < matches[j].RuleID })
	return matches
}

func (e evaluation) nodesOfType(kind domain.NodeType) []string {
	return e.nodesMatching(kind, func(domain.Node) bool { return true })
}

func filterNodeIDs(ids []string, nodes map[string]domain.Node, keep func(domain.Node) bool) []string {
	result := make([]string, 0, len(ids))
	for _, id := range ids {
		if node, ok := nodes[id]; ok && keep(node) {
			result = append(result, id)
		}
	}
	return result
}

func isLoopbackHost(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	return value == "localhost" || value == "::1" || strings.HasPrefix(value, "127.")
}

func (e evaluation) nodesMatching(kind domain.NodeType, match func(domain.Node) bool) []string {
	var result []string
	for id := range e.reach {
		node, ok := e.nodes[id]
		if ok && node.Type == kind && match(node) {
			result = append(result, id)
		}
	}
	sort.Strings(result)
	return result
}

func (e evaluation) directTargets(kind domain.NodeType, edgeTypes ...domain.EdgeType) []string {
	allowed := make(map[domain.EdgeType]bool, len(edgeTypes))
	for _, edgeType := range edgeTypes {
		allowed[edgeType] = true
	}
	var result []string
	for _, edge := range e.direct {
		if allowed[edge.Type] && e.nodes[edge.To].Type == kind {
			result = append(result, edge.To)
		}
	}
	return uniqueStrings(result)
}

func (e evaluation) directByEvidence(kind domain.NodeType, evidenceType string) ([]string, []domain.Evidence) {
	var nodes []string
	var evidence []domain.Evidence
	for _, edge := range e.direct {
		if e.nodes[edge.To].Type != kind {
			continue
		}
		for _, item := range edge.Evidence {
			if item.Type == evidenceType {
				nodes = append(nodes, edge.To)
				evidence = append(evidence, item)
			}
		}
	}
	return uniqueStrings(nodes), uniqueEvidence(evidence)
}

func (e evaluation) independentComponents() []string {
	workflows := e.directTargets(domain.NodeWorkflow, domain.EdgeConfiguredIn, domain.EdgeExplicitlyForwardedTo)
	services := e.directTargets(domain.NodeComposeService, domain.EdgeAvailableToService, domain.EdgeMountedAsSecret, domain.EdgeExplicitlyForwardedTo)
	jobs := e.directTargets(domain.NodeJob, domain.EdgeConfiguredIn, domain.EdgeExplicitlyForwardedTo, domain.EdgeAvailableToProcess)
	result := appendCopy(workflows, services...)
	if len(workflows) == 0 || len(jobs) >= 2 {
		result = append(result, jobs...)
	}
	return uniqueStrings(result)
}

func (e evaluation) nodeEvidence(ids []string) []domain.Evidence {
	var result []domain.Evidence
	for _, id := range ids {
		result = append(result, e.nodes[id].Evidence...)
	}
	return uniqueEvidence(result)
}

func (e evaluation) pathsFor(nodeIDs []string) []string {
	wanted := make(map[string]bool, len(nodeIDs))
	for _, id := range nodeIDs {
		wanted[id] = true
	}
	var result []string
	for _, path := range e.paths {
		for _, node := range path.Nodes {
			if wanted[node.ID] {
				result = append(result, path.ID)
				break
			}
		}
	}
	return uniqueStrings(result)
}

func uniqueStrings(items []string) []string {
	set := make(map[string]struct{}, len(items))
	for _, item := range items {
		if item != "" {
			set[item] = struct{}{}
		}
	}
	result := make([]string, 0, len(set))
	for item := range set {
		result = append(result, item)
	}
	sort.Strings(result)
	return result
}

func uniqueEvidence(items []domain.Evidence) []domain.Evidence {
	set := make(map[string]domain.Evidence, len(items))
	for _, item := range items {
		key := strings.Join([]string{item.Type, item.RuleID, item.Description, item.Location.Path, strconv.Itoa(item.Location.Line), strconv.Itoa(item.Location.Column), item.Field, item.Source, string(item.Confidence)}, "\x00")
		set[key] = item
	}
	result := make([]domain.Evidence, 0, len(set))
	for _, item := range set {
		result = append(result, item)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Location.Path != result[j].Location.Path {
			return result[i].Location.Path < result[j].Location.Path
		}
		if result[i].Location.Line != result[j].Location.Line {
			return result[i].Location.Line < result[j].Location.Line
		}
		if result[i].Field != result[j].Field {
			return result[i].Field < result[j].Field
		}
		return result[i].Type < result[j].Type
	})
	return result
}

func appendCopy(base []string, items ...string) []string {
	result := make([]string, len(base), len(base)+len(items))
	copy(result, base)
	return append(result, items...)
}

func isRootUser(value string) bool {
	value = strings.TrimSpace(strings.ToLower(value))
	return value == "root" || value == "0" || strings.HasPrefix(value, "0:") || strings.HasPrefix(value, "root:")
}
