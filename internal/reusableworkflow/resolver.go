// Package reusableworkflow resolves job-level `uses:` reusable workflow calls
// against a fixed, immutable set of already-parsed workflows. It performs no
// filesystem or network access and never mutates its input.
package reusableworkflow

import (
	"regexp"
	"sort"
	"strings"

	"github.com/Bavlik/CredScope/internal/domain"
)

// DirectStatus is a closed set of outcomes for a single job-level `uses:` call.
type DirectStatus string

const (
	// StatusResolvedLocal means the call targets a workflow found in the
	// input set that declares a workflow_call trigger.
	StatusResolvedLocal DirectStatus = "resolved_local"
	// StatusOpaqueExternal means the call targets another repository. It is
	// never fetched and never treated as missing.
	StatusOpaqueExternal DirectStatus = "opaque_external"
	// StatusUnsupportedExpression means the raw uses value contains a
	// ${{ ... }} expression and cannot be statically resolved.
	StatusUnsupportedExpression DirectStatus = "unsupported_expression"
	// StatusRejectedPath means the raw uses value looks like a local
	// reference but does not match the accepted structural shape.
	StatusRejectedPath DirectStatus = "rejected_path"
	// StatusTargetMissing means the normalized local path is well-formed but
	// no workflow with that canonical path is present in the input set.
	StatusTargetMissing DirectStatus = "target_missing"
	// StatusTargetNotReusable means the target workflow exists but does not
	// declare a workflow_call trigger.
	StatusTargetNotReusable DirectStatus = "target_not_reusable"
)

// DirectCall is the resolution outcome for a single job-level `uses:` call.
type DirectCall struct {
	CallerWorkflow   string
	CallerJobID      string
	RawUses          string
	NormalizedTarget string
	Status           DirectStatus
	Reason           string
	Evidence         domain.Evidence
	TargetWorkflow   string
}

// ChainDiagnosticKind is a closed set of chain-level (multi-workflow)
// diagnostic categories, distinct from the per-call DirectStatus.
type ChainDiagnosticKind string

const (
	ChainCycle         ChainDiagnosticKind = "cycle"
	ChainDepthExceeded ChainDiagnosticKind = "depth_exceeded"
)

// ChainDiagnostic describes a property of the directed graph formed by
// StatusResolvedLocal calls: a cycle, or a chain that exceeds the maximum
// supported depth. Path holds canonical workflow paths in traversal order.
type ChainDiagnostic struct {
	Kind  ChainDiagnosticKind
	Path  []string
	Depth int
}

// Result is the deterministic output of Resolve.
type Result struct {
	DirectCalls []DirectCall
	Chains      []ChainDiagnostic
}

// MaxChainDepth is the maximum number of workflows permitted in one resolved
// reusable-call chain, counting the initial workflow as depth 1.
const MaxChainDepth = 10

var driveLetterPattern = regexp.MustCompile(`^[A-Za-z]:`)

// Resolve computes direct call resolutions and chain diagnostics for the
// given workflows. It reads workflows and never writes to them; the returned
// Result contains only new, independently allocated records.
func Resolve(workflows []domain.Workflow) Result {
	index := buildIndex(workflows)

	var calls []DirectCall
	for _, wf := range workflows {
		for _, job := range wf.Jobs {
			if job.ReusableWorkflow == nil {
				continue
			}
			calls = append(calls, resolveCall(index, wf, job))
		}
	}
	sort.Slice(calls, func(i, j int) bool { return lessCall(calls[i], calls[j]) })

	chains := buildChainDiagnostics(workflows, calls)

	return Result{DirectCalls: calls, Chains: chains}
}

func buildIndex(workflows []domain.Workflow) map[string]domain.Workflow {
	index := make(map[string]domain.Workflow, len(workflows))
	for _, wf := range workflows {
		index[wf.File] = wf
	}
	return index
}

func resolveCall(index map[string]domain.Workflow, caller domain.Workflow, job domain.WorkflowJob) DirectCall {
	raw := job.ReusableWorkflow.Reference
	call := DirectCall{
		CallerWorkflow: caller.File,
		CallerJobID:    job.ID,
		RawUses:        raw,
		Evidence:       job.ReusableWorkflow.Evidence,
	}

	if strings.Contains(raw, "${{") {
		call.Status = StatusUnsupportedExpression
		call.Reason = "expression_in_uses"
		return call
	}

	if !isLocalAttempt(raw) {
		call.Status = StatusOpaqueExternal
		return call
	}

	normalized, reason, ok := validateLocalPath(raw)
	if !ok {
		call.Status = StatusRejectedPath
		call.Reason = reason
		return call
	}
	call.NormalizedTarget = normalized

	target, found := index[normalized]
	if !found {
		call.Status = StatusTargetMissing
		call.Reason = "target_workflow_not_found"
		return call
	}
	if !hasWorkflowCallTrigger(target) {
		call.Status = StatusTargetNotReusable
		call.Reason = "target_missing_workflow_call_trigger"
		return call
	}

	call.Status = StatusResolvedLocal
	call.TargetWorkflow = normalized
	return call
}

// isLocalAttempt reports whether raw could only ever be intended as a local
// filesystem-shaped reference (as opposed to an owner/repo external
// reference), so it must be strictly validated rather than treated as opaque.
func isLocalAttempt(raw string) bool {
	switch {
	case strings.HasPrefix(raw, "./"):
		return true
	case strings.HasPrefix(raw, "../"):
		return true
	case strings.HasPrefix(raw, "/"):
		return true
	case strings.Contains(raw, "\\"):
		return true
	case driveLetterPattern.MatchString(raw):
		return true
	}
	return false
}

const workflowsDir = ".github/workflows/"

// validateLocalPath accepts only ./.github/workflows/<single-file>.yml (or
// .yaml). On success it returns the normalized, case-preserved target path
// in the same form as domain.Workflow.File (no leading "./").
func validateLocalPath(raw string) (normalized, reason string, ok bool) {
	switch {
	case strings.Contains(raw, "\\"):
		return "", "backslash_in_path", false
	case strings.HasPrefix(raw, "../"):
		return "", "parent_traversal", false
	case !strings.HasPrefix(raw, "./"):
		return "", "not_relative_local_path", false
	}

	rest := raw[len("./"):]
	if strings.Contains(rest, "..") {
		return "", "parent_traversal", false
	}
	if !strings.HasPrefix(rest, workflowsDir) {
		return "", "outside_workflows_directory", false
	}

	filename := rest[len(workflowsDir):]
	if filename == "" {
		return "", "empty_filename", false
	}
	if strings.Contains(filename, "/") {
		return "", "nested_workflow_directory", false
	}
	if strings.ContainsAny(filename, "?#") {
		return "", "query_or_fragment_suffix", false
	}

	var base string
	switch {
	case strings.HasSuffix(filename, ".yml"):
		base = strings.TrimSuffix(filename, ".yml")
	case strings.HasSuffix(filename, ".yaml"):
		base = strings.TrimSuffix(filename, ".yaml")
	default:
		return "", "wrong_extension", false
	}
	if base == "" {
		return "", "empty_filename", false
	}

	return rest, "", true
}

func hasWorkflowCallTrigger(wf domain.Workflow) bool {
	for _, trigger := range wf.Triggers {
		if trigger.Name == "workflow_call" {
			return true
		}
	}
	return false
}

func lessCall(a, b DirectCall) bool {
	if a.CallerWorkflow != b.CallerWorkflow {
		return a.CallerWorkflow < b.CallerWorkflow
	}
	if a.CallerJobID != b.CallerJobID {
		return a.CallerJobID < b.CallerJobID
	}
	return a.RawUses < b.RawUses
}

// buildChainDiagnostics builds a directed graph from resolved-local calls
// only, then reports cycles and chains that exceed MaxChainDepth. Every
// workflow present in the input is treated as a potential chain root, since
// depth-exceedance is a property of a specific traversal path, not of the
// edge itself: the same edge may be shallow from one root and over-depth
// from another.
func buildChainDiagnostics(workflows []domain.Workflow, calls []DirectCall) []ChainDiagnostic {
	edgesByCaller := make(map[string][]DirectCall)
	for _, call := range calls {
		if call.Status != StatusResolvedLocal {
			continue
		}
		edgesByCaller[call.CallerWorkflow] = append(edgesByCaller[call.CallerWorkflow], call)
	}
	for caller := range edgesByCaller {
		edges := edgesByCaller[caller]
		sort.Slice(edges, func(i, j int) bool {
			if edges[i].TargetWorkflow != edges[j].TargetWorkflow {
				return edges[i].TargetWorkflow < edges[j].TargetWorkflow
			}
			return edges[i].CallerJobID < edges[j].CallerJobID
		})
		edgesByCaller[caller] = edges
	}

	roots := make([]string, 0, len(workflows))
	for _, wf := range workflows {
		roots = append(roots, wf.File)
	}
	sort.Strings(roots)

	cycles := detectCycles(roots, edgesByCaller)
	depthExceeded := detectDepthExceeded(roots, edgesByCaller)

	diagnostics := make([]ChainDiagnostic, 0, len(cycles)+len(depthExceeded))
	diagnostics = append(diagnostics, cycles...)
	diagnostics = append(diagnostics, depthExceeded...)
	sort.Slice(diagnostics, func(i, j int) bool { return lessChainDiagnostic(diagnostics[i], diagnostics[j]) })
	return diagnostics
}

func detectCycles(roots []string, edgesByCaller map[string][]DirectCall) []ChainDiagnostic {
	seen := make(map[string]ChainDiagnostic)
	for _, root := range roots {
		var stack []string
		onStack := make(map[string]int, len(roots))
		var walk func(node string)
		walk = func(node string) {
			stack = append(stack, node)
			onStack[node] = len(stack) - 1
			for _, edge := range edgesByCaller[node] {
				child := edge.TargetWorkflow
				if idx, inStack := onStack[child]; inStack {
					cycle := append([]string(nil), stack[idx:]...)
					canonical := canonicalizeCycle(cycle)
					key := strings.Join(canonical, "\x00")
					if _, exists := seen[key]; !exists {
						seen[key] = ChainDiagnostic{Kind: ChainCycle, Path: canonical}
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
	result := make([]ChainDiagnostic, 0, len(seen))
	for _, diag := range seen {
		result = append(result, diag)
	}
	return result
}

// canonicalizeCycle rotates a cycle so it starts at its lexicographically
// smallest node, making the representation independent of which node the
// traversal happened to start from.
func canonicalizeCycle(cycle []string) []string {
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

func detectDepthExceeded(roots []string, edgesByCaller map[string][]DirectCall) []ChainDiagnostic {
	var result []ChainDiagnostic
	for _, root := range roots {
		path := []string{root}
		var walk func(node string, depth int)
		walk = func(node string, depth int) {
			for _, edge := range edgesByCaller[node] {
				childDepth := depth + 1
				childPath := append(append([]string(nil), path...), edge.TargetWorkflow)
				if childDepth > MaxChainDepth {
					result = append(result, ChainDiagnostic{Kind: ChainDepthExceeded, Path: childPath, Depth: childDepth})
					continue
				}
				path = childPath
				walk(edge.TargetWorkflow, childDepth)
				path = path[:len(path)-1]
			}
		}
		walk(root, 1)
	}
	return result
}

func lessChainDiagnostic(a, b ChainDiagnostic) bool {
	if a.Kind != b.Kind {
		return a.Kind < b.Kind
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
