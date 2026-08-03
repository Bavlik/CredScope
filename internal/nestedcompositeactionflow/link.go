// Package nestedcompositeactionflow implements Phase CA3B: confirmed
// call-specific input forwarding through repository-local nested composite
// actions. It is a pure computation over already-computed CA2
// (internal/compositeactionflow) and CA3A (internal/compositeaction) output:
// it never touches the filesystem, never parses YAML, never builds graph
// nodes or edges, and never mutates its inputs. Every Link invocation
// returns a wholly independent, freshly allocated Result.
//
// Link only ever extends an already-confirmed CA2 ConfirmedInputFlow one (or
// more) nesting levels deeper: it never re-derives a root-level secret-to-
// input flow itself (that remains CA2's exclusive responsibility), and it
// never infers a confirmed nested flow from the mere existence of a CA2
// InputUsage — a usage record only proves the declared input is read
// somewhere inside that internal step (with:, if:, env:, run:, shell:,
// working-directory: are all indistinguishably swept into one
// ActionStep.References list). Link independently inspects the exact
// ActionStep.With mapping at that step and applies its own dedicated,
// whole-value `${{ inputs.NAME }}` matcher before ever treating a nested
// step as a forwarding call.
package nestedcompositeactionflow

import (
	"context"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/Bavlik/CredScope/internal/compositeaction"
	"github.com/Bavlik/CredScope/internal/compositeactionflow"
	"github.com/Bavlik/CredScope/internal/domain"
	"github.com/Bavlik/CredScope/internal/sanitizer"
)

// DiagnosticKind is the closed set of CA3B linker diagnostics. None of these
// correspond to a rules.Catalog entry, a Finding, a score effect, or a
// remediation. Cycle and depth are never diagnosed here — CA3A already owns
// those diagnostics; CA3B's own onPath/depth tracking (see expandUsage) is
// an operational recursion-safety gate only, never a second source of cycle
// or depth notices.
type DiagnosticKind string

const (
	// DiagnosticUndeclaredInput fires when a nested call's With binding is a
	// clean, whole-value reference to the exact parent input currently being
	// expanded, but the binding's own alias has no matching
	// ActionInputDefinition on the resolved child action.
	DiagnosticUndeclaredInput DiagnosticKind = "nested_undeclared_input"
	// DiagnosticRequiredInputMissing fires when a nested call's resolved
	// child action declares a required input (with no default) that has no
	// With binding at all at that exact call site.
	DiagnosticRequiredInputMissing DiagnosticKind = "nested_required_input_missing"
	// DiagnosticDynamicInputReference fires when a With binding's raw value
	// contains an `inputs[...]` indexing form inside `${{ ... }}`. No static
	// input name can ever be recovered for this shape.
	DiagnosticDynamicInputReference DiagnosticKind = "nested_dynamic_input_reference"
	// DiagnosticAmbiguousInputSources fires when a With binding's value
	// contains two or more distinct statically named action-input
	// references.
	DiagnosticAmbiguousInputSources DiagnosticKind = "nested_ambiguous_input_sources"
	// DiagnosticUnsupportedInputExpression fires when a With binding's value
	// references exactly one static action input, but the whole scalar is
	// not exactly `${{ inputs.NAME }}` (surrounding whitespace only) — a
	// prefix/suffix, a format() call, a conditional, or a defensive
	// Value/References disagreement.
	DiagnosticUnsupportedInputExpression DiagnosticKind = "nested_unsupported_input_expression"
)

// CallPathSegment is one hop in an ordered, root-to-here nested call path:
// the parent canonical directory and its exact internal action-step index,
// together with the child canonical directory that step resolves to.
type CallPathSegment struct {
	ParentCanonicalDirectory string
	ParentActionStepIndex    int
	ChildCanonicalDirectory  string
}

// InputUsage is one internal ActionStep's usage of a specific declared
// input, scoped to the ConfirmedNestedInputFlow that contains it — mirrors
// compositeactionflow.InputUsage exactly, kept as a distinct type so this
// package never re-exports a CA2 type as part of its own public shape.
type InputUsage struct {
	ActionStepIndex int
	ActionStepID    string
	Evidence        domain.Evidence
}

// ConfirmedNestedInputFlow represents one specific nested call-site binding
// — identified by its exact root invocation, ordered call path, and child
// input alias — whose value was proven, by whole-value static matching, to
// be exactly a forward of the already-confirmed parent flow input, and whose
// resolved child action reads that declared input in at least one internal
// step. The raw binding Value is deliberately not present here and must
// never be serialized by any consumer of this type; neither is any input
// default content.
type ConfirmedNestedInputFlow struct {
	RootCallerWorkflow  string
	RootCallerJobID     string
	RootCallerStepIndex int
	RootCallerStepID    string
	RootInputName       string
	RootSourceSecret    string

	// CallPath is the ordered, root-to-here chain of nesting hops; always a
	// freshly allocated slice, never shared with any sibling flow or any
	// other Link invocation's output.
	CallPath []CallPathSegment

	ParentCanonicalDirectory string
	ParentInputName          string
	ParentUsageStepIndex     int
	ParentUsageStepID        string

	ChildCanonicalDirectory string
	ChildInputName          string

	BindingEvidence domain.Evidence
	// Usages is always freshly allocated, never shared with any other flow
	// or any other Link invocation's output.
	Usages []InputUsage
}

// Diagnostic is one deterministic CA3B linker notice.
type Diagnostic struct {
	Kind DiagnosticKind

	RootCallerWorkflow  string
	RootCallerJobID     string
	RootCallerStepIndex int

	// CallPath is the root-to-parent chain (not including the current hop),
	// always a freshly allocated slice.
	CallPath []CallPathSegment

	ParentCanonicalDirectory string
	ParentActionStepIndex    int
	ChildCanonicalDirectory  string
	ChildInputName           string

	Evidence domain.Evidence
}

// Result is the deterministic, immutable output of Link.
type Result struct {
	Flows       []ConfirmedNestedInputFlow
	Diagnostics []Diagnostic
}

// confirmedActionInputExpressionPattern is the dedicated, conservative
// whole-value matcher required by CA3B: it accepts only a scalar whose
// entire content, modulo surrounding whitespace inside the expression
// delimiters, is exactly one static dot-notation action-input reference. It
// deliberately does not rely on a len(References) == 1 shortcut, mirroring
// compositeactionflow's own confirmedSecretExpressionPattern rationale
// exactly, one context literal apart ("inputs" here, "secrets" there). This
// is a dedicated, independent matcher — CA2's own secret matcher is never
// generalized or reused for this purpose.
var confirmedActionInputExpressionPattern = regexp.MustCompile(`(?i)^\$\{\{\s*inputs\.([A-Za-z_][A-Za-z0-9_-]*)\s*\}\}$`)

// dynamicActionInputIndexPattern detects an `inputs[...]` indexing form
// anywhere inside a `${{ ... }}` expression, mirroring
// compositeactionflow's own dynamicSecretIndexPattern exactly: the parser's
// expression regex requires a literal `.` immediately after a context name,
// so it never produces a ReferenceActionInput for this shape at all (zero
// references, not a misclassified one) — this pattern exists solely so CA3B
// can positively diagnose the attempt.
var dynamicActionInputIndexPattern = regexp.MustCompile(`(?i)\$\{\{[^}]*\binputs\s*\[`)

type parentStepKey struct {
	directory string
	stepIndex int
}

// parentFrame carries every root-invariant field plus the current level's
// parent identity and usage list through one recursive expansion.
type parentFrame struct {
	rootWorkflow  string
	rootJobID     string
	rootStepIndex int
	rootStepID    string
	rootInputName string
	rootSecret    string

	callPath           []CallPathSegment
	canonicalDirectory string
	inputName          string
	usages             []InputUsage
}

type linker struct {
	ctx                     context.Context
	actionsByDirectory      map[string]domain.ActionMetadata
	nestedCallsByParentStep map[parentStepKey]domain.NestedCompositeActionCall

	flows          []ConfirmedNestedInputFlow
	diagnostics    []Diagnostic
	diagnosticSeen map[string]bool
}

// Link matches every already-confirmed CA2 caller-binding usage against its
// resolved nested composite-action call site's own With mapping, recursively,
// to the CA3A-supported nesting depth. It reads rootFlows and resolution
// only; it never mutates either, and every returned slice (including nested
// CallPath/Usages slices) is freshly allocated and independent of any other
// Link invocation's output.
func Link(ctx context.Context, rootFlows compositeactionflow.Result, resolution domain.CompositeActionResolution) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}

	actionsByDirectory := make(map[string]domain.ActionMetadata, len(resolution.Actions))
	for _, action := range resolution.Actions {
		actionsByDirectory[action.Directory] = action
	}
	nestedCallsByParentStep := make(map[parentStepKey]domain.NestedCompositeActionCall, len(resolution.NestedCalls))
	for _, call := range resolution.NestedCalls {
		nestedCallsByParentStep[parentStepKey{call.ParentCanonicalDirectory, call.ParentActionStepIndex}] = call
	}

	l := &linker{
		ctx: ctx, actionsByDirectory: actionsByDirectory, nestedCallsByParentStep: nestedCallsByParentStep,
		diagnosticSeen: make(map[string]bool),
	}

	for _, flow := range rootFlows.Flows {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		usages := make([]InputUsage, 0, len(flow.Usages))
		for _, u := range flow.Usages {
			usages = append(usages, InputUsage{ActionStepIndex: u.ActionStepIndex, ActionStepID: u.ActionStepID, Evidence: u.Evidence})
		}
		frame := parentFrame{
			rootWorkflow: flow.CallerWorkflow, rootJobID: flow.CallerJobID, rootStepIndex: flow.CallerStepIndex,
			rootStepID: flow.CallerStepID, rootInputName: flow.InputName, rootSecret: flow.SourceSecret,
			canonicalDirectory: flow.CanonicalDirectory, inputName: flow.InputName, usages: usages,
		}
		// onPath is initialized with the root's own canonical directory and
		// is scoped to exactly this one root flow's expansion — a diamond or
		// cycle reached from a different root flow must never be affected by
		// this map (each root flow gets its own, fresh onPath).
		onPath := map[string]bool{flow.CanonicalDirectory: true}
		if err := l.expand(frame, onPath, 1); err != nil {
			return Result{}, err
		}
	}

	sort.Slice(l.flows, func(i, j int) bool { return lessFlow(l.flows[i], l.flows[j]) })
	sort.Slice(l.diagnostics, func(i, j int) bool { return lessDiagnostic(l.diagnostics[i], l.diagnostics[j]) })
	return Result{Flows: l.flows, Diagnostics: l.diagnostics}, nil
}

// expand independently inspects each of frame's usages: a parent input may
// legitimately be read at several internal steps, and only some of those
// steps are themselves resolved nested composite-action calls at all.
func (l *linker) expand(frame parentFrame, onPath map[string]bool, depth int) error {
	for _, usage := range frame.usages {
		if err := l.ctx.Err(); err != nil {
			return err
		}
		if err := l.expandUsage(frame, usage, onPath, depth); err != nil {
			return err
		}
	}
	return nil
}

// expandUsage inspects exactly one parent usage step. It never assumes the
// step is a resolved nested call merely because a CA2/CA3B usage record
// exists there — it looks up the exact (parent directory, step index) pair
// in nestedCallsByParentStep and requires resolved_local_composite before
// doing anything else, which is also precisely the mechanism that makes a
// usage originating from with:/if:/env:/run:/shell:/working-directory: text
// with no actual nested uses: step silently produce nothing here: no entry
// ever exists in that index for a step with no Action reference at all.
func (l *linker) expandUsage(frame parentFrame, usage InputUsage, onPath map[string]bool, depth int) error {
	nestedCall, ok := l.nestedCallsByParentStep[parentStepKey{frame.canonicalDirectory, usage.ActionStepIndex}]
	if !ok || nestedCall.Status != domain.CompositeActionResolvedLocalComposite {
		return nil
	}
	childDir := nestedCall.CanonicalDirectory
	if onPath[childDir] {
		// Cycle: CA3A's own detectNestedCycles already emits the cycle
		// diagnostic for this path over the same NestedCalls data; this
		// check exists solely to stop CA3B's own recursive flow expansion
		// from looping forever, never to emit a second, CA3B-owned notice.
		return nil
	}
	if depth+1 > compositeaction.MaxCompositeActionNestingDepth {
		// Depth: CA3A's own detectNestedDepthExceeded already emits the
		// depth diagnostic for this path; this check exists solely to stop
		// CA3B's own recursive flow expansion at the same boundary, never to
		// emit a second, CA3B-owned notice.
		return nil
	}
	parentAction, ok := l.actionsByDirectory[frame.canonicalDirectory]
	if !ok {
		return nil
	}
	childAction, ok := l.actionsByDirectory[childDir]
	if !ok {
		return nil
	}
	if nestedCall.ParentActionStepIndex < 0 || nestedCall.ParentActionStepIndex >= len(parentAction.Runs.Steps) {
		return nil
	}
	parentStep := parentAction.Runs.Steps[nestedCall.ParentActionStepIndex]

	declaredByName := make(map[string]domain.ActionInputDefinition, len(childAction.Inputs))
	for _, input := range childAction.Inputs {
		declaredByName[input.Name] = input
	}
	boundNames := make(map[string]bool, len(parentStep.With))
	for _, binding := range parentStep.With {
		boundNames[binding.Name] = true
	}
	for _, input := range childAction.Inputs {
		if !input.Required || input.Default != nil || boundNames[input.Name] {
			continue
		}
		l.emitDiagnostic(DiagnosticRequiredInputMissing, frame, nestedCall, input.Name, input.Evidence)
	}

	for _, binding := range parentStep.With {
		if err := l.ctx.Err(); err != nil {
			return err
		}
		matchedInput, diagKind, hasDiagnostic := classifyNestedBinding(binding)
		if hasDiagnostic {
			l.emitDiagnostic(diagKind, frame, nestedCall, binding.Name, binding.Evidence)
			continue
		}
		if matchedInput == "" || matchedInput != frame.inputName {
			// Zero action-input references, or a clean whole-value
			// reference to a different (possibly separately confirmed)
			// parent input: not an error, not a match for this flow.
			continue
		}
		declared, isDeclared := declaredByName[binding.Name]
		if !isDeclared {
			l.emitDiagnostic(DiagnosticUndeclaredInput, frame, nestedCall, binding.Name, binding.Evidence)
			continue
		}
		childUsages := compositeactionflow.InternalUsages(childAction, declared.Name)
		if len(childUsages) == 0 {
			// Declared but internally unused: no confirmed flow, no
			// diagnostic (mirrors CA2's own H.10 precedent one level deeper).
			continue
		}
		usages := make([]InputUsage, 0, len(childUsages))
		for _, u := range childUsages {
			usages = append(usages, InputUsage{ActionStepIndex: u.ActionStepIndex, ActionStepID: u.ActionStepID, Evidence: u.Evidence})
		}
		segment := CallPathSegment{ParentCanonicalDirectory: frame.canonicalDirectory, ParentActionStepIndex: nestedCall.ParentActionStepIndex, ChildCanonicalDirectory: childDir}
		nextCallPath := append(append([]CallPathSegment(nil), frame.callPath...), segment)

		flow := ConfirmedNestedInputFlow{
			RootCallerWorkflow: frame.rootWorkflow, RootCallerJobID: frame.rootJobID, RootCallerStepIndex: frame.rootStepIndex,
			RootCallerStepID: frame.rootStepID, RootInputName: frame.rootInputName, RootSourceSecret: frame.rootSecret,
			CallPath:                 nextCallPath,
			ParentCanonicalDirectory: frame.canonicalDirectory, ParentInputName: frame.inputName,
			ParentUsageStepIndex: usage.ActionStepIndex, ParentUsageStepID: usage.ActionStepID,
			ChildCanonicalDirectory: childDir, ChildInputName: declared.Name,
			BindingEvidence: binding.Evidence, Usages: usages,
		}
		l.flows = append(l.flows, flow)

		nextFrame := parentFrame{
			rootWorkflow: frame.rootWorkflow, rootJobID: frame.rootJobID, rootStepIndex: frame.rootStepIndex,
			rootStepID: frame.rootStepID, rootInputName: frame.rootInputName, rootSecret: frame.rootSecret,
			callPath: nextCallPath, canonicalDirectory: childDir, inputName: declared.Name, usages: usages,
		}
		onPath[childDir] = true
		err := l.expand(nextFrame, onPath, depth+1)
		delete(onPath, childDir)
		if err != nil {
			return err
		}
	}
	return nil
}

// classifyNestedBinding determines binding's shape, independent of which
// parent input is currently being expanded. matchedName is non-empty only
// for a clean, whole-value, single static `${{ inputs.NAME }}` reference;
// the caller alone decides whether that matched name equals the currently
// confirmed parent input. hasDiagnostic reports whether diagKind should be
// emitted; a binding with zero action-input references produces neither a
// matched name nor a diagnostic (a legitimate, common, silent case).
func classifyNestedBinding(binding domain.ActionInputBinding) (matchedName string, diagKind DiagnosticKind, hasDiagnostic bool) {
	if dynamicActionInputIndexPattern.MatchString(binding.Value) {
		return "", DiagnosticDynamicInputReference, true
	}
	names := distinctActionInputReferenceNames(binding.References)
	switch len(names) {
	case 0:
		return "", "", false
	case 1:
		matched, ok := matchWholeValueActionInput(binding.Value)
		// Both the whole-value matcher's own name and the parser's
		// structured ReferenceActionInput name must agree; a candidate is
		// never produced from Value alone. Disagreement is treated
		// defensively as unsupported, exactly like compositeactionflow's
		// own posture.
		if !ok || matched != names[0] {
			return "", DiagnosticUnsupportedInputExpression, true
		}
		return matched, "", false
	default:
		return "", DiagnosticAmbiguousInputSources, true
	}
}

// matchWholeValueActionInput reports the sole statically named action input
// when value, trimmed of surrounding whitespace, is exactly
// `${{ inputs.NAME }}` with only internal whitespace variance permitted
// around NAME. It is the only place in this package that inspects a
// binding's raw Value; its result (a bare input name) is the only thing
// ever retained.
func matchWholeValueActionInput(value string) (string, bool) {
	match := confirmedActionInputExpressionPattern.FindStringSubmatch(strings.TrimSpace(value))
	if match == nil {
		return "", false
	}
	name := sanitizer.Identifier(match[1])
	if name == "" {
		return "", false
	}
	return name, true
}

// distinctActionInputReferenceNames collects each distinct
// ReferenceActionInput name found in refs, in first-appearance order.
func distinctActionInputReferenceNames(refs []domain.Reference) []string {
	seen := make(map[string]bool, len(refs))
	names := make([]string, 0, len(refs))
	for _, ref := range refs {
		if ref.Kind != domain.ReferenceActionInput || seen[ref.Name] {
			continue
		}
		seen[ref.Name] = true
		names = append(names, ref.Name)
	}
	return names
}

// emitDiagnostic records one diagnostic, deduplicated so that the same
// underlying (root invocation, call path, exact nested call site, offending
// child input/alias) never produces more than one diagnostic merely because
// two independently confirmed sibling flows (e.g. two aliases both fed by
// the same or different already-confirmed parent inputs) both happen to
// reach the identical nested call site.
func (l *linker) emitDiagnostic(kind DiagnosticKind, frame parentFrame, nestedCall domain.NestedCompositeActionCall, childInputName string, ev domain.Evidence) {
	key := diagnosticDedupKey(kind, frame, nestedCall.ParentActionStepIndex, childInputName)
	if l.diagnosticSeen[key] {
		return
	}
	l.diagnosticSeen[key] = true
	l.diagnostics = append(l.diagnostics, Diagnostic{
		Kind:               kind,
		RootCallerWorkflow: frame.rootWorkflow, RootCallerJobID: frame.rootJobID, RootCallerStepIndex: frame.rootStepIndex,
		CallPath:                 append([]CallPathSegment(nil), frame.callPath...),
		ParentCanonicalDirectory: frame.canonicalDirectory, ParentActionStepIndex: nestedCall.ParentActionStepIndex,
		ChildCanonicalDirectory: nestedCall.CanonicalDirectory, ChildInputName: childInputName,
		Evidence: ev,
	})
}

func diagnosticDedupKey(kind DiagnosticKind, frame parentFrame, parentActionStepIndex int, childInputName string) string {
	var b strings.Builder
	b.WriteString(string(kind))
	b.WriteByte(0)
	b.WriteString(frame.rootWorkflow)
	b.WriteByte(0)
	b.WriteString(frame.rootJobID)
	b.WriteByte(0)
	b.WriteString(strconv.Itoa(frame.rootStepIndex))
	b.WriteByte(0)
	for _, seg := range frame.callPath {
		b.WriteString(seg.ParentCanonicalDirectory)
		b.WriteByte(0)
		b.WriteString(strconv.Itoa(seg.ParentActionStepIndex))
		b.WriteByte(0)
		b.WriteString(seg.ChildCanonicalDirectory)
		b.WriteByte(0)
	}
	b.WriteString(frame.canonicalDirectory)
	b.WriteByte(0)
	b.WriteString(strconv.Itoa(parentActionStepIndex))
	b.WriteByte(0)
	b.WriteString(childInputName)
	return b.String()
}

func compareCallPath(a, b []CallPathSegment) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i].ParentCanonicalDirectory != b[i].ParentCanonicalDirectory {
			return strings.Compare(a[i].ParentCanonicalDirectory, b[i].ParentCanonicalDirectory)
		}
		if a[i].ParentActionStepIndex != b[i].ParentActionStepIndex {
			return a[i].ParentActionStepIndex - b[i].ParentActionStepIndex
		}
		if a[i].ChildCanonicalDirectory != b[i].ChildCanonicalDirectory {
			return strings.Compare(a[i].ChildCanonicalDirectory, b[i].ChildCanonicalDirectory)
		}
	}
	return len(a) - len(b)
}

func lessFlow(a, b ConfirmedNestedInputFlow) bool {
	if a.RootCallerWorkflow != b.RootCallerWorkflow {
		return a.RootCallerWorkflow < b.RootCallerWorkflow
	}
	if a.RootCallerJobID != b.RootCallerJobID {
		return a.RootCallerJobID < b.RootCallerJobID
	}
	if a.RootCallerStepIndex != b.RootCallerStepIndex {
		return a.RootCallerStepIndex < b.RootCallerStepIndex
	}
	if a.RootInputName != b.RootInputName {
		return a.RootInputName < b.RootInputName
	}
	if c := compareCallPath(a.CallPath, b.CallPath); c != 0 {
		return c < 0
	}
	if a.ChildInputName != b.ChildInputName {
		return a.ChildInputName < b.ChildInputName
	}
	return a.ChildCanonicalDirectory < b.ChildCanonicalDirectory
}

func lessDiagnostic(a, b Diagnostic) bool {
	if a.Kind != b.Kind {
		return a.Kind < b.Kind
	}
	if a.RootCallerWorkflow != b.RootCallerWorkflow {
		return a.RootCallerWorkflow < b.RootCallerWorkflow
	}
	if a.RootCallerJobID != b.RootCallerJobID {
		return a.RootCallerJobID < b.RootCallerJobID
	}
	if a.RootCallerStepIndex != b.RootCallerStepIndex {
		return a.RootCallerStepIndex < b.RootCallerStepIndex
	}
	if c := compareCallPath(a.CallPath, b.CallPath); c != 0 {
		return c < 0
	}
	if a.ParentCanonicalDirectory != b.ParentCanonicalDirectory {
		return a.ParentCanonicalDirectory < b.ParentCanonicalDirectory
	}
	if a.ParentActionStepIndex != b.ParentActionStepIndex {
		return a.ParentActionStepIndex < b.ParentActionStepIndex
	}
	return a.ChildInputName < b.ChildInputName
}
