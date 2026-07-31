// Package compositeactionflow links workflow-step `with:` bindings to
// resolved, repository-local composite-action declared inputs and their
// internal ActionStep usages. It is a pure computation over already-parsed
// domain values: it never touches the filesystem, never parses YAML, never
// builds graph nodes or edges, and never mutates its inputs. Every Link
// invocation returns wholly independent, freshly allocated output.
//
// Link only ever produces a confirmed flow for a caller binding whose entire
// raw scalar value is exactly one static `${{ secrets.NAME }}` expression
// (surrounding whitespace only) for a resolved_local_composite call whose
// canonical action declares the bound input and internally reads it via at
// least one `${{ inputs.<name> }}` usage. Every other shape (undeclared
// input, ambiguous or dynamic secret reference, non-whole-value secret
// expression, unresolved/external/docker/malformed action, zero internal
// usage) produces no flow, only — where applicable — a deterministic,
// non-scoring, non-rule diagnostic.
package compositeactionflow

import (
	"context"
	"regexp"
	"sort"
	"strings"

	"github.com/Bavlik/CredScope/internal/domain"
	"github.com/Bavlik/CredScope/internal/sanitizer"
)

// DiagnosticKind is the closed set of CA2 linker diagnostics. None of these
// correspond to a rules.Catalog entry, a Finding, a score effect, or a
// remediation: they are structural, offline-analysis notices only.
type DiagnosticKind string

const (
	// DiagnosticUndeclaredInput fires when a resolved local composite call's
	// caller binding name has no matching ActionInputDefinition.
	DiagnosticUndeclaredInput DiagnosticKind = "undeclared_input"
	// DiagnosticRequiredInputMissing fires when a declared required input
	// (with no default) has no caller binding at all.
	DiagnosticRequiredInputMissing DiagnosticKind = "required_input_missing"
	// DiagnosticDynamicSecretReference fires when a caller binding's raw
	// value contains a `secrets[...]` indexing form inside `${{ ... }}`. No
	// static secret name can ever be invented for this case.
	DiagnosticDynamicSecretReference DiagnosticKind = "dynamic_secret_reference"
	// DiagnosticAmbiguousSecretSources fires when a caller binding's value
	// contains two or more distinct statically named secret references.
	DiagnosticAmbiguousSecretSources DiagnosticKind = "ambiguous_secret_sources"
	// DiagnosticUnsupportedSecretExpression fires when a caller binding's
	// value references exactly one static secret, but the whole scalar is
	// not exactly `${{ secrets.NAME }}` (surrounding whitespace only) —
	// e.g. a prefix/suffix, a format() call, or a conditional.
	DiagnosticUnsupportedSecretExpression DiagnosticKind = "unsupported_secret_expression"
)

// Diagnostic is one deterministic CA2 linker notice.
type Diagnostic struct {
	Kind               DiagnosticKind
	CallerWorkflow     string
	CallerJobID        string
	CallerStepIndex    int
	CallerStepID       string
	CanonicalDirectory string
	InputName          string
	Evidence           domain.Evidence
}

// InputUsage is one internal ActionStep's usage of a specific declared input,
// scoped to the ConfirmedInputFlow that contains it (its identity is only
// ever meaningful alongside its parent flow's caller/binding identity).
type InputUsage struct {
	ActionStepIndex int
	ActionStepID    string
	Evidence        domain.Evidence
}

// ConfirmedInputFlow represents one specific caller binding — identified by
// its exact call site and input name — whose value was proven, by whole-value
// static matching, to be exactly one named secret reference, and whose
// canonical action reads that declared input in at least one internal step.
// SourceSecret is only ever a secret name, never a value. The raw caller
// binding Value is deliberately not present here and must never be
// serialized by any consumer of this type.
type ConfirmedInputFlow struct {
	CallerWorkflow     string
	CallerJobID        string
	CallerStepIndex    int
	CallerStepID       string
	CanonicalDirectory string
	InputName          string
	SourceSecret       string
	BindingEvidence    domain.Evidence
	Usages             []InputUsage
}

// Result is the deterministic, immutable output of Link.
type Result struct {
	Flows       []ConfirmedInputFlow
	Diagnostics []Diagnostic
}

type stepKey struct {
	workflow  string
	jobID     string
	stepIndex int
}

// Link matches every workflow-step `with:` binding against its resolved
// local composite-action target's declared inputs and internal usages. It
// reads workflows and resolution only; it never mutates either, and every
// returned slice (including nested Usages slices) is freshly allocated and
// independent of any other Link invocation's output.
func Link(ctx context.Context, workflows []domain.Workflow, resolution domain.CompositeActionResolution) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}

	actionsByDirectory := make(map[string]domain.ActionMetadata, len(resolution.Actions))
	for _, action := range resolution.Actions {
		actionsByDirectory[action.Directory] = action
	}
	callsByStep := make(map[stepKey]domain.CompositeActionCall, len(resolution.Calls))
	for _, call := range resolution.Calls {
		callsByStep[stepKey{call.CallerWorkflow, call.CallerJobID, call.CallerStepIndex}] = call
	}

	var flows []ConfirmedInputFlow
	var diagnostics []Diagnostic

	for _, wf := range workflows {
		for _, job := range wf.Jobs {
			for stepIndex, step := range job.Steps {
				if err := ctx.Err(); err != nil {
					return Result{}, err
				}
				// Note: do not skip a step merely because step.With is
				// empty — a required_input_missing diagnostic must still
				// fire for a resolved local composite call whose caller
				// supplies no `with:` block at all, not only for one whose
				// `with:` is present but incomplete.
				call, hasCall := callsByStep[stepKey{wf.File, job.ID, stepIndex}]
				if !hasCall || call.Status != domain.CompositeActionResolvedLocalComposite {
					// Every non-resolved-local-composite status (opaque
					// external/docker, unsupported expression, rejected
					// path, metadata missing/ambiguous/malformed, and
					// target_not_composite) gets no CA2 flow and no CA2
					// diagnostic: CA1 already diagnoses problematic
					// resolution statuses on its own.
					continue
				}
				action, ok := actionsByDirectory[call.CanonicalDirectory]
				if !ok {
					continue
				}
				declaredByName := make(map[string]domain.ActionInputDefinition, len(action.Inputs))
				for _, input := range action.Inputs {
					declaredByName[input.Name] = input
				}
				boundNames := make(map[string]bool, len(step.With))
				for _, binding := range step.With {
					boundNames[binding.Name] = true
					if _, declared := declaredByName[binding.Name]; !declared {
						diagnostics = append(diagnostics, Diagnostic{
							Kind: DiagnosticUndeclaredInput, CallerWorkflow: wf.File, CallerJobID: job.ID,
							CallerStepIndex: stepIndex, CallerStepID: step.ID, CanonicalDirectory: call.CanonicalDirectory,
							InputName: binding.Name, Evidence: binding.Evidence,
						})
						continue
					}
					flow, diagnostic, hasFlow := classifyBinding(wf.File, job.ID, stepIndex, step.ID, call.CanonicalDirectory, binding)
					if diagnostic != nil {
						diagnostics = append(diagnostics, *diagnostic)
					}
					if !hasFlow {
						continue
					}
					usages := internalUsages(action, binding.Name)
					if len(usages) == 0 {
						// Part H.10: a declared input with zero internal
						// step usages produces no confirmed flow, even
						// though the binding itself was a clean single
						// secret reference.
						continue
					}
					flow.Usages = usages
					flows = append(flows, flow)
				}
				for _, input := range action.Inputs {
					if !input.Required || input.Default != nil || boundNames[input.Name] {
						continue
					}
					diagnostics = append(diagnostics, Diagnostic{
						Kind: DiagnosticRequiredInputMissing, CallerWorkflow: wf.File, CallerJobID: job.ID,
						CallerStepIndex: stepIndex, CallerStepID: step.ID, CanonicalDirectory: call.CanonicalDirectory,
						InputName: input.Name, Evidence: input.Evidence,
					})
				}
			}
		}
	}

	sort.Slice(flows, func(i, j int) bool { return lessFlow(flows[i], flows[j]) })
	sort.Slice(diagnostics, func(i, j int) bool { return lessDiagnostic(diagnostics[i], diagnostics[j]) })
	return Result{Flows: flows, Diagnostics: diagnostics}, nil
}

// dynamicSecretIndexPattern detects a `secrets[...]` indexing form anywhere
// inside a `${{ ... }}` expression. extractReferences' own regex requires a
// literal `.` immediately after a context name, so it never matches this
// form at all (zero references, not a misclassified one) — this pattern
// exists solely so CA2 can positively diagnose the attempt rather than
// silently treating it as an unremarkable non-secret literal.
var dynamicSecretIndexPattern = regexp.MustCompile(`(?i)\$\{\{[^}]*\bsecrets\s*\[`)

// confirmedSecretExpressionPattern is the dedicated, conservative whole-value
// matcher required by CA2: it accepts only a scalar whose entire content,
// modulo surrounding whitespace inside the expression delimiters, is exactly
// one static dot-notation secret reference. It deliberately does not use
// extractReferences' len(References) == 1 shortcut, since format(),
// conditionals, and string concatenation can all also produce exactly one
// ReferenceSecret while the raw value is not a truthful single substitution.
var confirmedSecretExpressionPattern = regexp.MustCompile(`(?i)^\$\{\{\s*secrets\.([A-Za-z_][A-Za-z0-9_-]*)\s*\}\}$`)

// classifyBinding determines whether one caller binding (already confirmed to
// target a declared input) qualifies for confirmed secret flow. It returns at
// most one diagnostic and never fabricates a flow for anything other than a
// clean, whole-value, single static secret reference.
func classifyBinding(callerWorkflow, callerJobID string, callerStepIndex int, callerStepID, canonicalDirectory string, binding domain.ActionCallInputBinding) (ConfirmedInputFlow, *Diagnostic, bool) {
	if dynamicSecretIndexPattern.MatchString(binding.Value) {
		return ConfirmedInputFlow{}, &Diagnostic{
			Kind: DiagnosticDynamicSecretReference, CallerWorkflow: callerWorkflow, CallerJobID: callerJobID,
			CallerStepIndex: callerStepIndex, CallerStepID: callerStepID, CanonicalDirectory: canonicalDirectory,
			InputName: binding.Name, Evidence: binding.Evidence,
		}, false
	}

	secretNames := distinctSecretReferenceNames(binding.References)
	switch len(secretNames) {
	case 0:
		// noncredential_binding: a legitimate, expected, silent case (a
		// literal, or a reference to a non-secret context). CA2 emits no
		// diagnostic and creates no flow.
		return ConfirmedInputFlow{}, nil, false
	case 1:
		matched, ok := matchWholeValueSecret(binding.Value)
		// Both the whole-value matcher's own name and the parser's
		// structured ReferenceSecret name must agree; a confirmed flow is
		// never created from Value alone. Disagreement is not expected in
		// practice (the same parser output feeds both), but is treated as
		// unsupported rather than trusted, matching the same
		// defense-in-depth posture as every other rejection in this
		// function.
		if !ok || matched != secretNames[0] {
			return ConfirmedInputFlow{}, &Diagnostic{
				Kind: DiagnosticUnsupportedSecretExpression, CallerWorkflow: callerWorkflow, CallerJobID: callerJobID,
				CallerStepIndex: callerStepIndex, CallerStepID: callerStepID, CanonicalDirectory: canonicalDirectory,
				InputName: binding.Name, Evidence: binding.Evidence,
			}, false
		}
		return ConfirmedInputFlow{
			CallerWorkflow: callerWorkflow, CallerJobID: callerJobID, CallerStepIndex: callerStepIndex,
			CallerStepID: callerStepID, CanonicalDirectory: canonicalDirectory, InputName: binding.Name,
			SourceSecret: matched, BindingEvidence: binding.Evidence,
		}, nil, true
	default:
		return ConfirmedInputFlow{}, &Diagnostic{
			Kind: DiagnosticAmbiguousSecretSources, CallerWorkflow: callerWorkflow, CallerJobID: callerJobID,
			CallerStepIndex: callerStepIndex, CallerStepID: callerStepID, CanonicalDirectory: canonicalDirectory,
			InputName: binding.Name, Evidence: binding.Evidence,
		}, false
	}
}

// matchWholeValueSecret reports the sole statically named secret when value,
// trimmed of surrounding whitespace, is exactly `${{ secrets.NAME }}` with
// only internal whitespace variance permitted around NAME. It is the only
// place in CA2 that inspects a binding's raw Value; its result (a bare
// secret name) is the only thing ever retained. The captured name is run
// through sanitizer.Identifier — the same normalization extractReferences
// already applies when it produces a ReferenceSecret's Name — so the
// agreement check in classifyBinding compares two names produced by
// identical normalization, rather than a raw regex capture against an
// already-normalized reference name.
func matchWholeValueSecret(value string) (string, bool) {
	match := confirmedSecretExpressionPattern.FindStringSubmatch(strings.TrimSpace(value))
	if match == nil {
		return "", false
	}
	name := sanitizer.Identifier(match[1])
	if name == "" {
		return "", false
	}
	return name, true
}

// distinctSecretReferenceNames collects each distinct ReferenceSecret name
// found in refs, in first-appearance order.
func distinctSecretReferenceNames(refs []domain.Reference) []string {
	seen := make(map[string]bool, len(refs))
	names := make([]string, 0, len(refs))
	for _, ref := range refs {
		if ref.Kind != domain.ReferenceSecret || seen[ref.Name] {
			continue
		}
		seen[ref.Name] = true
		names = append(names, ref.Name)
	}
	return names
}

// internalUsages scans action's own composite runs.steps in source order for
// ActionStep.References entries naming inputName as a ReferenceActionInput.
// At most one InputUsage is produced per internal step index: multiple
// references to the same input within one step (whether from run, if,
// shell, working-directory, env, or with) collapse into a single usage
// carrying that step's deterministically earliest evidence location. Action
// output references are never inspected.
func internalUsages(action domain.ActionMetadata, inputName string) []InputUsage {
	usages := make([]InputUsage, 0, len(action.Runs.Steps))
	for stepIndex, step := range action.Runs.Steps {
		found := false
		var earliest domain.Evidence
		for _, ref := range step.References {
			if ref.Kind != domain.ReferenceActionInput || ref.Name != inputName {
				continue
			}
			if !found || isEarlierEvidence(ref.Evidence, earliest) {
				earliest = ref.Evidence
				found = true
			}
		}
		if !found {
			continue
		}
		usages = append(usages, InputUsage{ActionStepIndex: stepIndex, ActionStepID: step.ID, Evidence: earliest})
	}
	sort.Slice(usages, func(i, j int) bool { return lessUsage(usages[i], usages[j]) })
	return usages
}

func isEarlierEvidence(a, b domain.Evidence) bool {
	if a.Location.Line != b.Location.Line {
		return a.Location.Line < b.Location.Line
	}
	if a.Location.Column != b.Location.Column {
		return a.Location.Column < b.Location.Column
	}
	return a.Field < b.Field
}

func lessUsage(a, b InputUsage) bool {
	if a.ActionStepIndex != b.ActionStepIndex {
		return a.ActionStepIndex < b.ActionStepIndex
	}
	if a.Evidence.Location.Line != b.Evidence.Location.Line {
		return a.Evidence.Location.Line < b.Evidence.Location.Line
	}
	return a.Evidence.Location.Column < b.Evidence.Location.Column
}

func lessFlow(a, b ConfirmedInputFlow) bool {
	if a.CallerWorkflow != b.CallerWorkflow {
		return a.CallerWorkflow < b.CallerWorkflow
	}
	if a.CallerJobID != b.CallerJobID {
		return a.CallerJobID < b.CallerJobID
	}
	if a.CallerStepIndex != b.CallerStepIndex {
		return a.CallerStepIndex < b.CallerStepIndex
	}
	return a.InputName < b.InputName
}

func lessDiagnostic(a, b Diagnostic) bool {
	if a.Kind != b.Kind {
		return a.Kind < b.Kind
	}
	if a.CallerWorkflow != b.CallerWorkflow {
		return a.CallerWorkflow < b.CallerWorkflow
	}
	if a.CallerJobID != b.CallerJobID {
		return a.CallerJobID < b.CallerJobID
	}
	if a.CallerStepIndex != b.CallerStepIndex {
		return a.CallerStepIndex < b.CallerStepIndex
	}
	return a.InputName < b.InputName
}
