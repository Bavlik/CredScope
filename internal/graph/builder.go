package graph

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/Bavlik/CredScope/internal/classification"
	"github.com/Bavlik/CredScope/internal/domain"
	"github.com/Bavlik/CredScope/internal/reusableworkflow"
	"github.com/Bavlik/CredScope/internal/sanitizer"
)

type BuildOptions struct {
	Classifications  map[string]domain.Classification
	IgnoredVariables map[string]domain.IgnoredItem
	// ReusableWorkflows carries the resolver's direct-call outcomes, computed
	// once by the caller (typically internal/analysis) before graph
	// construction. A zero-value Result is safe: every reusable workflow
	// call is then represented exactly as an unresolved call, matching the
	// pre-resolver behavior.
	ReusableWorkflows reusableworkflow.Result
	// CompositeActions carries internal/compositeaction.Resolve's immutable
	// output, computed once by internal/ingest before graph construction. A
	// zero-value CompositeActionResolution is safe: no call-site metadata is
	// added and no canonical composite-action node is created, matching
	// pre-CA1 behavior. The graph builder performs no filesystem access or
	// action-metadata parsing of its own; it only ever reads this value.
	CompositeActions domain.CompositeActionResolution
}

type BuildResult struct {
	Graph         domain.Graph
	Credentials   []domain.CredentialSubject
	Warnings      []string
	LimitExceeded bool
	Ignored       []domain.IgnoredItem
}

type builder struct {
	graph                       *mutableGraph
	credentials                 map[string]*credentialState
	warnings                    map[string]struct{}
	options                     BuildOptions
	ignored                     map[string]domain.IgnoredItem
	resolvedCalls               map[string]reusableworkflow.DirectCall
	workflowsByFile             map[string]domain.Workflow
	compositeCallsByStep        map[string]domain.CompositeActionCall
	compositeActionsByDirectory map[string]domain.ActionMetadata
}

type credentialState struct {
	id                   string
	label                string
	kind                 string
	fingerprints         map[string]struct{}
	kinds                map[domain.ReferenceKind]struct{}
	importedFinding      bool
	testFixtureCandidate bool
}

// Build constructs a graph from scanner-neutral parsed repository data. It
// never resolves expressions or executes repository content.
func Build(parsed domain.ParsedRepository) BuildResult {
	return BuildWithOptions(parsed, BuildOptions{})
}

func BuildWithOptions(parsed domain.ParsedRepository, options BuildOptions) BuildResult {
	resolvedCalls := make(map[string]reusableworkflow.DirectCall, len(options.ReusableWorkflows.DirectCalls))
	for _, call := range options.ReusableWorkflows.DirectCalls {
		resolvedCalls[call.CallerWorkflow+"\x00"+call.CallerJobID] = call
	}
	compositeCallsByStep := make(map[string]domain.CompositeActionCall, len(options.CompositeActions.Calls))
	for _, call := range options.CompositeActions.Calls {
		compositeCallsByStep[compositeStepKey(call.CallerWorkflow, call.CallerJobID, call.CallerStepIndex)] = call
	}
	compositeActionsByDirectory := make(map[string]domain.ActionMetadata, len(options.CompositeActions.Actions))
	for _, action := range options.CompositeActions.Actions {
		compositeActionsByDirectory[action.Directory] = action
	}
	b := &builder{
		graph: newMutable(), credentials: make(map[string]*credentialState), warnings: make(map[string]struct{}),
		options: options, ignored: make(map[string]domain.IgnoredItem), resolvedCalls: resolvedCalls,
		compositeCallsByStep: compositeCallsByStep, compositeActionsByDirectory: compositeActionsByDirectory,
	}
	b.build(parsed)
	return b.finish()
}

func compositeStepKey(callerWorkflow, callerJobID string, callerStepIndex int) string {
	return callerWorkflow + "\x00" + callerJobID + "\x00" + strconv.Itoa(callerStepIndex)
}

func (b *builder) build(parsed domain.ParsedRepository) {
	b.workflowsByFile = make(map[string]domain.Workflow, len(parsed.Workflows))
	for _, workflow := range parsed.Workflows {
		b.workflowsByFile[workflow.File] = workflow
	}
	repoID := b.graph.addNode(domain.NodeRepository, "selected-repository", "repository", nil, map[string]string{"scope": "selected_root"}, nil, domain.ConfidenceConfirmed)
	for _, finding := range parsed.Findings {
		credentialID := b.credential(finding.Credential.Label, finding.Credential.Type, finding.Credential.Fingerprint, "", true, finding.TestFixtureCandidate)
		if credentialID == "" {
			continue
		}
		findingEvidence := domain.Evidence{Type: "scanner_finding", RuleID: finding.RuleID, Description: finding.Description, Location: finding.Location, Field: "finding", Source: finding.Source, Confidence: domain.ConfidenceConfirmed}
		findingID := b.graph.addNode(domain.NodeFinding, finding.ID, finding.RuleID, &finding.Location, map[string]string{"scanner": finding.Source, "rule_id": finding.RuleID}, []domain.Evidence{findingEvidence}, domain.ConfidenceConfirmed)
		b.graph.addEdge(credentialID, findingID, domain.EdgeDetectedIn, []domain.Evidence{findingEvidence}, domain.ConfidenceConfirmed)
		if finding.Location.Path != "" {
			fileID := b.file(finding.Location.Path, findingEvidence)
			b.graph.addEdge(findingID, fileID, domain.EdgeDetectedIn, []domain.Evidence{findingEvidence}, domain.ConfidenceConfirmed)
			b.graph.addEdge(fileID, repoID, domain.EdgeDetectedIn, []domain.Evidence{findingEvidence}, domain.ConfidenceConfirmed)
		}
	}
	for _, workflow := range parsed.Workflows {
		b.workflow(repoID, workflow)
	}
	// Secret forwarding runs only after every workflow (including every
	// callee) has been fully processed above, because it must reuse the
	// credential nodes callees already created from their own genuine
	// secret usage rather than fabricate alias nodes from the contract
	// declaration alone.
	b.propagateReusableWorkflowSecrets(parsed.Workflows)
	b.emitReusableSecretsInheritDiagnostics(parsed.Workflows)
	for _, project := range parsed.Compose {
		b.compose(repoID, project)
	}
}

func (b *builder) credential(label, kind, fingerprint string, referenceKind domain.ReferenceKind, importedFinding, testFixtureCandidate bool) string {
	label = sanitizer.Identifier(label)
	if label == "" {
		b.warnings["A parsed credential reference had an empty name and was excluded from analysis."] = struct{}{}
		return ""
	}
	key := strings.ToUpper(label)
	if ignored, ok := b.options.IgnoredVariables[key]; ok {
		ignored.Count++
		b.ignored["variable\x00"+key] = ignored
		return ""
	}
	state := b.credentials[key]
	if state == nil {
		state = &credentialState{label: label, kind: kind, fingerprints: make(map[string]struct{}), kinds: make(map[domain.ReferenceKind]struct{})}
		state.id = b.graph.addNode(domain.NodeCredential, key, label, nil, map[string]string{"credential_type": kind}, nil, domain.ConfidenceConfirmed)
		b.credentials[key] = state
	}
	if referenceKind != "" {
		state.kinds[referenceKind] = struct{}{}
	}
	state.importedFinding = state.importedFinding || importedFinding
	state.testFixtureCandidate = state.testFixtureCandidate || testFixtureCandidate
	if state.kind == "" && kind != "" {
		state.kind = kind
	}
	if fingerprint != "" {
		state.fingerprints[fingerprint] = struct{}{}
	}
	return state.id
}

func (b *builder) reference(ref domain.Reference) string {
	if ref.Kind != domain.ReferenceSecret && ref.Kind != domain.ReferenceComposeVariable && ref.Kind != domain.ReferenceComposeSecret {
		return ""
	}
	return b.credential(ref.Name, string(ref.Kind), "", ref.Kind, false, false)
}

func (b *builder) file(path string, ev domain.Evidence) string {
	return b.graph.addNode(domain.NodeFile, path, path, &domain.Location{Path: path}, map[string]string{"path": path}, []domain.Evidence{ev}, domain.ConfidenceConfirmed)
}

func (b *builder) workflow(repoID string, workflow domain.Workflow) {
	fileID := b.file(workflow.File, workflow.Evidence)
	b.graph.addEdge(fileID, repoID, domain.EdgeDetectedIn, []domain.Evidence{evidence("repository_file", workflow.Evidence, "Workflow file belongs to the selected repository.", domain.ConfidenceConfirmed)}, domain.ConfidenceConfirmed)
	wfKey := nodeKey(workflow.File, workflow.Name)
	wfEvidence := append([]domain.Evidence{workflow.Evidence}, signalEvidence(workflow.Signals)...)
	wfID := b.graph.addNode(domain.NodeWorkflow, wfKey, workflow.Name, locationPtr(workflow.Evidence), map[string]string{"file": workflow.File, "missing_explicit_permissions": boolText(workflow.MissingExplicitPermissions)}, wfEvidence, domain.ConfidenceConfirmed)
	b.graph.addEdge(wfID, fileID, domain.EdgeDetectedIn, []domain.Evidence{evidence("workflow_definition", workflow.Evidence, "Workflow is defined in this file.", domain.ConfidenceConfirmed)}, domain.ConfidenceConfirmed)
	for _, ref := range workflow.References {
		if credentialID := b.reference(ref); credentialID != "" {
			b.graph.addTypedEdge(credentialID, wfID, domain.EdgeConfiguredIn, domain.EvidenceExposureContext, []domain.Evidence{evidence("credential_reference", ref.Evidence, "Workflow contains this reference.", ref.Evidence.Confidence)}, ref.Evidence.Confidence)
		}
	}
	for _, trigger := range workflow.Triggers {
		triggerID := b.graph.addNode(domain.NodeTrigger, nodeKey(wfKey, trigger.Name), trigger.Name, locationPtr(trigger.Evidence), map[string]string{"name": trigger.Name}, []domain.Evidence{trigger.Evidence}, trigger.Evidence.Confidence)
		b.graph.addEdge(wfID, triggerID, domain.EdgeTriggeredBy, []domain.Evidence{evidence("workflow_trigger", trigger.Evidence, "Workflow declares this trigger.", trigger.Evidence.Confidence)}, trigger.Evidence.Confidence)
	}
	for _, permission := range workflow.Permissions {
		b.permission(wfID, wfKey, permission)
	}
	for _, binding := range workflow.Environment {
		for _, ref := range binding.References {
			if credentialID := b.reference(ref); credentialID != "" {
				b.graph.addTypedEdge(credentialID, wfID, domain.EdgeConfiguredIn, domain.EvidenceConfirmedDataFlow, []domain.Evidence{evidence("workflow_environment", ref.Evidence, "Reference is configured in workflow-level environment scope.", ref.Evidence.Confidence)}, ref.Evidence.Confidence)
			}
		}
	}
	jobIDs := make(map[string]string, len(workflow.Jobs))
	var workflowEnvironmentRefs []domain.Reference
	for _, binding := range workflow.Environment {
		workflowEnvironmentRefs = append(workflowEnvironmentRefs, binding.References...)
	}
	for _, job := range workflow.Jobs {
		jobKey := nodeKey(wfKey, job.ID)
		jobEvidence := append([]domain.Evidence{job.Evidence}, signalEvidence(job.Signals)...)
		jobIDs[job.ID] = b.graph.addNode(domain.NodeJob, jobKey, jobLabel(job), locationPtr(job.Evidence), map[string]string{"job_id": job.ID, "workflow": workflow.Name}, jobEvidence, domain.ConfidenceConfirmed)
	}
	for _, job := range workflow.Jobs {
		inherited := workflowEnvironmentRefs
		if job.ReusableWorkflow != nil {
			inherited = nil
		}
		b.job(workflow, wfID, wfKey, jobIDs, job, inherited)
	}
}

func (b *builder) permission(parent, parentKey string, permission domain.Permission) {
	key := nodeKey(parentKey, permission.Scope, permission.Level, permission.Evidence.Field)
	permissionID := b.graph.addNode(domain.NodePermission, key, permission.Scope+":"+permission.Level, locationPtr(permission.Evidence), map[string]string{"scope": permission.Scope, "level": permission.Level}, []domain.Evidence{permission.Evidence}, permission.Evidence.Confidence)
	b.graph.addEdge(parent, permissionID, domain.EdgeHasPermission, []domain.Evidence{evidence("permission", permission.Evidence, "Explicit GitHub Actions permission.", permission.Evidence.Confidence)}, permission.Evidence.Confidence)
}

func (b *builder) job(workflow domain.Workflow, wfID, wfKey string, jobIDs map[string]string, job domain.WorkflowJob, inheritedRefs []domain.Reference) {
	jobID := jobIDs[job.ID]
	jobKey := nodeKey(wfKey, job.ID)
	b.graph.addTypedEdge(jobID, wfID, domain.EdgeBelongsTo, domain.EvidenceExposureContext, []domain.Evidence{evidence("workflow_job", job.Evidence, "Job belongs to this workflow.", domain.ConfidenceConfirmed)}, domain.ConfidenceConfirmed)
	for _, need := range job.Needs {
		if dependencyID := jobIDs[need]; dependencyID != "" {
			b.graph.addEdge(jobID, dependencyID, domain.EdgeDependsOn, []domain.Evidence{evidence("job_dependency", job.Evidence, "Job declares a dependency.", domain.ConfidenceConfirmed)}, domain.ConfidenceConfirmed)
		}
	}
	for _, permission := range job.Permissions {
		b.permission(jobID, jobKey, permission)
	}
	if job.EnvironmentName != "" {
		confidence := domain.ConfidenceConfirmed
		if productionLike(job.EnvironmentName) {
			confidence = domain.ConfidenceMedium
		}
		environmentEvidence := job.Evidence
		if job.EnvironmentEvidence != nil {
			environmentEvidence = *job.EnvironmentEvidence
		}
		environmentID := b.graph.addNode(domain.NodeEnvironment, nodeKey(workflow.File, job.EnvironmentName), job.EnvironmentName, locationPtr(environmentEvidence), map[string]string{"production_like": boolText(productionLike(job.EnvironmentName))}, []domain.Evidence{environmentEvidence}, confidence)
		b.graph.addEdge(jobID, environmentID, domain.EdgeUsesEnvironment, []domain.Evidence{evidence("deployment_environment", environmentEvidence, "Job declares a GitHub environment.", confidence)}, confidence)
	}
	for _, ref := range job.References {
		if credentialID := b.reference(ref); credentialID != "" {
			b.graph.addTypedEdge(credentialID, jobID, domain.EdgeConfiguredIn, domain.EvidenceExposureContext, []domain.Evidence{evidence("job_credential_reference", ref.Evidence, "Job contains this reference.", ref.Evidence.Confidence)}, ref.Evidence.Confidence)
		}
	}
	for _, binding := range job.Environment {
		for _, ref := range binding.References {
			if credentialID := b.reference(ref); credentialID != "" {
				b.graph.addTypedEdge(credentialID, jobID, domain.EdgeExplicitlyForwardedTo, domain.EvidenceConfirmedDataFlow, []domain.Evidence{evidence("job_environment", ref.Evidence, "Reference is explicitly forwarded into job-level environment scope.", ref.Evidence.Confidence)}, ref.Evidence.Confidence)
			}
		}
	}
	propagatedRefs := append([]domain.Reference{}, inheritedRefs...)
	for _, binding := range job.Environment {
		propagatedRefs = append(propagatedRefs, binding.References...)
	}
	for _, ref := range inheritedRefs {
		if credentialID := b.reference(ref); credentialID != "" {
			b.graph.addTypedEdge(credentialID, jobID, domain.EdgeAvailableToProcess, domain.EvidenceConfirmedDataFlow, []domain.Evidence{evidence("workflow_environment", ref.Evidence, "Workflow-level environment reference is available to this job.", ref.Evidence.Confidence)}, ref.Evidence.Confidence)
		}
	}
	if job.ReusableWorkflow != nil {
		b.reusableWorkflowCall(workflow, jobID, jobKey, job)
	}
	for outputIndex, output := range job.Outputs {
		for _, ref := range output.References {
			if credentialID := b.reference(ref); credentialID != "" {
				b.graph.addTypedEdge(credentialID, jobID, domain.EdgeExplicitlyForwardedTo, domain.EvidenceConfirmedDataFlow, []domain.Evidence{evidence("job_output", ref.Evidence, "Reference is explicitly forwarded through a job output.", domain.ConfidenceConfirmed)}, domain.ConfidenceConfirmed)
			}
		}
		_ = outputIndex
	}
	for index, step := range job.Steps {
		stepID := b.step(workflow.File, job.ID, jobID, jobKey, index, step)
		for _, ref := range propagatedRefs {
			if credentialID := b.reference(ref); credentialID != "" {
				b.graph.addTypedEdge(credentialID, stepID, domain.EdgeAvailableToProcess, domain.EvidenceConfirmedDataFlow, []domain.Evidence{evidence("inherited_environment", ref.Evidence, "Environment reference is available to this workflow step.", ref.Evidence.Confidence)}, ref.Evidence.Confidence)
			}
		}
	}
}

// reusableWorkflowCall represents a job-level `uses:` reusable workflow call.
// It preserves the pre-resolver "unresolved" representation exactly for every
// status other than resolved_local. For a resolved local call it additionally
// links the call-site node to the already-created target workflow node using
// EvidenceStructuralCallOnly, which traversal never walks through: the edge
// is a truthful structural fact, not credential data flow or exposure
// evidence, so it cannot by itself make CRD501 fire or expose the callee's
// secrets/permissions to whatever credential reaches the caller.
func (b *builder) reusableWorkflowCall(workflow domain.Workflow, jobID, jobKey string, job domain.WorkflowJob) {
	action := job.ReusableWorkflow
	call, hasCall := b.resolvedCalls[workflow.File+"\x00"+job.ID]
	resolved := hasCall && call.Status == reusableworkflow.StatusResolvedLocal
	nodeID := b.graph.addNode(domain.NodeReusableWorkflow, nodeKey(jobKey, action.Reference), action.Reference, locationPtr(action.Evidence), actionMetadata(*action, !resolved), []domain.Evidence{action.Evidence}, domain.ConfidenceConfirmed)
	if !resolved {
		b.graph.addEdge(jobID, nodeID, domain.EdgeCallsWorkflow, []domain.Evidence{evidence("reusable_workflow", action.Evidence, "Reusable workflow reference was recorded but not resolved.", domain.ConfidenceUnknown)}, domain.ConfidenceUnknown)
		return
	}
	b.graph.addEdge(jobID, nodeID, domain.EdgeCallsWorkflow, []domain.Evidence{evidence("reusable_workflow", action.Evidence, "Reusable workflow reference was resolved to a local workflow.", domain.ConfidenceConfirmed)}, domain.ConfidenceConfirmed)
	target, ok := b.workflowsByFile[call.TargetWorkflow]
	if !ok {
		return
	}
	targetID := workflowNodeID(call.TargetWorkflow, target.Name)
	structuralEvidence := []domain.Evidence{evidence("resolved_reusable_call", action.Evidence, "Caller structurally invokes this reusable workflow; this is not credential data flow or permission exposure.", domain.ConfidenceConfirmed)}
	b.graph.addTypedEdge(nodeID, targetID, domain.EdgeCallsWorkflow, domain.EvidenceStructuralCallOnly, structuralEvidence, domain.ConfidenceConfirmed)
}

func workflowNodeID(file, name string) string {
	return stableID("node:"+string(domain.NodeWorkflow), nodeKey(file, name))
}

// propagateReusableWorkflowSecrets connects a caller's explicit job-level
// `secrets:` forwarding to the callee's declared workflow_call.secrets
// contract, but only for calls the resolver marked resolved_local, only for
// caller values it can statically prove are a single literal secret
// reference, and only for aliases the callee genuinely uses (i.e. a
// credential node already exists for that alias from the callee's own
// normal processing above). This is a single flat pass over every job in
// every workflow: it never recurses, so it cannot loop on a reusable-call
// cycle, and nested forwarding chains (A->B->C) fall out naturally because
// each hop independently reuses the same content-addressed credential
// nodes — graph traversal, not this pass, is what walks the resulting
// multi-hop chain.
func (b *builder) propagateReusableWorkflowSecrets(workflows []domain.Workflow) {
	for _, caller := range workflows {
		for _, job := range caller.Jobs {
			if len(job.ReusableWorkflowSecrets) == 0 {
				continue
			}
			call, hasCall := b.resolvedCalls[caller.File+"\x00"+job.ID]
			if !hasCall || call.Status != reusableworkflow.StatusResolvedLocal {
				continue
			}
			target, ok := b.workflowsByFile[call.TargetWorkflow]
			if !ok || target.WorkflowCall == nil {
				continue
			}
			declared := make(map[string]bool, len(target.WorkflowCall.Secrets))
			for _, secretDef := range target.WorkflowCall.Secrets {
				declared[secretDef.Name] = true
			}
			for _, binding := range job.ReusableWorkflowSecrets {
				if !declared[binding.Name] {
					b.warnings[fmt.Sprintf("Reusable workflow job %q in %q forwards secret alias %q that is not declared in %q's workflow_call.secrets contract; no forwarding edge was created.", job.ID, caller.File, binding.Name, target.File)] = struct{}{}
					continue
				}
				sourceRef, ok := singleSecretReference(binding.References)
				if !ok {
					continue
				}
				b.forwardReusableWorkflowSecret(caller, job.ID, binding, sourceRef, target)
			}
		}
	}
}

// singleSecretReference reports the caller-side value's sole secrets.<name>
// reference. It deliberately refuses anything else the parser may have
// found in that same value — zero secret references (a literal string, or
// an expression over env/inputs/vars/github context), or more than one
// (concatenation of multiple secrets) — since neither can be treated as a
// single confirmed forwarded credential.
func singleSecretReference(refs []domain.Reference) (domain.Reference, bool) {
	var found domain.Reference
	count := 0
	for _, ref := range refs {
		if ref.Kind == domain.ReferenceSecret {
			found = ref
			count++
		}
	}
	return found, count == 1
}

// referencesNamed collects every already-parsed Reference of the given kind
// and name from a workflow's aggregated reference list; used here to find
// the callee's own usage evidence for a forwarded secret alias.
func referencesNamed(refs []domain.Reference, kind domain.ReferenceKind, name string) []domain.Reference {
	var result []domain.Reference
	for _, ref := range refs {
		if ref.Kind == kind && ref.Name == name {
			result = append(result, ref)
		}
	}
	return result
}

// forwardReusableWorkflowSecret links the caller's already-existing source
// credential node to the callee's already-existing alias credential node
// with a confirmed, security-traversable EdgeExplicitlyForwardedTo edge.
// The alias's credential node is looked up, never created here: if the
// callee's own processing never produced one, the alias was declared but
// never actually used, and no forwarding edge is created — this call alone
// must not fabricate a credential that only exists as a contract name.
func (b *builder) forwardReusableWorkflowSecret(caller domain.Workflow, jobID string, binding domain.ReusableWorkflowSecret, sourceRef domain.Reference, target domain.Workflow) {
	targetState, ok := b.credentials[strings.ToUpper(binding.Name)]
	if !ok {
		return
	}
	sourceCredentialID := b.reference(sourceRef)
	if sourceCredentialID == "" || sourceCredentialID == targetState.id {
		return
	}
	evidenceItems := []domain.Evidence{
		evidence("reusable_secret_forwarding_caller", binding.Evidence, "Caller explicitly forwards this secret to the reusable workflow's declared secret alias \""+binding.Name+"\" in "+target.File+".", domain.ConfidenceConfirmed),
	}
	for _, usage := range referencesNamed(target.References, domain.ReferenceSecret, binding.Name) {
		evidenceItems = append(evidenceItems, evidence("reusable_secret_forwarding_callee_usage", usage.Evidence, "Reusable workflow "+target.File+" uses the forwarded secret under alias \""+binding.Name+"\".", domain.ConfidenceConfirmed))
	}
	// Metadata is folded into the edge's content-addressed identity (see
	// addTypedEdgeWithMetadata) so two distinct caller jobs never collapse
	// into one edge merely because they forward the same source secret to
	// the same callee alias, and so downstream consumers (including
	// traversal's reusable-workflow hop cap) can read the resolved call
	// identity directly instead of parsing evidence text.
	metadata := map[string]string{
		"caller_workflow":              caller.File,
		"caller_job_id":                jobID,
		"target_workflow":              target.File,
		"callee_alias":                 binding.Name,
		"source_secret":                sourceRef.Name,
		reusableWorkflowHopMetadataKey: reusableWorkflowHopMetadataValue,
	}
	b.graph.addTypedEdgeWithMetadata(sourceCredentialID, targetState.id, domain.EdgeExplicitlyForwardedTo, domain.EvidenceConfirmedDataFlow, metadata, evidenceItems, domain.ConfidenceConfirmed)
}

// reusableSecretsInheritDiagnosticCode is a stable, machine-readable prefix
// for `secrets: inherit` diagnostics. It is deliberately not shaped like a
// catalog rule ID (no "CRD" prefix, no rules.Catalog entry): this is a
// structural, offline-analysis-limitation notice, never a risk finding.
const reusableSecretsInheritDiagnosticCode = "REUSABLE_SECRETS_INHERIT"

// emitReusableSecretsInheritDiagnostics records one deterministic,
// non-traversable diagnostic per job that declares `secrets: inherit` on a
// reusable workflow call. CredScope is offline and cannot enumerate the
// caller's real repository, organization, or environment secret inventory,
// so `secrets: inherit` never creates a credential node, a binding node, a
// forwarding edge, or confirmed_static_data_flow evidence here — this is
// diagnostic-only, by design (see the architecture audit this phase is
// scoped to): a call-scoped binding sourced from the existing global,
// name-only NodeCredential identity would still let unrelated same-named
// workflow references, same-name Gitleaks findings, and globally merged
// evidence leak into an inherited path, which would overclaim a specific
// secret's availability CredScope cannot actually prove offline.
func (b *builder) emitReusableSecretsInheritDiagnostics(workflows []domain.Workflow) {
	for _, caller := range workflows {
		for _, job := range caller.Jobs {
			if !job.ReusableSecretsInherit {
				continue
			}
			call := b.resolvedCalls[caller.File+"\x00"+job.ID]
			b.warnings[reusableSecretsInheritDiagnostic(caller, job, call)] = struct{}{}
		}
	}
}

func reusableSecretsInheritDiagnostic(caller domain.Workflow, job domain.WorkflowJob, call reusableworkflow.DirectCall) string {
	status := string(call.Status)
	if status == "" {
		status = "unknown"
	}
	location := "unknown location"
	if job.ReusableSecretsInheritEvidence != nil {
		location = diagnosticLocationText(job.ReusableSecretsInheritEvidence.Location)
	}
	const noInventory = "CredScope cannot enumerate the caller's real repository, organization, or environment secret inventory offline, so no credential forwarding relationship was inferred."
	if call.Status == reusableworkflow.StatusResolvedLocal {
		return fmt.Sprintf("%s: job %q in %q declares secrets: inherit calling %q (status=%s). %s (%s)",
			reusableSecretsInheritDiagnosticCode, job.ID, caller.File, call.TargetWorkflow, status, noInventory, location)
	}
	return fmt.Sprintf("%s: job %q in %q declares secrets: inherit (status=%s); target secret availability cannot be determined. %s (%s)",
		reusableSecretsInheritDiagnosticCode, job.ID, caller.File, status, noInventory, location)
}

func diagnosticLocationText(loc domain.Location) string {
	if loc.Path == "" {
		return "unknown location"
	}
	if loc.Line > 0 {
		return fmt.Sprintf("%s:%d", loc.Path, loc.Line)
	}
	return loc.Path
}

func (b *builder) step(callerWorkflowFile, callerJobID, jobID, jobKey string, index int, step domain.WorkflowStep) string {
	label := step.Name
	if label == "" {
		label = step.ID
	}
	if label == "" {
		label = "step " + sanitizer.Identifier(step.Evidence.Field)
	}
	stepKey := nodeKey(jobKey, index, step.ID, label)
	metadata := map[string]string{"step_id": step.ID, "has_shell": boolText(step.Run != nil)}
	stepID := b.graph.addNode(domain.NodeStep, stepKey, label, locationPtr(step.Evidence), metadata, []domain.Evidence{step.Evidence}, domain.ConfidenceConfirmed)
	b.graph.addEdge(stepID, jobID, domain.EdgeExecutedBy, []domain.Evidence{evidence("workflow_step", step.Evidence, "Step executes within this job.", domain.ConfidenceConfirmed)}, domain.ConfidenceConfirmed)
	for _, ref := range step.References {
		if credentialID := b.reference(ref); credentialID != "" {
			evidenceType := "step_credential_reference"
			if step.Run != nil && hasReference(step.Run.References, ref.Name) {
				evidenceType = "shell_credential_reference"
			}
			edgeType := domain.EdgeExplicitlyForwardedTo
			if evidenceType == "shell_credential_reference" {
				edgeType = domain.EdgeReferencedByProcess
			}
			b.graph.addTypedEdge(credentialID, stepID, edgeType, domain.EvidenceConfirmedDataFlow, []domain.Evidence{evidence(evidenceType, ref.Evidence, "Reference is used by this workflow step.", ref.Evidence.Confidence)}, ref.Evidence.Confidence)
		}
	}
	if step.Action != nil {
		action := step.Action
		metadata := actionMetadata(*action, false)
		call, hasCall := b.compositeCallsByStep[compositeStepKey(callerWorkflowFile, callerJobID, index)]
		if hasCall {
			addCompositeCallMetadata(metadata, call)
		}
		actionID := b.graph.addNode(domain.NodeExternalAction, nodeKey(stepKey, action.Reference), action.Reference, locationPtr(action.Evidence), metadata, []domain.Evidence{action.Evidence}, domain.ConfidenceConfirmed)
		b.graph.addEdge(stepID, actionID, domain.EdgeRunsAction, []domain.Evidence{evidence("action_reference", action.Evidence, "Step references this action; third-party does not imply malicious.", domain.ConfidenceConfirmed)}, domain.ConfidenceConfirmed)
		if hasCall {
			b.compositeActionCall(actionID, call)
		}
	}
	return stepID
}

// addCompositeCallMetadata adds additive, machine-readable resolver-outcome
// metadata for a workflow-step action call site. It never overwrites any key
// actionMetadata already set (local, third_party, mutable, owner,
// repository, revision, pinned_sha, artifact_kind, unresolved), and never
// changes the node's identity: metadata is not part of a node's stable ID.
func addCompositeCallMetadata(metadata map[string]string, call domain.CompositeActionCall) {
	metadata["resolution_status"] = string(call.Status)
	metadata["raw_reference"] = call.RawReference
	metadata["caller_workflow"] = call.CallerWorkflow
	metadata["caller_job_id"] = call.CallerJobID
	metadata["caller_step_index"] = strconv.Itoa(call.CallerStepIndex)
	if call.CanonicalDirectory != "" {
		metadata["canonical_directory"] = call.CanonicalDirectory
	}
	if call.MetadataFile != "" {
		metadata["metadata_file"] = call.MetadataFile
	}
}

// compositeActionCall represents, structurally, one resolved local
// composite-action call: it creates (or reuses) the canonical
// NodeCompositeAction for call.CanonicalDirectory and connects the existing
// call-site node to it with a structural, non-traversable edge. For every
// other status it either emits a deterministic diagnostic (rejected path,
// missing/ambiguous/malformed metadata) or does nothing (opaque external,
// opaque docker, unsupported expression, target not composite) — the
// existing call-site node and edge are never altered either way.
func (b *builder) compositeActionCall(actionID string, call domain.CompositeActionCall) {
	switch call.Status {
	case domain.CompositeActionRejectedPath, domain.CompositeActionMetadataMissing, domain.CompositeActionMetadataAmbiguous, domain.CompositeActionMalformedMetadata:
		b.warnings[compositeActionDiagnostic(call)] = struct{}{}
		return
	case domain.CompositeActionResolvedLocalComposite:
	default:
		return
	}
	action, ok := b.compositeActionsByDirectory[call.CanonicalDirectory]
	if !ok {
		return
	}
	label := action.Name
	if label == "" {
		label = action.Directory
	}
	inputNames := make([]string, 0, len(action.Inputs))
	for _, input := range action.Inputs {
		inputNames = append(inputNames, input.Name)
	}
	outputNames := make([]string, 0, len(action.Outputs))
	for _, output := range action.Outputs {
		outputNames = append(outputNames, output.Name)
	}
	metadata := map[string]string{
		"directory":     action.Directory,
		"metadata_file": call.MetadataFile,
		"name":          action.Name,
		"runs_using":    action.Runs.Using,
		"input_names":   strings.Join(inputNames, ","),
		"output_names":  strings.Join(outputNames, ","),
		"step_count":    strconv.Itoa(len(action.Runs.Steps)),
	}
	canonicalID := b.graph.addNode(domain.NodeCompositeAction, action.Directory, label, locationPtr(action.Evidence), metadata, []domain.Evidence{action.Evidence}, domain.ConfidenceConfirmed)
	structuralEvidence := []domain.Evidence{evidence("resolved_local_composite_action", action.Evidence, "Workflow step's local action reference resolves to this composite action; this is not credential data flow or exposure.", domain.ConfidenceConfirmed)}
	b.graph.addTypedEdge(actionID, canonicalID, domain.EdgeRunsAction, domain.EvidenceStructuralCallOnly, structuralEvidence, domain.ConfidenceConfirmed)
}

const compositeActionDiagnosticCode = "COMPOSITE_ACTION_RESOLUTION"

// compositeActionDiagnostic renders one deterministic warning for a
// composite-action call whose resolution needs surfacing to a human
// (rejected path, missing/ambiguous/malformed metadata). Its identity is
// folded entirely into the returned text, which finish() deduplicates and
// sorts exactly like every other builder warning.
func compositeActionDiagnostic(call domain.CompositeActionCall) string {
	message := fmt.Sprintf("%s: workflow %q job %q step %s references %q (status=%s)",
		compositeActionDiagnosticCode, call.CallerWorkflow, call.CallerJobID, compositeActionStepIdentifier(call), call.RawReference, call.Status)
	if call.CanonicalDirectory != "" {
		message += fmt.Sprintf(" directory=%q", call.CanonicalDirectory)
	}
	if call.MetadataFile != "" {
		message += fmt.Sprintf(" metadata_file=%q", call.MetadataFile)
	}
	return message + " (" + diagnosticLocationText(call.Evidence.Location) + ")"
}

func compositeActionStepIdentifier(call domain.CompositeActionCall) string {
	if call.CallerStepID != "" {
		return call.CallerStepID
	}
	return strconv.Itoa(call.CallerStepIndex)
}

func (b *builder) compose(repoID string, project domain.ComposeProject) {
	fileID := b.file(project.File, project.Evidence)
	b.graph.addEdge(fileID, repoID, domain.EdgeDetectedIn, []domain.Evidence{evidence("repository_file", project.Evidence, "Compose file belongs to the selected repository.", domain.ConfidenceConfirmed)}, domain.ConfidenceConfirmed)
	serviceIDs := make(map[string]string, len(project.Services))
	for _, service := range project.Services {
		key := nodeKey(project.File, service.Name)
		metadata := map[string]string{"file": project.File, "privileged": boolText(service.Privileged), "host_network": boolText(service.HostNetwork), "user_specified": boolText(service.UserSpecified), "user": service.User, "production_like": boolText(service.ProductionLike)}
		serviceEvidence := append([]domain.Evidence{service.Evidence}, signalEvidence(service.Signals)...)
		serviceIDs[service.Name] = b.graph.addNode(domain.NodeComposeService, key, service.Name, locationPtr(service.Evidence), metadata, serviceEvidence, domain.ConfidenceConfirmed)
	}
	for _, service := range project.Services {
		b.service(fileID, project, serviceIDs, service)
	}
	for i := range project.Services {
		for j := i + 1; j < len(project.Services); j++ {
			if !shareComposeNetwork(project.Services[i], project.Services[j]) {
				continue
			}
			left, right := serviceIDs[project.Services[i].Name], serviceIDs[project.Services[j].Name]
			ev := []domain.Evidence{evidence("compose_network", project.Evidence, "Services share a Compose network; this is topology only and does not imply credential transmission.", domain.ConfidenceHigh)}
			b.graph.addTypedEdge(left, right, domain.EdgeNetworkReachable, domain.EvidenceNetworkTopology, ev, domain.ConfidenceHigh)
			b.graph.addTypedEdge(right, left, domain.EdgeNetworkReachable, domain.EvidenceNetworkTopology, ev, domain.ConfidenceHigh)
		}
	}
}

func shareComposeNetwork(left, right domain.ComposeService) bool {
	if len(left.Networks) == 0 && len(right.Networks) == 0 {
		return true
	}
	set := make(map[string]bool, len(left.Networks))
	for _, item := range left.Networks {
		set[item.Name] = true
	}
	for _, item := range right.Networks {
		if set[item.Name] {
			return true
		}
	}
	return false
}

func (b *builder) service(fileID string, project domain.ComposeProject, serviceIDs map[string]string, service domain.ComposeService) {
	serviceID := serviceIDs[service.Name]
	serviceKey := nodeKey(project.File, service.Name)
	b.graph.addEdge(serviceID, fileID, domain.EdgeDetectedIn, []domain.Evidence{evidence("compose_service", service.Evidence, "Service is defined in this Compose file.", domain.ConfidenceConfirmed)}, domain.ConfidenceConfirmed)
	for _, ref := range service.References {
		if credentialID := b.reference(ref); credentialID != "" {
			edgeType := domain.EdgeAvailableToService
			if ref.Kind == domain.ReferenceComposeSecret {
				edgeType = domain.EdgeMountedAsSecret
			}
			b.graph.addTypedEdge(credentialID, serviceID, edgeType, domain.EvidenceConfirmedDataFlow, []domain.Evidence{evidence("compose_credential_reference", ref.Evidence, "Reference is available to this Compose service.", domain.ConfidenceConfirmed)}, domain.ConfidenceConfirmed)
		}
	}
	for _, port := range service.Ports {
		label := port.Target
		if port.Published != "" {
			label = "published " + port.Published + " -> " + port.Target
		}
		portID := b.graph.addNode(domain.NodePortExposure, nodeKey(serviceKey, port.Published, port.Target, port.HostIP, port.Protocol), label, locationPtr(port.Evidence), map[string]string{"published": port.Published, "target": port.Target, "host_ip": port.HostIP, "protocol": port.Protocol, "runtime_exposure": "unknown"}, []domain.Evidence{port.Evidence}, domain.ConfidenceMedium)
		b.graph.addTypedEdge(serviceID, portID, domain.EdgeExposesPort, domain.EvidenceExposureContext, []domain.Evidence{evidence("published_host_port", port.Evidence, "Service publishes a host port; external reachability remains unknown.", domain.ConfidenceMedium)}, domain.ConfidenceMedium)
	}
	for _, volume := range service.Volumes {
		metadata := map[string]string{"source": volume.Source, "target": volume.Target, "type": volume.Type, "read_only": boolText(volume.ReadOnly), "host_bind": boolText(volume.HostBind), "writable_host_bind": boolText(volume.WritableHostBind), "docker_socket": boolText(volume.DockerSocket)}
		volumeID := b.graph.addNode(domain.NodeVolumeMount, nodeKey(serviceKey, volume.Source, volume.Target, volume.Type), volume.Source+":"+volume.Target, locationPtr(volume.Evidence), metadata, []domain.Evidence{volume.Evidence}, domain.ConfidenceConfirmed)
		b.graph.addEdge(serviceID, volumeID, domain.EdgeMounts, []domain.Evidence{evidence("volume_mount", volume.Evidence, "Service declares this volume mount.", domain.ConfidenceConfirmed)}, domain.ConfidenceConfirmed)
	}
	for _, item := range service.Secrets {
		secretID := b.graph.addNode(domain.NodeComposeSecret, nodeKey(project.File, item.Source), item.Source, locationPtr(item.Evidence), map[string]string{"source": item.Source}, []domain.Evidence{item.Evidence}, domain.ConfidenceConfirmed)
		b.graph.addTypedEdge(secretID, serviceID, domain.EdgeMountedAsSecret, domain.EvidenceConfirmedDataFlow, []domain.Evidence{evidence("compose_secret", item.Evidence, "Declared Compose secret is mounted into this service.", domain.ConfidenceConfirmed)}, domain.ConfidenceConfirmed)
	}
	for _, item := range service.EnvFiles {
		envFileID := b.graph.addNode(domain.NodeEnvFile, nodeKey(project.File, item.Path), item.Path, locationPtr(item.Evidence), map[string]string{"path": item.Path}, []domain.Evidence{item.Evidence}, domain.ConfidenceConfirmed)
		b.graph.addTypedEdge(serviceID, envFileID, domain.EdgeReadsEnvFile, domain.EvidenceExposureContext, []domain.Evidence{evidence("compose_env_file", item.Evidence, "Service is configured to read this env_file at runtime.", domain.ConfidenceHigh)}, domain.ConfidenceHigh)
	}
	for _, dependency := range service.DependsOn {
		if targetID := serviceIDs[dependency.Name]; targetID != "" {
			b.graph.addTypedEdge(serviceID, targetID, domain.EdgeDependsOn, domain.EvidenceNetworkTopology, []domain.Evidence{evidence("compose_dependency", dependency.Evidence, "Service declares this dependency; it does not imply credential transmission.", domain.ConfidenceConfirmed)}, domain.ConfidenceConfirmed)
		}
	}
}

func (b *builder) finish() BuildResult {
	result := BuildResult{Graph: b.graph.finish(), Credentials: make([]domain.CredentialSubject, 0, len(b.credentials)), LimitExceeded: b.graph.limitExceeded}
	if b.graph.limitExceeded {
		b.warnings[fmt.Sprintf("Graph construction exceeded the safety limit of %d nodes or %d edges.", DefaultMaxGraphNodes, DefaultMaxGraphEdges)] = struct{}{}
	}
	for _, state := range b.credentials {
		fingerprints := make([]string, 0, len(state.fingerprints))
		for fingerprint := range state.fingerprints {
			fingerprints = append(fingerprints, fingerprint)
		}
		sort.Strings(fingerprints)
		kinds := make([]domain.ReferenceKind, 0, len(state.kinds))
		for kind := range state.kinds {
			kinds = append(kinds, kind)
		}
		assessment := classification.Assess(classification.Input{Name: state.label, ReferenceKinds: kinds, ImportedFinding: state.importedFinding, Override: b.options.Classifications[strings.ToUpper(state.label)], TestFixtureCandidate: state.testFixtureCandidate})
		result.Credentials = append(result.Credentials, domain.CredentialSubject{ID: state.id, Label: state.label, Type: state.kind, Fingerprints: fingerprints, Classification: assessment.Classification, ClassificationConfidence: assessment.Confidence, ClassificationReason: assessment.Reason, ClassificationSource: assessment.Source, ExpectedSecret: assessment.ExpectedSecret, RotationApplicable: assessment.RotationApplicable, TestFixtureCandidate: state.testFixtureCandidate})
	}
	sort.Slice(result.Credentials, func(i, j int) bool { return result.Credentials[i].ID < result.Credentials[j].ID })
	for warning := range b.warnings {
		result.Warnings = append(result.Warnings, warning)
	}
	for _, ignored := range b.ignored {
		result.Ignored = append(result.Ignored, ignored)
	}
	sort.Slice(result.Ignored, func(i, j int) bool {
		if result.Ignored[i].Kind != result.Ignored[j].Kind {
			return result.Ignored[i].Kind < result.Ignored[j].Kind
		}
		return result.Ignored[i].Target < result.Ignored[j].Target
	})
	sort.Strings(result.Warnings)
	return result
}

func actionMetadata(action domain.ActionReference, unresolved bool) map[string]string {
	return map[string]string{"owner": action.Owner, "repository": action.Repository, "revision": action.Revision, "third_party": boolText(action.ThirdParty), "pinned_sha": boolText(action.PinnedSHA), "mutable": boolText(action.Mutable), "local": boolText(action.Local), "docker": boolText(action.Docker), "artifact_kind": action.ArtifactKind, "unresolved": boolText(unresolved)}
}

func hasReference(refs []domain.Reference, name string) bool {
	for _, ref := range refs {
		if ref.Name == name && (ref.Kind == domain.ReferenceSecret || ref.Kind == domain.ReferenceComposeVariable || ref.Kind == domain.ReferenceComposeSecret) {
			return true
		}
	}
	return false
}

func productionLike(value string) bool {
	value = strings.ToLower(value)
	return strings.Contains(value, "production") || strings.Contains(value, "prod") || strings.Contains(value, "release")
}

func jobLabel(job domain.WorkflowJob) string {
	if job.Name != "" {
		return job.Name
	}
	return job.ID
}

func signalEvidence(signals []domain.StructuralSignal) []domain.Evidence {
	result := make([]domain.Evidence, 0, len(signals))
	for _, signal := range signals {
		item := signal.Evidence
		item.Type = "signal:" + signal.Kind
		item.Description = signal.Description
		item.Confidence = signal.Confidence
		result = append(result, item)
	}
	return result
}
