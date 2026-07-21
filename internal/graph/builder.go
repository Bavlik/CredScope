package graph

import (
	"fmt"
	"sort"
	"strings"

	"github.com/credscope/credscope/internal/domain"
	"github.com/credscope/credscope/internal/sanitizer"
)

type BuildResult struct {
	Graph         domain.Graph
	Credentials   []domain.CredentialSubject
	Warnings      []string
	LimitExceeded bool
}

type builder struct {
	graph       *mutableGraph
	credentials map[string]*credentialState
	warnings    map[string]struct{}
}

type credentialState struct {
	id           string
	label        string
	kind         string
	fingerprints map[string]struct{}
}

// Build constructs a graph from scanner-neutral parsed repository data. It
// never resolves expressions or executes repository content.
func Build(parsed domain.ParsedRepository) BuildResult {
	b := &builder{graph: newMutable(), credentials: make(map[string]*credentialState), warnings: make(map[string]struct{})}
	b.build(parsed)
	return b.finish()
}

func (b *builder) build(parsed domain.ParsedRepository) {
	repoID := b.graph.addNode(domain.NodeRepository, "selected-repository", "repository", nil, map[string]string{"scope": "selected_root"}, nil, domain.ConfidenceConfirmed)
	for _, finding := range parsed.Findings {
		credentialID := b.credential(finding.Credential.Label, finding.Credential.Type, finding.Credential.Fingerprint)
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
	for _, project := range parsed.Compose {
		b.compose(repoID, project)
	}
}

func (b *builder) credential(label, kind, fingerprint string) string {
	label = sanitizer.Identifier(label)
	if label == "" {
		b.warnings["A parsed credential reference had an empty name and was excluded from analysis."] = struct{}{}
		return ""
	}
	key := strings.ToUpper(label)
	state := b.credentials[key]
	if state == nil {
		state = &credentialState{label: label, kind: kind, fingerprints: make(map[string]struct{})}
		state.id = b.graph.addNode(domain.NodeCredential, key, label, nil, map[string]string{"credential_type": kind}, nil, domain.ConfidenceConfirmed)
		b.credentials[key] = state
	}
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
	return b.credential(ref.Name, string(ref.Kind), "")
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
			b.graph.addEdge(credentialID, wfID, domain.EdgeReferencedBy, []domain.Evidence{evidence("credential_reference", ref.Evidence, "Workflow contains a credential reference.", ref.Evidence.Confidence)}, ref.Evidence.Confidence)
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
				b.graph.addEdge(credentialID, wfID, domain.EdgePropagatesTo, []domain.Evidence{evidence("workflow_environment", ref.Evidence, "Credential is copied into workflow-level environment scope.", ref.Evidence.Confidence)}, ref.Evidence.Confidence)
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
	b.graph.addEdge(jobID, wfID, domain.EdgeReferencedBy, []domain.Evidence{evidence("workflow_job", job.Evidence, "Job belongs to this workflow.", domain.ConfidenceConfirmed)}, domain.ConfidenceConfirmed)
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
			b.graph.addEdge(credentialID, jobID, domain.EdgePassedTo, []domain.Evidence{evidence("job_credential_reference", ref.Evidence, "Job contains a credential reference.", ref.Evidence.Confidence)}, ref.Evidence.Confidence)
		}
	}
	for _, binding := range job.Environment {
		for _, ref := range binding.References {
			if credentialID := b.reference(ref); credentialID != "" {
				b.graph.addEdge(credentialID, jobID, domain.EdgePropagatesTo, []domain.Evidence{evidence("job_environment", ref.Evidence, "Credential is copied into job-level environment scope.", ref.Evidence.Confidence)}, ref.Evidence.Confidence)
			}
		}
	}
	propagatedRefs := append([]domain.Reference{}, inheritedRefs...)
	for _, binding := range job.Environment {
		propagatedRefs = append(propagatedRefs, binding.References...)
	}
	for _, ref := range inheritedRefs {
		if credentialID := b.reference(ref); credentialID != "" {
			b.graph.addEdge(credentialID, jobID, domain.EdgePropagatesTo, []domain.Evidence{evidence("workflow_environment", ref.Evidence, "Workflow-level credential environment is inherited by this job.", ref.Evidence.Confidence)}, ref.Evidence.Confidence)
		}
	}
	if job.ReusableWorkflow != nil {
		action := job.ReusableWorkflow
		nodeID := b.graph.addNode(domain.NodeReusableWorkflow, nodeKey(jobKey, action.Reference), action.Reference, locationPtr(action.Evidence), actionMetadata(*action, !job.ReusableResolved), []domain.Evidence{action.Evidence}, domain.ConfidenceConfirmed)
		b.graph.addEdge(jobID, nodeID, domain.EdgeCallsWorkflow, []domain.Evidence{evidence("reusable_workflow", action.Evidence, "Reusable workflow reference was recorded but not resolved.", domain.ConfidenceUnknown)}, domain.ConfidenceUnknown)
	}
	for outputIndex, output := range job.Outputs {
		for _, ref := range output.References {
			if credentialID := b.reference(ref); credentialID != "" {
				b.graph.addEdge(credentialID, jobID, domain.EdgePropagatesTo, []domain.Evidence{evidence("job_output", ref.Evidence, "Credential is referenced by a job output.", domain.ConfidenceConfirmed)}, domain.ConfidenceConfirmed)
			}
		}
		_ = outputIndex
	}
	for index, step := range job.Steps {
		stepID := b.step(jobID, jobKey, index, step)
		for _, ref := range propagatedRefs {
			if credentialID := b.reference(ref); credentialID != "" {
				b.graph.addEdge(credentialID, stepID, domain.EdgePropagatesTo, []domain.Evidence{evidence("inherited_environment", ref.Evidence, "Credential environment is inherited by this workflow step.", ref.Evidence.Confidence)}, ref.Evidence.Confidence)
			}
		}
	}
}

func (b *builder) step(jobID, jobKey string, index int, step domain.WorkflowStep) string {
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
			b.graph.addEdge(credentialID, stepID, domain.EdgePassedTo, []domain.Evidence{evidence(evidenceType, ref.Evidence, "Credential is passed to a workflow step.", ref.Evidence.Confidence)}, ref.Evidence.Confidence)
		}
	}
	if step.Action != nil {
		action := step.Action
		actionID := b.graph.addNode(domain.NodeExternalAction, nodeKey(stepKey, action.Reference), action.Reference, locationPtr(action.Evidence), actionMetadata(*action, false), []domain.Evidence{action.Evidence}, domain.ConfidenceConfirmed)
		b.graph.addEdge(stepID, actionID, domain.EdgeRunsAction, []domain.Evidence{evidence("action_reference", action.Evidence, "Step references this action; third-party does not imply malicious.", domain.ConfidenceConfirmed)}, domain.ConfidenceConfirmed)
	}
	return stepID
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
	for _, shared := range project.SharedCredentials {
		for i := range shared.Services {
			for j := i + 1; j < len(shared.Services); j++ {
				left, right := serviceIDs[shared.Services[i]], serviceIDs[shared.Services[j]]
				if left != "" && right != "" {
					b.graph.addEdge(left, right, domain.EdgeSharedWith, shared.Evidence, shared.Confidence)
					b.graph.addEdge(right, left, domain.EdgeSharedWith, shared.Evidence, shared.Confidence)
				}
			}
		}
	}
}

func (b *builder) service(fileID string, project domain.ComposeProject, serviceIDs map[string]string, service domain.ComposeService) {
	serviceID := serviceIDs[service.Name]
	serviceKey := nodeKey(project.File, service.Name)
	b.graph.addEdge(serviceID, fileID, domain.EdgeDetectedIn, []domain.Evidence{evidence("compose_service", service.Evidence, "Service is defined in this Compose file.", domain.ConfidenceConfirmed)}, domain.ConfidenceConfirmed)
	for _, ref := range service.References {
		if credentialID := b.reference(ref); credentialID != "" {
			b.graph.addEdge(credentialID, serviceID, domain.EdgePassedTo, []domain.Evidence{evidence("compose_credential_reference", ref.Evidence, "Credential reference is passed to this Compose service.", domain.ConfidenceConfirmed)}, domain.ConfidenceConfirmed)
		}
	}
	for _, port := range service.Ports {
		label := port.Target
		if port.Published != "" {
			label = "published " + port.Published + " -> " + port.Target
		}
		portID := b.graph.addNode(domain.NodePortExposure, nodeKey(serviceKey, port.Published, port.Target, port.HostIP, port.Protocol), label, locationPtr(port.Evidence), map[string]string{"published": port.Published, "target": port.Target, "host_ip": port.HostIP, "protocol": port.Protocol, "runtime_exposure": "unknown"}, []domain.Evidence{port.Evidence}, domain.ConfidenceMedium)
		b.graph.addEdge(serviceID, portID, domain.EdgePublishesPort, []domain.Evidence{evidence("published_host_port", port.Evidence, "Service publishes a host port and may be externally reachable depending on runtime configuration.", domain.ConfidenceMedium)}, domain.ConfidenceMedium)
	}
	for _, volume := range service.Volumes {
		metadata := map[string]string{"source": volume.Source, "target": volume.Target, "type": volume.Type, "read_only": boolText(volume.ReadOnly), "host_bind": boolText(volume.HostBind), "writable_host_bind": boolText(volume.WritableHostBind), "docker_socket": boolText(volume.DockerSocket)}
		volumeID := b.graph.addNode(domain.NodeVolumeMount, nodeKey(serviceKey, volume.Source, volume.Target, volume.Type), volume.Source+":"+volume.Target, locationPtr(volume.Evidence), metadata, []domain.Evidence{volume.Evidence}, domain.ConfidenceConfirmed)
		b.graph.addEdge(serviceID, volumeID, domain.EdgeMounts, []domain.Evidence{evidence("volume_mount", volume.Evidence, "Service declares this volume mount.", domain.ConfidenceConfirmed)}, domain.ConfidenceConfirmed)
	}
	for _, item := range service.Secrets {
		secretID := b.graph.addNode(domain.NodeComposeSecret, nodeKey(project.File, item.Source), item.Source, locationPtr(item.Evidence), map[string]string{"source": item.Source}, []domain.Evidence{item.Evidence}, domain.ConfidenceConfirmed)
		b.graph.addEdge(serviceID, secretID, domain.EdgeUsesSecret, []domain.Evidence{evidence("compose_secret", item.Evidence, "Service uses a declared Compose secret reference.", domain.ConfidenceConfirmed)}, domain.ConfidenceConfirmed)
	}
	for _, item := range service.EnvFiles {
		envFileID := b.graph.addNode(domain.NodeEnvFile, nodeKey(project.File, item.Path), item.Path, locationPtr(item.Evidence), map[string]string{"path": item.Path}, []domain.Evidence{item.Evidence}, domain.ConfidenceConfirmed)
		b.graph.addEdge(serviceID, envFileID, domain.EdgeLoadsEnvFile, []domain.Evidence{evidence("compose_env_file", item.Evidence, "Service loads variables from this env_file at runtime.", domain.ConfidenceHigh)}, domain.ConfidenceHigh)
	}
	for _, dependency := range service.DependsOn {
		if targetID := serviceIDs[dependency.Name]; targetID != "" {
			b.graph.addEdge(serviceID, targetID, domain.EdgeDependsOn, []domain.Evidence{evidence("compose_dependency", dependency.Evidence, "Service declares this dependency.", domain.ConfidenceConfirmed)}, domain.ConfidenceConfirmed)
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
		result.Credentials = append(result.Credentials, domain.CredentialSubject{ID: state.id, Label: state.label, Type: state.kind, Fingerprints: fingerprints})
	}
	sort.Slice(result.Credentials, func(i, j int) bool { return result.Credentials[i].ID < result.Credentials[j].ID })
	for warning := range b.warnings {
		result.Warnings = append(result.Warnings, warning)
	}
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
