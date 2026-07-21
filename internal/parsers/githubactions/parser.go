// Package githubactions parses workflow structure without executing any content.
package githubactions

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/Bavlik/CredScope/internal/domain"
	"github.com/Bavlik/CredScope/internal/parsers/yamlsafe"
	"github.com/Bavlik/CredScope/internal/sanitizer"
	"go.yaml.in/yaml/v3"
)

const parserSource = "github-actions"

type ParseError struct {
	Path  string
	Line  int
	Field string
	Msg   string
}

func (e *ParseError) Error() string {
	location := e.Path
	if e.Line > 0 {
		location += fmt.Sprintf(":%d", e.Line)
	}
	if e.Field != "" {
		location += " field " + e.Field
	}
	return "github-actions parse error: " + location + ": " + e.Msg
}

type Parser struct{}

func New() *Parser             { return &Parser{} }
func (p *Parser) Name() string { return parserSource }

func (p *Parser) Parse(ctx context.Context, root, file string) (domain.Workflow, error) {
	if err := ctx.Err(); err != nil {
		return domain.Workflow{}, err
	}
	document, rel, err := yamlsafe.Parse(root, file)
	if err != nil {
		return domain.Workflow{}, &ParseError{Path: safeText(file), Msg: err.Error()}
	}
	rootNode, err := yamlsafe.DocumentRoot(document)
	if err != nil || rootNode.Kind != yaml.MappingNode {
		return domain.Workflow{}, &ParseError{Path: rel, Msg: "workflow root must be a mapping"}
	}
	workflow := domain.Workflow{
		File:     rel,
		Evidence: evidence(rel, rootNode, "", "GitHub Actions workflow", domain.ConfidenceConfirmed),
	}
	if name, ok, mapErr := yamlsafe.MappingValue(rootNode, "name"); mapErr != nil {
		return domain.Workflow{}, structuralError(rel, rootNode, "name", mapErr)
	} else if ok {
		workflow.Name = safeText(name.Value)
	}
	if workflow.Name == "" {
		workflow.Name = rel
	}
	onNode, hasOn, mapErr := yamlsafe.MappingValue(rootNode, "on")
	if mapErr != nil {
		return domain.Workflow{}, structuralError(rel, rootNode, "on", mapErr)
	}
	if hasOn {
		workflow.Triggers, err = parseTriggers(rel, onNode)
		if err != nil {
			return domain.Workflow{}, err
		}
	}
	permissionsNode, hasPermissions, mapErr := yamlsafe.MappingValue(rootNode, "permissions")
	if mapErr != nil {
		return domain.Workflow{}, structuralError(rel, rootNode, "permissions", mapErr)
	}
	workflow.MissingExplicitPermissions = !hasPermissions
	if hasPermissions {
		workflow.Permissions, err = parsePermissions(rel, permissionsNode, "workflow.permissions")
		if err != nil {
			return domain.Workflow{}, err
		}
	} else {
		workflow.Signals = append(workflow.Signals, signal(rel, rootNode, "permissions", "missing_explicit_permissions", "Workflow does not declare explicit repository permissions; effective defaults depend on repository settings.", domain.ConfidenceHigh))
	}
	envNode, hasEnv, mapErr := yamlsafe.MappingValue(rootNode, "env")
	if mapErr != nil {
		return domain.Workflow{}, structuralError(rel, rootNode, "env", mapErr)
	}
	if hasEnv {
		workflow.Environment, err = parseEnvironment(rel, envNode, "workflow")
		if err != nil {
			return domain.Workflow{}, err
		}
		workflow.Signals = append(workflow.Signals, environmentSignals(workflow.Environment, "workflow-level")...)
	}
	jobsNode, hasJobs, mapErr := yamlsafe.MappingValue(rootNode, "jobs")
	if mapErr != nil {
		return domain.Workflow{}, structuralError(rel, rootNode, "jobs", mapErr)
	}
	if !hasJobs {
		return domain.Workflow{}, &ParseError{Path: rel, Line: rootNode.Line, Field: "jobs", Msg: "required jobs mapping is missing"}
	}
	workflow.Jobs, err = parseJobs(ctx, rel, jobsNode)
	if err != nil {
		return domain.Workflow{}, err
	}
	workflow.References = collectWorkflowReferences(workflow)
	workflow.Signals = append(workflow.Signals, permissionSignals(workflow.Permissions)...)
	if hasTrigger(workflow.Triggers, "pull_request_target") {
		workflow.Signals = append(workflow.Signals, signal(rel, onNode, "on.pull_request_target", "pull_request_target", "Workflow uses pull_request_target, which runs in the base repository context.", domain.ConfidenceConfirmed))
	}
	if isPullRequestWorkflow(workflow.Triggers) {
		for _, ref := range workflow.References {
			if ref.Kind == domain.ReferenceSecret {
				workflow.Signals = append(workflow.Signals, domain.StructuralSignal{
					Kind: "secret_in_pull_request_workflow", Description: "A secret reference is present in a pull-request-related workflow.",
					Confidence: domain.ConfidenceHigh, Evidence: ref.Evidence,
				})
			}
		}
	}
	workflow.Signals = uniqueSignals(workflow.Signals)
	return workflow, nil
}

func parseTriggers(file string, node *yaml.Node) ([]domain.WorkflowTrigger, error) {
	var result []domain.WorkflowTrigger
	switch node.Kind {
	case yaml.ScalarNode:
		result = append(result, domain.WorkflowTrigger{Name: safeText(node.Value), Evidence: evidence(file, node, "on", "Workflow trigger", domain.ConfidenceConfirmed)})
	case yaml.SequenceNode:
		for _, item := range node.Content {
			if item.Kind != yaml.ScalarNode {
				return nil, &ParseError{Path: file, Line: item.Line, Field: "on", Msg: "trigger list entries must be scalars"}
			}
			result = append(result, domain.WorkflowTrigger{Name: safeText(item.Value), Evidence: evidence(file, item, "on", "Workflow trigger", domain.ConfidenceConfirmed)})
		}
	case yaml.MappingNode:
		entries, err := yamlsafe.MappingEntries(node)
		if err != nil {
			return nil, structuralError(file, node, "on", err)
		}
		for _, entry := range entries {
			result = append(result, domain.WorkflowTrigger{Name: safeText(entry[0].Value), Evidence: evidence(file, entry[0], "on."+safeText(entry[0].Value), "Workflow trigger", domain.ConfidenceConfirmed)})
		}
	default:
		return nil, &ParseError{Path: file, Line: node.Line, Field: "on", Msg: "trigger must be a scalar, list, or mapping"}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result, nil
}

func parsePermissions(file string, node *yaml.Node, field string) ([]domain.Permission, error) {
	var result []domain.Permission
	if node.Kind == yaml.ScalarNode {
		level := safeText(node.Value)
		if level == "" {
			return result, nil
		}
		result = append(result, domain.Permission{Scope: "all", Level: level, Evidence: evidence(file, node, field, "Repository permission", domain.ConfidenceConfirmed)})
		return result, nil
	}
	if node.Kind != yaml.MappingNode {
		return nil, &ParseError{Path: file, Line: node.Line, Field: field, Msg: "permissions must be a scalar or mapping"}
	}
	entries, err := yamlsafe.MappingEntries(node)
	if err != nil {
		return nil, structuralError(file, node, field, err)
	}
	for _, entry := range entries {
		if entry[1].Kind != yaml.ScalarNode {
			return nil, &ParseError{Path: file, Line: entry[1].Line, Field: field, Msg: "permission levels must be scalars"}
		}
		result = append(result, domain.Permission{
			Scope: safeText(entry[0].Value), Level: safeText(entry[1].Value),
			Evidence: evidence(file, entry[1], field+"."+safeText(entry[0].Value), "Repository permission", domain.ConfidenceConfirmed),
		})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Scope < result[j].Scope })
	return result, nil
}

func parseEnvironment(file string, node *yaml.Node, scope string) ([]domain.EnvironmentBinding, error) {
	if node.Kind != yaml.MappingNode {
		return nil, &ParseError{Path: file, Line: node.Line, Field: scope + ".env", Msg: "environment must be a mapping"}
	}
	entries, err := yamlsafe.MappingEntries(node)
	if err != nil {
		return nil, structuralError(file, node, scope+".env", err)
	}
	result := make([]domain.EnvironmentBinding, 0, len(entries))
	for _, entry := range entries {
		name := sanitizer.Identifier(entry[0].Value)
		value := entry[1].Value
		refs := extractReferences(file, entry[1], scope+".env."+name, value)
		withoutExpressions := expressionPattern.ReplaceAllString(value, "")
		binding := domain.EnvironmentBinding{
			Name: name, Scope: scope, References: refs,
			HasLiteral: strings.TrimSpace(withoutExpressions) != "",
			Evidence:   evidence(file, entry[1], scope+".env."+name, "Environment binding", domain.ConfidenceConfirmed),
		}
		if binding.HasLiteral {
			binding.LiteralFingerprint = sanitizer.Fingerprint(value)
		}
		result = append(result, binding)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result, nil
}

func parseJobs(ctx context.Context, file string, node *yaml.Node) ([]domain.WorkflowJob, error) {
	if node.Kind != yaml.MappingNode {
		return nil, &ParseError{Path: file, Line: node.Line, Field: "jobs", Msg: "jobs must be a mapping"}
	}
	entries, err := yamlsafe.MappingEntries(node)
	if err != nil {
		return nil, structuralError(file, node, "jobs", err)
	}
	jobs := make([]domain.WorkflowJob, 0, len(entries))
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		job, err := parseJob(file, sanitizer.Identifier(entry[0].Value), entry[1])
		if err != nil {
			return nil, err
		}
		jobs = append(jobs, job)
	}
	sort.Slice(jobs, func(i, j int) bool { return jobs[i].ID < jobs[j].ID })
	return jobs, nil
}

func parseJob(file, id string, node *yaml.Node) (domain.WorkflowJob, error) {
	if node.Kind != yaml.MappingNode {
		return domain.WorkflowJob{}, &ParseError{Path: file, Line: node.Line, Field: "jobs." + id, Msg: "job must be a mapping"}
	}
	job := domain.WorkflowJob{ID: id, Evidence: evidence(file, node, "jobs."+id, "Workflow job", domain.ConfidenceConfirmed)}
	if name, ok, err := yamlsafe.MappingValue(node, "name"); err != nil {
		return job, structuralError(file, node, "jobs."+id+".name", err)
	} else if ok {
		job.Name = safeText(name.Value)
	}
	if needs, ok, err := yamlsafe.MappingValue(node, "needs"); err != nil {
		return job, structuralError(file, node, "jobs."+id+".needs", err)
	} else if ok {
		job.Needs, err = scalarList(needs)
		if err != nil {
			return job, &ParseError{Path: file, Line: needs.Line, Field: "jobs." + id + ".needs", Msg: err.Error()}
		}
	}
	if permissions, ok, err := yamlsafe.MappingValue(node, "permissions"); err != nil {
		return job, structuralError(file, node, "jobs."+id+".permissions", err)
	} else if ok {
		job.Permissions, err = parsePermissions(file, permissions, "jobs."+id+".permissions")
		if err != nil {
			return job, err
		}
		job.Signals = append(job.Signals, permissionSignals(job.Permissions)...)
	}
	if env, ok, err := yamlsafe.MappingValue(node, "env"); err != nil {
		return job, structuralError(file, node, "jobs."+id+".env", err)
	} else if ok {
		job.Environment, err = parseEnvironment(file, env, "job."+id)
		if err != nil {
			return job, err
		}
		job.Signals = append(job.Signals, environmentSignals(job.Environment, "job-level")...)
	}
	if environment, ok, err := yamlsafe.MappingValue(node, "environment"); err != nil {
		return job, structuralError(file, node, "jobs."+id+".environment", err)
	} else if ok {
		job.EnvironmentName, err = parseEnvironmentName(environment)
		if err != nil {
			return job, &ParseError{Path: file, Line: environment.Line, Field: "jobs." + id + ".environment", Msg: err.Error()}
		}
		environmentEvidence := evidence(file, environment, "jobs."+id+".environment", "GitHub deployment environment", domain.ConfidenceConfirmed)
		job.EnvironmentEvidence = &environmentEvidence
	}
	if uses, ok, err := yamlsafe.MappingValue(node, "uses"); err != nil {
		return job, structuralError(file, node, "jobs."+id+".uses", err)
	} else if ok {
		action := classifyAction(file, uses, "jobs."+id+".uses")
		job.ReusableWorkflow = &action
		job.ReusableResolved = false
	}
	if steps, ok, err := yamlsafe.MappingValue(node, "steps"); err != nil {
		return job, structuralError(file, node, "jobs."+id+".steps", err)
	} else if ok {
		job.Steps, err = parseSteps(file, id, steps)
		if err != nil {
			return job, err
		}
	}
	if outputs, ok, err := yamlsafe.MappingValue(node, "outputs"); err != nil {
		return job, structuralError(file, node, "jobs."+id+".outputs", err)
	} else if ok {
		job.Outputs, err = parseOutputs(file, id, outputs)
		if err != nil {
			return job, err
		}
		for _, output := range job.Outputs {
			for _, ref := range output.References {
				if ref.Kind == domain.ReferenceSecret {
					job.Signals = append(job.Signals, domain.StructuralSignal{Kind: "secret_propagated_through_output", Description: "A job output directly references a secret.", Confidence: domain.ConfidenceConfirmed, Evidence: ref.Evidence})
				}
			}
		}
	}
	job.References = extractReferencesFromNode(file, node, "jobs."+id)
	if job.ReusableWorkflow != nil && job.ReusableWorkflow.ThirdParty && job.ReusableWorkflow.Mutable {
		job.Signals = append(job.Signals, domain.StructuralSignal{
			Kind: "mutable_third_party_reusable_workflow", Description: "Third-party reusable workflow is referenced by a mutable revision and was not resolved; this does not imply it is malicious.",
			Confidence: domain.ConfidenceConfirmed, Evidence: job.ReusableWorkflow.Evidence,
		})
	}
	for _, step := range job.Steps {
		job.Signals = append(job.Signals, stepSignals(step)...)
	}
	job.Signals = uniqueSignals(job.Signals)
	return job, nil
}

func parseSteps(file, jobID string, node *yaml.Node) ([]domain.WorkflowStep, error) {
	if node.Kind != yaml.SequenceNode {
		return nil, &ParseError{Path: file, Line: node.Line, Field: "jobs." + jobID + ".steps", Msg: "steps must be a list"}
	}
	steps := make([]domain.WorkflowStep, 0, len(node.Content))
	for index, item := range node.Content {
		if item.Kind != yaml.MappingNode {
			return nil, &ParseError{Path: file, Line: item.Line, Field: fmt.Sprintf("jobs.%s.steps[%d]", jobID, index), Msg: "step must be a mapping"}
		}
		field := fmt.Sprintf("jobs.%s.steps[%d]", jobID, index)
		step := domain.WorkflowStep{Evidence: evidence(file, item, field, "Workflow step", domain.ConfidenceConfirmed)}
		if id, ok, err := yamlsafe.MappingValue(item, "id"); err != nil {
			return nil, structuralError(file, item, field+".id", err)
		} else if ok {
			step.ID = sanitizer.Identifier(id.Value)
		}
		if name, ok, err := yamlsafe.MappingValue(item, "name"); err != nil {
			return nil, structuralError(file, item, field+".name", err)
		} else if ok {
			step.Name = safeText(name.Value)
		}
		if uses, ok, err := yamlsafe.MappingValue(item, "uses"); err != nil {
			return nil, structuralError(file, item, field+".uses", err)
		} else if ok {
			action := classifyAction(file, uses, field+".uses")
			step.Action = &action
		}
		if run, ok, err := yamlsafe.MappingValue(item, "run"); err != nil {
			return nil, structuralError(file, item, field+".run", err)
		} else if ok {
			command := parseRun(file, run, field+".run")
			step.Run = &command
		}
		if env, ok, err := yamlsafe.MappingValue(item, "env"); err != nil {
			return nil, structuralError(file, item, field+".env", err)
		} else if ok {
			step.Environment, err = parseEnvironment(file, env, "step."+jobID)
			if err != nil {
				return nil, err
			}
		}
		step.References = extractReferencesFromNode(file, item, field)
		steps = append(steps, step)
	}
	return steps, nil
}

func parseRun(file string, node *yaml.Node, field string) domain.ShellCommand {
	text := node.Value
	refs := extractReferences(file, node, field, text)
	canonical := make([]string, 0, len(refs))
	for _, ref := range refs {
		canonical = append(canonical, ref.Expression)
	}
	redacted := "<redacted>"
	if len(canonical) > 0 {
		redacted += " " + strings.Join(canonical, " ")
	}
	sum := sha256.Sum256([]byte("credscope:shell:v1\x00" + text))
	return domain.ShellCommand{
		RedactedText: redacted, Fingerprint: "sha256:" + hex.EncodeToString(sum[:]),
		LineCount: strings.Count(text, "\n") + 1, References: refs,
		Evidence: evidence(file, node, field, "Inert shell command (body redacted)", domain.ConfidenceConfirmed),
	}
}

func parseOutputs(file, jobID string, node *yaml.Node) ([]domain.WorkflowOutput, error) {
	if node.Kind != yaml.MappingNode {
		return nil, &ParseError{Path: file, Line: node.Line, Field: "jobs." + jobID + ".outputs", Msg: "outputs must be a mapping"}
	}
	entries, err := yamlsafe.MappingEntries(node)
	if err != nil {
		return nil, structuralError(file, node, "jobs."+jobID+".outputs", err)
	}
	outputs := make([]domain.WorkflowOutput, 0, len(entries))
	for _, entry := range entries {
		name := sanitizer.Identifier(entry[0].Value)
		field := "jobs." + jobID + ".outputs." + name
		if entry[1].Kind != yaml.ScalarNode {
			return nil, &ParseError{Path: file, Line: entry[1].Line, Field: field, Msg: "job output value must be a scalar"}
		}
		outputs = append(outputs, domain.WorkflowOutput{Name: name, References: extractReferences(file, entry[1], field, entry[1].Value), Evidence: evidence(file, entry[1], field, "Job output", domain.ConfidenceConfirmed)})
	}
	sort.Slice(outputs, func(i, j int) bool { return outputs[i].Name < outputs[j].Name })
	return outputs, nil
}

func classifyAction(file string, node *yaml.Node, field string) domain.ActionReference {
	reference := safeText(node.Value)
	action := domain.ActionReference{Reference: reference, Evidence: evidence(file, node, field, "Action or reusable workflow reference", domain.ConfidenceConfirmed)}
	if strings.HasPrefix(reference, "./") {
		action.Local = true
		return action
	}
	if strings.HasPrefix(reference, "docker://") {
		action.Docker = true
		return action
	}
	base, revision, found := strings.Cut(reference, "@")
	if found {
		action.Revision = revision
	}
	parts := strings.Split(base, "/")
	if len(parts) >= 2 {
		action.Owner = parts[0]
		action.Repository = parts[1]
		action.ThirdParty = action.Owner != "actions" && action.Owner != "github"
	}
	action.PinnedSHA = fullSHA.MatchString(action.Revision)
	action.Mutable = !action.PinnedSHA
	lower := strings.ToLower(base)
	if strings.HasPrefix(lower, "actions/upload-artifact") {
		action.ArtifactKind = "upload"
	} else if strings.HasPrefix(lower, "actions/download-artifact") {
		action.ArtifactKind = "download"
	}
	return action
}

func stepSignals(step domain.WorkflowStep) []domain.StructuralSignal {
	var signals []domain.StructuralSignal
	if step.Action != nil && step.Action.ThirdParty && step.Action.Mutable {
		signals = append(signals, domain.StructuralSignal{Kind: "mutable_third_party_action", Description: "Third-party action is referenced by a mutable revision; this does not imply the action is malicious.", Confidence: domain.ConfidenceConfirmed, Evidence: step.Action.Evidence})
	}
	if step.Run != nil {
		for _, ref := range step.Run.References {
			if ref.Kind == domain.ReferenceSecret {
				signals = append(signals, domain.StructuralSignal{Kind: "secret_passed_to_shell", Description: "A secret reference is interpolated into an inert shell command.", Confidence: domain.ConfidenceConfirmed, Evidence: ref.Evidence})
			}
			if ref.Kind == domain.ReferenceGitHubContext && dangerousContext(ref.Name) {
				signals = append(signals, domain.StructuralSignal{Kind: "github_context_in_shell", Description: "Potentially attacker-influenced GitHub context is interpolated into shell text.", Confidence: domain.ConfidenceHigh, Evidence: ref.Evidence})
			}
		}
	}
	if step.Action != nil && step.Action.ThirdParty {
		for _, ref := range step.References {
			if ref.Kind == domain.ReferenceSecret {
				signals = append(signals, domain.StructuralSignal{Kind: "secret_passed_to_third_party_action", Description: "A secret reference is passed to a third-party action; this does not imply the action is malicious.", Confidence: domain.ConfidenceConfirmed, Evidence: ref.Evidence})
			}
		}
	}
	return signals
}

func permissionSignals(permissions []domain.Permission) []domain.StructuralSignal {
	var result []domain.StructuralSignal
	for _, permission := range permissions {
		if permission.Level == "write" || permission.Level == "write-all" {
			result = append(result, domain.StructuralSignal{Kind: "write_permission", Description: permission.Scope + " permission is write-capable.", Confidence: domain.ConfidenceConfirmed, Evidence: permission.Evidence})
		}
	}
	return result
}

func environmentSignals(bindings []domain.EnvironmentBinding, scope string) []domain.StructuralSignal {
	var result []domain.StructuralSignal
	for _, binding := range bindings {
		for _, ref := range binding.References {
			if ref.Kind == domain.ReferenceSecret {
				result = append(result, domain.StructuralSignal{Kind: "secret_copied_to_environment", Description: "A secret reference is copied into " + scope + " environment scope.", Confidence: domain.ConfidenceConfirmed, Evidence: ref.Evidence})
			}
		}
	}
	return result
}

var (
	expressionPattern = regexp.MustCompile(`\$\{\{\s*([A-Za-z_][A-Za-z0-9_-]*)\.([^}]+?)\s*\}\}`)
	fullSHA           = regexp.MustCompile(`^[a-fA-F0-9]{40}([a-fA-F0-9]{24})?$`)
)

func extractReferences(file string, node *yaml.Node, field, text string) []domain.Reference {
	matches := expressionPattern.FindAllStringSubmatch(text, -1)
	refs := make([]domain.Reference, 0, len(matches))
	for _, match := range matches {
		contextName := strings.ToLower(match[1])
		member := strings.TrimSpace(match[2])
		member = firstReferenceMember(member)
		kind := domain.ReferenceGitHubContext
		name := sanitizer.Identifier(contextName + "." + member)
		if contextName == "secrets" {
			kind = domain.ReferenceSecret
			name = sanitizer.Identifier(member)
		} else if contextName == "env" {
			kind = domain.ReferenceEnvironment
			name = sanitizer.Identifier(member)
		}
		if name == "" {
			continue
		}
		expression := "${{ " + contextName + "." + sanitizer.Identifier(member) + " }}"
		refs = append(refs, domain.Reference{Kind: kind, Name: name, Expression: expression, Evidence: evidence(file, node, field, "Expression reference", domain.ConfidenceConfirmed)})
	}
	return uniqueReferences(refs)
}

func firstReferenceMember(value string) string {
	for index, r := range value {
		if !(r == '_' || r == '-' || r == '.' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			return value[:index]
		}
	}
	return value
}

func extractReferencesFromNode(file string, node *yaml.Node, field string) []domain.Reference {
	var refs []domain.Reference
	var walk func(*yaml.Node)
	walk = func(current *yaml.Node) {
		if current == nil {
			return
		}
		if current.Kind == yaml.ScalarNode {
			refs = append(refs, extractReferences(file, current, field, current.Value)...)
		}
		for _, child := range current.Content {
			walk(child)
		}
	}
	walk(node)
	return uniqueReferences(refs)
}

func collectWorkflowReferences(workflow domain.Workflow) []domain.Reference {
	var refs []domain.Reference
	for _, binding := range workflow.Environment {
		refs = append(refs, binding.References...)
	}
	for _, job := range workflow.Jobs {
		refs = append(refs, job.References...)
	}
	return uniqueReferences(refs)
}

func uniqueReferences(refs []domain.Reference) []domain.Reference {
	byKey := make(map[string]domain.Reference, len(refs))
	for _, ref := range refs {
		key := string(ref.Kind) + "\x00" + ref.Name + "\x00" + ref.Evidence.Location.Path + "\x00" + fmt.Sprintf("%d", ref.Evidence.Location.Line) + "\x00" + ref.Evidence.Field
		byKey[key] = ref
	}
	result := make([]domain.Reference, 0, len(byKey))
	for _, ref := range byKey {
		result = append(result, ref)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Kind != result[j].Kind {
			return result[i].Kind < result[j].Kind
		}
		if result[i].Name != result[j].Name {
			return result[i].Name < result[j].Name
		}
		if result[i].Evidence.Location.Line != result[j].Evidence.Location.Line {
			return result[i].Evidence.Location.Line < result[j].Evidence.Location.Line
		}
		return result[i].Evidence.Field < result[j].Evidence.Field
	})
	return result
}

func uniqueSignals(signals []domain.StructuralSignal) []domain.StructuralSignal {
	byKey := make(map[string]domain.StructuralSignal, len(signals))
	for _, item := range signals {
		key := item.Kind + "\x00" + item.Evidence.Location.Path + "\x00" + fmt.Sprintf("%d", item.Evidence.Location.Line) + "\x00" + item.Evidence.Field
		byKey[key] = item
	}
	result := make([]domain.StructuralSignal, 0, len(byKey))
	for _, item := range byKey {
		result = append(result, item)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Kind != result[j].Kind {
			return result[i].Kind < result[j].Kind
		}
		if result[i].Evidence.Location.Line != result[j].Evidence.Location.Line {
			return result[i].Evidence.Location.Line < result[j].Evidence.Location.Line
		}
		return result[i].Evidence.Field < result[j].Evidence.Field
	})
	return result
}

func parseEnvironmentName(node *yaml.Node) (string, error) {
	if node.Kind == yaml.ScalarNode {
		return safeText(node.Value), nil
	}
	if node.Kind == yaml.MappingNode {
		name, ok, err := yamlsafe.MappingValue(node, "name")
		if err != nil {
			return "", err
		}
		if !ok {
			return "", errors.New("environment mapping requires name")
		}
		return safeText(name.Value), nil
	}
	return "", errors.New("environment must be a scalar or mapping")
}

func scalarList(node *yaml.Node) ([]string, error) {
	var result []string
	switch node.Kind {
	case yaml.ScalarNode:
		result = append(result, sanitizer.Identifier(node.Value))
	case yaml.SequenceNode:
		for _, child := range node.Content {
			if child.Kind != yaml.ScalarNode {
				return nil, errors.New("entries must be scalars")
			}
			result = append(result, sanitizer.Identifier(child.Value))
		}
	default:
		return nil, errors.New("value must be a scalar or list")
	}
	sort.Strings(result)
	return result, nil
}

func dangerousContext(name string) bool {
	return strings.HasPrefix(name, "github.event.") || name == "github.head_ref" || strings.HasPrefix(name, "inputs.")
}

func hasTrigger(triggers []domain.WorkflowTrigger, name string) bool {
	for _, trigger := range triggers {
		if trigger.Name == name {
			return true
		}
	}
	return false
}

func isPullRequestWorkflow(triggers []domain.WorkflowTrigger) bool {
	return hasTrigger(triggers, "pull_request") || hasTrigger(triggers, "pull_request_target")
}

func evidence(file string, node *yaml.Node, field, description string, confidence domain.Confidence) domain.Evidence {
	location := domain.Location{Path: file}
	if node != nil {
		location.Line, location.Column = node.Line, node.Column
	}
	return domain.Evidence{Description: description, Location: location, Field: field, Source: parserSource, Confidence: confidence}
}

func signal(file string, node *yaml.Node, field, kind, description string, confidence domain.Confidence) domain.StructuralSignal {
	return domain.StructuralSignal{Kind: kind, Description: description, Confidence: confidence, Evidence: evidence(file, node, field, description, confidence)}
}

func structuralError(file string, node *yaml.Node, field string, err error) error {
	line := 0
	if node != nil {
		line = node.Line
	}
	return &ParseError{Path: file, Line: line, Field: field, Msg: err.Error()}
}

func safeText(value string) string { return sanitizer.TerminalText(value) }
