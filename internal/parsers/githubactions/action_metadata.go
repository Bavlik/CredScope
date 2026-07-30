package githubactions

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/Bavlik/CredScope/internal/domain"
	"github.com/Bavlik/CredScope/internal/parsers/yamlsafe"
	"github.com/Bavlik/CredScope/internal/sanitizer"
	"gopkg.in/yaml.v3"
)

// ParseActionMetadata parses one repository-relative action.yml/action.yaml
// file supplied explicitly by the caller. It never searches for a sibling
// metadata file and never decides between action.yml and action.yaml when
// both might exist in the same directory — locating and choosing the
// correct file belongs to the future local-action resolver (CA1); this
// entry point only parses the exact file it is given.
func (p *Parser) ParseActionMetadata(ctx context.Context, root, file string) (domain.ActionMetadata, error) {
	if err := ctx.Err(); err != nil {
		return domain.ActionMetadata{}, err
	}
	if err := validateActionMetadataFile(file); err != nil {
		return domain.ActionMetadata{}, &ParseError{Path: safeText(file), Msg: err.Error()}
	}
	document, rel, err := yamlsafe.Parse(root, file)
	if err != nil {
		return domain.ActionMetadata{}, &ParseError{Path: safeText(file), Msg: err.Error()}
	}
	rootNode, err := yamlsafe.DocumentRoot(document)
	if err != nil || rootNode.Kind != yaml.MappingNode {
		return domain.ActionMetadata{}, &ParseError{Path: rel, Msg: "action metadata root must be a mapping"}
	}
	metadata := domain.ActionMetadata{
		File:      rel,
		Directory: actionDirectory(rel),
		Evidence:  evidence(rel, rootNode, "", "GitHub Action metadata", domain.ConfidenceConfirmed),
	}

	nameNode, hasName, err := yamlsafe.MappingValue(rootNode, "name")
	if err != nil {
		return domain.ActionMetadata{}, structuralError(rel, rootNode, "name", err)
	}
	if !hasName || nameNode.Kind != yaml.ScalarNode || safeText(nameNode.Value) == "" {
		return domain.ActionMetadata{}, &ParseError{Path: rel, Line: rootNode.Line, Field: "name", Msg: "name must be a non-empty scalar string"}
	}
	metadata.Name = safeText(nameNode.Value)

	descNode, hasDesc, err := yamlsafe.MappingValue(rootNode, "description")
	if err != nil {
		return domain.ActionMetadata{}, structuralError(rel, rootNode, "description", err)
	}
	if !hasDesc || descNode.Kind != yaml.ScalarNode {
		return domain.ActionMetadata{}, &ParseError{Path: rel, Line: rootNode.Line, Field: "description", Msg: "description must be a scalar string"}
	}
	metadata.Description = safeText(descNode.Value)

	if inputsNode, ok, mapErr := yamlsafe.MappingValue(rootNode, "inputs"); mapErr != nil {
		return domain.ActionMetadata{}, structuralError(rel, rootNode, "inputs", mapErr)
	} else if ok {
		metadata.Inputs, err = parseActionInputs(rel, inputsNode)
		if err != nil {
			return domain.ActionMetadata{}, err
		}
	}

	if outputsNode, ok, mapErr := yamlsafe.MappingValue(rootNode, "outputs"); mapErr != nil {
		return domain.ActionMetadata{}, structuralError(rel, rootNode, "outputs", mapErr)
	} else if ok {
		metadata.Outputs, err = parseActionOutputs(rel, outputsNode)
		if err != nil {
			return domain.ActionMetadata{}, err
		}
	}

	runsNode, hasRuns, err := yamlsafe.MappingValue(rootNode, "runs")
	if err != nil {
		return domain.ActionMetadata{}, structuralError(rel, rootNode, "runs", err)
	}
	if !hasRuns || runsNode.Kind != yaml.MappingNode {
		return domain.ActionMetadata{}, &ParseError{Path: rel, Line: rootNode.Line, Field: "runs", Msg: "runs must be a mapping"}
	}
	metadata.Runs, err = parseActionRuns(ctx, rel, runsNode)
	if err != nil {
		return domain.ActionMetadata{}, err
	}

	return metadata, nil
}

// validateActionMetadataFile rejects any path shape ParseActionMetadata must
// not accept before it ever reaches yamlsafe.Parse's own confinement checks.
// This is a pure string-shape gate: it exists so this entry point only ever
// parses one explicit action.yml/action.yaml file — never a directory,
// never a sibling file, never an arbitrary YAML name — matching the
// documented CA0 boundary that filename selection between action.yml and
// action.yaml belongs to the future CA1 resolver, not to this parser.
func validateActionMetadataFile(raw string) error {
	if raw == "" {
		return errors.New("path must not be empty")
	}
	if strings.ContainsRune(raw, 0) {
		return errors.New("path must not contain NUL characters")
	}
	if strings.Contains(raw, "\\") {
		return errors.New("path must not contain backslashes")
	}
	if strings.HasPrefix(raw, "//") {
		return errors.New("path must not be a UNC-style path")
	}
	if len(raw) >= 2 && raw[1] == ':' && ((raw[0] >= 'A' && raw[0] <= 'Z') || (raw[0] >= 'a' && raw[0] <= 'z')) {
		return errors.New("path must not be a drive-letter path")
	}
	if strings.HasPrefix(raw, "/") {
		return errors.New("path must not be an absolute path")
	}
	if strings.ContainsAny(raw, "?#") {
		return errors.New("path must not contain query or fragment suffixes")
	}
	if strings.HasSuffix(raw, "/") {
		return errors.New("path must name a file, not a directory")
	}
	for _, part := range strings.Split(raw, "/") {
		if part == ".." {
			return errors.New("path must not contain parent traversal components")
		}
	}
	base := path.Base(raw)
	if base != "action.yml" && base != "action.yaml" {
		return fmt.Errorf("path %q must name exactly action.yml or action.yaml", raw)
	}
	return nil
}

// actionDirectory derives the directory containing the metadata file from
// its already-forward-slashed, repository-relative path.
func actionDirectory(file string) string {
	dir := path.Dir(file)
	if dir == "" {
		return "."
	}
	return dir
}

func parseActionInputs(file string, node *yaml.Node) ([]domain.ActionInputDefinition, error) {
	if node.Kind != yaml.MappingNode {
		return nil, &ParseError{Path: file, Line: node.Line, Field: "inputs", Msg: "inputs must be a mapping"}
	}
	entries, err := yamlsafe.MappingEntries(node)
	if err != nil {
		return nil, structuralError(file, node, "inputs", err)
	}
	inputs := make([]domain.ActionInputDefinition, 0, len(entries))
	for _, entry := range entries {
		name := sanitizer.Identifier(entry[0].Value)
		field := "inputs." + name
		if entry[1].Kind != yaml.MappingNode {
			return nil, &ParseError{Path: file, Line: entry[1].Line, Field: field, Msg: "input definition must be a mapping"}
		}
		def := domain.ActionInputDefinition{Name: name, Evidence: evidence(file, entry[1], field, "Action input definition", domain.ConfidenceConfirmed)}
		if descNode, ok, mapErr := yamlsafe.MappingValue(entry[1], "description"); mapErr != nil {
			return nil, structuralError(file, entry[1], field+".description", mapErr)
		} else if ok {
			if descNode.Kind != yaml.ScalarNode {
				return nil, &ParseError{Path: file, Line: descNode.Line, Field: field + ".description", Msg: "description must be a scalar string"}
			}
			def.Description = safeText(descNode.Value)
		}
		if reqNode, ok, mapErr := yamlsafe.MappingValue(entry[1], "required"); mapErr != nil {
			return nil, structuralError(file, entry[1], field+".required", mapErr)
		} else if ok {
			value, boolErr := parseBoolScalar(reqNode)
			if boolErr != nil {
				return nil, &ParseError{Path: file, Line: reqNode.Line, Field: field + ".required", Msg: boolErr.Error()}
			}
			def.Required = value
		}
		if defaultNode, ok, mapErr := yamlsafe.MappingValue(entry[1], "default"); mapErr != nil {
			return nil, structuralError(file, entry[1], field+".default", mapErr)
		} else if ok {
			if isNullNode(defaultNode) {
				return nil, &ParseError{Path: file, Line: defaultNode.Line, Field: field + ".default", Msg: "default must not be null"}
			}
			if defaultNode.Kind != yaml.ScalarNode {
				return nil, &ParseError{Path: file, Line: defaultNode.Line, Field: field + ".default", Msg: "default must be a scalar"}
			}
			value := safeText(defaultNode.Value)
			def.Default = &value
		}
		inputs = append(inputs, def)
	}
	sort.Slice(inputs, func(i, j int) bool { return inputs[i].Name < inputs[j].Name })
	return inputs, nil
}

func parseActionOutputs(file string, node *yaml.Node) ([]domain.ActionOutputDefinition, error) {
	if node.Kind != yaml.MappingNode {
		return nil, &ParseError{Path: file, Line: node.Line, Field: "outputs", Msg: "outputs must be a mapping"}
	}
	entries, err := yamlsafe.MappingEntries(node)
	if err != nil {
		return nil, structuralError(file, node, "outputs", err)
	}
	outputs := make([]domain.ActionOutputDefinition, 0, len(entries))
	for _, entry := range entries {
		name := sanitizer.Identifier(entry[0].Value)
		field := "outputs." + name
		if entry[1].Kind != yaml.MappingNode {
			return nil, &ParseError{Path: file, Line: entry[1].Line, Field: field, Msg: "output definition must be a mapping"}
		}
		out := domain.ActionOutputDefinition{Name: name, Evidence: evidence(file, entry[1], field, "Action output definition", domain.ConfidenceConfirmed)}
		if descNode, ok, mapErr := yamlsafe.MappingValue(entry[1], "description"); mapErr != nil {
			return nil, structuralError(file, entry[1], field+".description", mapErr)
		} else if ok {
			if descNode.Kind != yaml.ScalarNode {
				return nil, &ParseError{Path: file, Line: descNode.Line, Field: field + ".description", Msg: "description must be a scalar string"}
			}
			out.Description = safeText(descNode.Value)
		}
		if valueNode, ok, mapErr := yamlsafe.MappingValue(entry[1], "value"); mapErr != nil {
			return nil, structuralError(file, entry[1], field+".value", mapErr)
		} else if ok {
			if valueNode.Kind != yaml.ScalarNode {
				return nil, &ParseError{Path: file, Line: valueNode.Line, Field: field + ".value", Msg: "value must be a scalar"}
			}
			out.Value = safeText(valueNode.Value)
			out.References = extractActionReferences(file, valueNode, field+".value", valueNode.Value)
		}
		outputs = append(outputs, out)
	}
	sort.Slice(outputs, func(i, j int) bool { return outputs[i].Name < outputs[j].Name })
	return outputs, nil
}

func parseActionRuns(ctx context.Context, file string, node *yaml.Node) (domain.ActionRuns, error) {
	runs := domain.ActionRuns{Evidence: evidence(file, node, "runs", "Action runs declaration", domain.ConfidenceConfirmed)}
	usingNode, hasUsing, err := yamlsafe.MappingValue(node, "using")
	if err != nil {
		return runs, structuralError(file, node, "runs.using", err)
	}
	if !hasUsing || usingNode.Kind != yaml.ScalarNode || safeText(usingNode.Value) == "" {
		return runs, &ParseError{Path: file, Line: node.Line, Field: "runs.using", Msg: "runs.using must be a non-empty scalar"}
	}
	runs.Using = safeText(usingNode.Value)
	if runs.Using != "composite" {
		// A valid, non-composite action (JavaScript, Docker, or any other
		// literal GitHub accepts) is not malformed metadata; its runs.*
		// shape is simply not parsed further in CA0.
		return runs, nil
	}
	stepsNode, hasSteps, err := yamlsafe.MappingValue(node, "steps")
	if err != nil {
		return runs, structuralError(file, node, "runs.steps", err)
	}
	if !hasSteps || stepsNode.Kind != yaml.SequenceNode {
		return runs, &ParseError{Path: file, Line: node.Line, Field: "runs.steps", Msg: "composite runs.steps must be a sequence"}
	}
	runs.Steps, err = parseActionSteps(ctx, file, stepsNode)
	if err != nil {
		return runs, err
	}
	return runs, nil
}

func parseActionSteps(ctx context.Context, file string, node *yaml.Node) ([]domain.ActionStep, error) {
	steps := make([]domain.ActionStep, 0, len(node.Content))
	for index, item := range node.Content {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if item.Kind != yaml.MappingNode {
			return nil, &ParseError{Path: file, Line: item.Line, Field: fmt.Sprintf("runs.steps[%d]", index), Msg: "step must be a mapping"}
		}
		step, err := parseActionStep(file, index, item)
		if err != nil {
			return nil, err
		}
		steps = append(steps, step)
	}
	return steps, nil
}

func parseActionStep(file string, index int, node *yaml.Node) (domain.ActionStep, error) {
	field := fmt.Sprintf("runs.steps[%d]", index)
	step := domain.ActionStep{Evidence: evidence(file, node, field, "Composite action step", domain.ConfidenceConfirmed)}

	if idNode, ok, err := yamlsafe.MappingValue(node, "id"); err != nil {
		return step, structuralError(file, node, field+".id", err)
	} else if ok {
		if idNode.Kind != yaml.ScalarNode {
			return step, &ParseError{Path: file, Line: idNode.Line, Field: field + ".id", Msg: "id must be a scalar"}
		}
		step.ID = sanitizer.Identifier(idNode.Value)
	}
	if nameNode, ok, err := yamlsafe.MappingValue(node, "name"); err != nil {
		return step, structuralError(file, node, field+".name", err)
	} else if ok {
		if nameNode.Kind != yaml.ScalarNode {
			return step, &ParseError{Path: file, Line: nameNode.Line, Field: field + ".name", Msg: "name must be a scalar"}
		}
		step.Name = safeText(nameNode.Value)
	}
	if ifNode, ok, err := yamlsafe.MappingValue(node, "if"); err != nil {
		return step, structuralError(file, node, field+".if", err)
	} else if ok {
		if ifNode.Kind != yaml.ScalarNode {
			return step, &ParseError{Path: file, Line: ifNode.Line, Field: field + ".if", Msg: "if must be a scalar"}
		}
		step.If = safeText(ifNode.Value)
	}

	usesNode, hasUses, err := yamlsafe.MappingValue(node, "uses")
	if err != nil {
		return step, structuralError(file, node, field+".uses", err)
	}
	runNode, hasRun, err := yamlsafe.MappingValue(node, "run")
	if err != nil {
		return step, structuralError(file, node, field+".run", err)
	}
	if hasUses && hasRun {
		return step, &ParseError{Path: file, Line: node.Line, Field: field, Msg: "step must not declare both uses and run"}
	}
	if hasUses {
		if usesNode.Kind != yaml.ScalarNode {
			return step, &ParseError{Path: file, Line: usesNode.Line, Field: field + ".uses", Msg: "uses must be a scalar"}
		}
		action := classifyAction(file, usesNode, field+".uses")
		step.Action = &action
	}
	if hasRun {
		if runNode.Kind != yaml.ScalarNode {
			return step, &ParseError{Path: file, Line: runNode.Line, Field: field + ".run", Msg: "run must be a scalar"}
		}
		step.Run = parseActionRun(file, runNode, field+".run")
	}

	if shellNode, ok, err := yamlsafe.MappingValue(node, "shell"); err != nil {
		return step, structuralError(file, node, field+".shell", err)
	} else if ok {
		if shellNode.Kind != yaml.ScalarNode {
			return step, &ParseError{Path: file, Line: shellNode.Line, Field: field + ".shell", Msg: "shell must be a scalar"}
		}
		step.Shell = safeText(shellNode.Value)
	}
	if wdNode, ok, err := yamlsafe.MappingValue(node, "working-directory"); err != nil {
		return step, structuralError(file, node, field+".working-directory", err)
	} else if ok {
		if wdNode.Kind != yaml.ScalarNode {
			return step, &ParseError{Path: file, Line: wdNode.Line, Field: field + ".working-directory", Msg: "working-directory must be a scalar"}
		}
		step.WorkingDirectory = safeText(wdNode.Value)
	}
	if withNode, ok, err := yamlsafe.MappingValue(node, "with"); err != nil {
		return step, structuralError(file, node, field+".with", err)
	} else if ok {
		step.With, err = parseActionInputBindings(file, field, withNode)
		if err != nil {
			return step, err
		}
	}
	if envNode, ok, err := yamlsafe.MappingValue(node, "env"); err != nil {
		return step, structuralError(file, node, field+".env", err)
	} else if ok {
		step.Environment, err = parseActionStepEnvironment(file, field, envNode)
		if err != nil {
			return step, err
		}
	}
	if coeNode, ok, err := yamlsafe.MappingValue(node, "continue-on-error"); err != nil {
		return step, structuralError(file, node, field+".continue-on-error", err)
	} else if ok {
		value, boolErr := parseBoolScalar(coeNode)
		if boolErr != nil {
			return step, &ParseError{Path: file, Line: coeNode.Line, Field: field + ".continue-on-error", Msg: boolErr.Error()}
		}
		step.ContinueOnError = &value
	}

	step.References = extractActionReferencesFromNode(file, node, field)
	return step, nil
}

func parseActionInputBindings(file, stepField string, node *yaml.Node) ([]domain.ActionInputBinding, error) {
	if node.Kind != yaml.MappingNode {
		return nil, &ParseError{Path: file, Line: node.Line, Field: stepField + ".with", Msg: "with must be a mapping"}
	}
	entries, err := yamlsafe.MappingEntries(node)
	if err != nil {
		return nil, structuralError(file, node, stepField+".with", err)
	}
	bindings := make([]domain.ActionInputBinding, 0, len(entries))
	for _, entry := range entries {
		name := sanitizer.Identifier(entry[0].Value)
		field := stepField + ".with." + name
		if entry[1].Kind != yaml.ScalarNode {
			return nil, &ParseError{Path: file, Line: entry[1].Line, Field: field, Msg: "with value must be a scalar"}
		}
		bindings = append(bindings, domain.ActionInputBinding{
			Name:       name,
			Value:      safeText(entry[1].Value),
			References: extractActionReferences(file, entry[1], field, entry[1].Value),
			Evidence:   evidence(file, entry[1], field, "Nested action input binding", domain.ConfidenceConfirmed),
		})
	}
	sort.Slice(bindings, func(i, j int) bool { return bindings[i].Name < bindings[j].Name })
	return bindings, nil
}

// parseActionStepEnvironment is the composite-step-scoped counterpart to
// parseEnvironment: identical structural handling, but reference extraction
// uses the composite-action-scoped extractor so that e.g.
// `env: { TOKEN: ${{ inputs.token }} }` inside a composite step is never
// misclassified using the workflow-level dangerous-context rule.
func parseActionStepEnvironment(file, stepField string, node *yaml.Node) ([]domain.EnvironmentBinding, error) {
	if node.Kind != yaml.MappingNode {
		return nil, &ParseError{Path: file, Line: node.Line, Field: stepField + ".env", Msg: "env must be a mapping"}
	}
	entries, err := yamlsafe.MappingEntries(node)
	if err != nil {
		return nil, structuralError(file, node, stepField+".env", err)
	}
	result := make([]domain.EnvironmentBinding, 0, len(entries))
	for _, entry := range entries {
		name := sanitizer.Identifier(entry[0].Value)
		if entry[1].Kind != yaml.ScalarNode {
			return nil, &ParseError{Path: file, Line: entry[1].Line, Field: stepField + ".env." + name, Msg: "env value must be a scalar"}
		}
		value := entry[1].Value
		field := stepField + ".env." + name
		refs := extractActionReferences(file, entry[1], field, value)
		withoutExpressions := expressionPattern.ReplaceAllString(value, "")
		binding := domain.EnvironmentBinding{
			Name: name, Scope: "action_step", References: refs,
			HasLiteral: strings.TrimSpace(withoutExpressions) != "",
			Evidence:   evidence(file, entry[1], field, "Action step environment binding", domain.ConfidenceConfirmed),
		}
		if binding.HasLiteral {
			binding.LiteralFingerprint = sanitizer.Fingerprint(value)
		}
		result = append(result, binding)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result, nil
}

// parseActionRun is the composite-step-scoped counterpart to parseRun: same
// redaction/fingerprint behavior, but composite-scoped reference extraction.
func parseActionRun(file string, node *yaml.Node, field string) *domain.ShellCommand {
	text := node.Value
	refs := extractActionReferences(file, node, field, text)
	canonical := make([]string, 0, len(refs))
	for _, ref := range refs {
		canonical = append(canonical, ref.Expression)
	}
	redacted := "<redacted>"
	if len(canonical) > 0 {
		redacted += " " + strings.Join(canonical, " ")
	}
	sum := sha256.Sum256([]byte("credscope:shell:v1\x00" + text))
	command := domain.ShellCommand{
		RedactedText: redacted, Fingerprint: "sha256:" + hex.EncodeToString(sum[:]),
		LineCount: strings.Count(text, "\n") + 1, References: refs,
		Evidence: evidence(file, node, field, "Inert shell command (body redacted)", domain.ConfidenceConfirmed),
	}
	return &command
}

// extractActionReferences is the composite-action-metadata-scoped
// counterpart to extractReferences. It must never mark ${{ inputs.* }} as
// the existing dangerous workflow-input context (composite inputs are not a
// workflow's own workflow_dispatch/workflow_call caller input) and must
// never mark ${{ secrets.* }} as ReferenceSecret (GitHub does not provide
// the secrets context inside composite actions, so a literal occurrence is
// structural text only, never a credential-eligible reference).
func extractActionReferences(file string, node *yaml.Node, field, text string) []domain.Reference {
	matches := expressionPattern.FindAllStringSubmatch(text, -1)
	refs := make([]domain.Reference, 0, len(matches))
	for _, match := range matches {
		contextName := strings.ToLower(match[1])
		member := strings.TrimSpace(match[2])
		member = firstReferenceMember(member)
		kind := domain.ReferenceGitHubContext
		name := sanitizer.Identifier(contextName + "." + member)
		switch contextName {
		case "inputs":
			kind = domain.ReferenceActionInput
			name = sanitizer.Identifier(member)
		case "env":
			kind = domain.ReferenceEnvironment
			name = sanitizer.Identifier(member)
		}
		if name == "" {
			continue
		}
		expression := "${{ " + contextName + "." + sanitizer.Identifier(member) + " }}"
		refs = append(refs, domain.Reference{Kind: kind, Name: name, Expression: expression, Evidence: evidence(file, node, field, "Action metadata expression reference", domain.ConfidenceConfirmed)})
	}
	return uniqueReferences(refs)
}

func extractActionReferencesFromNode(file string, node *yaml.Node, field string) []domain.Reference {
	var refs []domain.Reference
	var walk func(*yaml.Node)
	walk = func(current *yaml.Node) {
		if current == nil {
			return
		}
		if current.Kind == yaml.ScalarNode {
			refs = append(refs, extractActionReferences(file, current, field, current.Value)...)
		}
		for _, child := range current.Content {
			walk(child)
		}
	}
	walk(node)
	return uniqueReferences(refs)
}
