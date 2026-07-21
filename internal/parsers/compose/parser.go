// Package compose parses Docker Compose files without executing Docker.
package compose

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/credscope/credscope/internal/domain"
	"github.com/credscope/credscope/internal/parsers/yamlsafe"
	"github.com/credscope/credscope/internal/sanitizer"
	"go.yaml.in/yaml/v3"
)

const parserSource = "docker-compose"

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
	return "docker-compose parse error: " + location + ": " + e.Msg
}

type Parser struct{}

func New() *Parser             { return &Parser{} }
func (p *Parser) Name() string { return parserSource }

func (p *Parser) Parse(ctx context.Context, root, file string) (domain.ComposeProject, error) {
	if err := ctx.Err(); err != nil {
		return domain.ComposeProject{}, err
	}
	document, rel, err := yamlsafe.Parse(root, file)
	if err != nil {
		return domain.ComposeProject{}, &ParseError{Path: safeText(file), Msg: err.Error()}
	}
	rootNode, err := yamlsafe.DocumentRoot(document)
	if err != nil || rootNode.Kind != yaml.MappingNode {
		return domain.ComposeProject{}, &ParseError{Path: rel, Msg: "Compose root must be a mapping"}
	}
	project := domain.ComposeProject{File: rel, Evidence: evidence(rel, rootNode, "", "Docker Compose project", domain.ConfidenceConfirmed)}
	servicesNode, ok, mapErr := yamlsafe.MappingValue(rootNode, "services")
	if mapErr != nil {
		return project, structuralError(rel, rootNode, "services", mapErr)
	}
	if !ok || servicesNode.Kind != yaml.MappingNode {
		return project, &ParseError{Path: rel, Line: rootNode.Line, Field: "services", Msg: "required services mapping is missing or invalid"}
	}
	project.Services, err = parseServices(ctx, rel, servicesNode)
	if err != nil {
		return project, err
	}
	if secretsNode, found, getErr := yamlsafe.MappingValue(rootNode, "secrets"); getErr != nil {
		return project, structuralError(rel, rootNode, "secrets", getErr)
	} else if found {
		project.Secrets, err = parseTopSecrets(rel, secretsNode)
		if err != nil {
			return project, err
		}
	}
	if networksNode, found, getErr := yamlsafe.MappingValue(rootNode, "networks"); getErr != nil {
		return project, structuralError(rel, rootNode, "networks", getErr)
	} else if found {
		project.Networks, err = parseNamedMapping(rel, networksNode, "networks")
		if err != nil {
			return project, err
		}
	}
	project.SharedCredentials = sharedCredentials(project.Services)
	return project, nil
}

func parseServices(ctx context.Context, file string, node *yaml.Node) ([]domain.ComposeService, error) {
	entries, err := yamlsafe.MappingEntries(node)
	if err != nil {
		return nil, structuralError(file, node, "services", err)
	}
	services := make([]domain.ComposeService, 0, len(entries))
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		name := sanitizer.Identifier(entry[0].Value)
		service, parseErr := parseService(file, name, entry[1])
		if parseErr != nil {
			return nil, parseErr
		}
		services = append(services, service)
	}
	sort.Slice(services, func(i, j int) bool { return services[i].Name < services[j].Name })
	return services, nil
}

func parseService(file, name string, node *yaml.Node) (domain.ComposeService, error) {
	field := "services." + name
	if node.Kind != yaml.MappingNode {
		return domain.ComposeService{}, &ParseError{Path: file, Line: node.Line, Field: field, Msg: "service must be a mapping"}
	}
	service := domain.ComposeService{Name: name, Evidence: evidence(file, node, field, "Compose service", domain.ConfidenceConfirmed)}
	var err error
	if env, ok, getErr := yamlsafe.MappingValue(node, "environment"); getErr != nil {
		return service, structuralError(file, node, field+".environment", getErr)
	} else if ok {
		service.Environment, err = parseEnvironment(file, env, field+".environment", name)
		if err != nil {
			return service, err
		}
	}
	if envFiles, ok, getErr := yamlsafe.MappingValue(node, "env_file"); getErr != nil {
		return service, structuralError(file, node, field+".env_file", getErr)
	} else if ok {
		service.EnvFiles, err = parseEnvFiles(file, envFiles, field+".env_file")
		if err != nil {
			return service, err
		}
	}
	if secrets, ok, getErr := yamlsafe.MappingValue(node, "secrets"); getErr != nil {
		return service, structuralError(file, node, field+".secrets", getErr)
	} else if ok {
		service.Secrets, err = parseSecretUses(file, secrets, field+".secrets")
		if err != nil {
			return service, err
		}
	}
	if ports, ok, getErr := yamlsafe.MappingValue(node, "ports"); getErr != nil {
		return service, structuralError(file, node, field+".ports", getErr)
	} else if ok {
		service.Ports, err = parsePorts(file, ports, field+".ports")
		if err != nil {
			return service, err
		}
	}
	if expose, ok, getErr := yamlsafe.MappingValue(node, "expose"); getErr != nil {
		return service, structuralError(file, node, field+".expose", getErr)
	} else if ok {
		service.ExposedPorts, err = parseNamedList(file, expose, field+".expose")
		if err != nil {
			return service, err
		}
	}
	if networks, ok, getErr := yamlsafe.MappingValue(node, "networks"); getErr != nil {
		return service, structuralError(file, node, field+".networks", getErr)
	} else if ok {
		service.Networks, err = parseNamedCollection(file, networks, field+".networks")
		if err != nil {
			return service, err
		}
	}
	if volumes, ok, getErr := yamlsafe.MappingValue(node, "volumes"); getErr != nil {
		return service, structuralError(file, node, field+".volumes", getErr)
	} else if ok {
		service.Volumes, err = parseVolumes(file, volumes, field+".volumes")
		if err != nil {
			return service, err
		}
	}
	if privileged, ok, getErr := yamlsafe.MappingValue(node, "privileged"); getErr != nil {
		return service, structuralError(file, node, field+".privileged", getErr)
	} else if ok {
		service.Privileged, err = scalarBool(privileged)
		if err != nil {
			return service, &ParseError{Path: file, Line: privileged.Line, Field: field + ".privileged", Msg: err.Error()}
		}
	}
	if networkMode, ok, getErr := yamlsafe.MappingValue(node, "network_mode"); getErr != nil {
		return service, structuralError(file, node, field+".network_mode", getErr)
	} else if ok {
		service.NetworkMode = safeText(networkMode.Value)
		service.HostNetwork = strings.EqualFold(service.NetworkMode, "host")
	}
	if depends, ok, getErr := yamlsafe.MappingValue(node, "depends_on"); getErr != nil {
		return service, structuralError(file, node, field+".depends_on", getErr)
	} else if ok {
		service.DependsOn, err = parseNamedCollection(file, depends, field+".depends_on")
		if err != nil {
			return service, err
		}
	}
	if _, ok, getErr := yamlsafe.MappingValue(node, "healthcheck"); getErr != nil {
		return service, structuralError(file, node, field+".healthcheck", getErr)
	} else {
		service.HasHealthcheck = ok
	}
	if restart, ok, getErr := yamlsafe.MappingValue(node, "restart"); getErr != nil {
		return service, structuralError(file, node, field+".restart", getErr)
	} else if ok {
		service.Restart = safeText(restart.Value)
	}
	if profiles, ok, getErr := yamlsafe.MappingValue(node, "profiles"); getErr != nil {
		return service, structuralError(file, node, field+".profiles", getErr)
	} else if ok {
		service.Profiles, err = parseNamedList(file, profiles, field+".profiles")
		if err != nil {
			return service, err
		}
	}
	if user, ok, getErr := yamlsafe.MappingValue(node, "user"); getErr != nil {
		return service, structuralError(file, node, field+".user", getErr)
	} else if ok {
		service.UserSpecified = true
		service.User = safeText(user.Value)
	}
	if workdir, ok, getErr := yamlsafe.MappingValue(node, "working_dir"); getErr != nil {
		return service, structuralError(file, node, field+".working_dir", getErr)
	} else if ok {
		service.WorkingDirectory = safeText(workdir.Value)
	}
	service.References = collectServiceReferences(service)
	service.ProductionLike = productionLike(name, service.Profiles)
	service.Signals = serviceSignals(file, node, service)
	return service, nil
}

func parseEnvironment(file string, node *yaml.Node, field, serviceName string) ([]domain.EnvironmentBinding, error) {
	var bindings []domain.EnvironmentBinding
	switch node.Kind {
	case yaml.MappingNode:
		entries, err := yamlsafe.MappingEntries(node)
		if err != nil {
			return nil, structuralError(file, node, field, err)
		}
		for _, entry := range entries {
			name := sanitizer.Identifier(entry[0].Value)
			value := entry[1].Value
			refs := extractComposeReferences(file, entry[1], field+"."+name, value)
			if len(refs) == 0 && (entry[1].Tag == "!!null" || looksCredential(name)) {
				refs = append(refs, composeReference(file, entry[1], field+"."+name, name, domain.ConfidenceHigh))
			}
			hasLiteral := entry[1].Tag != "!!null" && strings.TrimSpace(composeExpression.ReplaceAllString(value, "")) != ""
			binding := domain.EnvironmentBinding{Name: name, Scope: "service." + serviceName, References: refs, HasLiteral: hasLiteral, Evidence: evidence(file, entry[1], field+"."+name, "Service environment binding", domain.ConfidenceConfirmed)}
			if hasLiteral {
				binding.LiteralFingerprint = sanitizer.Fingerprint(value)
			}
			bindings = append(bindings, binding)
		}
	case yaml.SequenceNode:
		for index, entry := range node.Content {
			if entry.Kind != yaml.ScalarNode {
				return nil, &ParseError{Path: file, Line: entry.Line, Field: field, Msg: "environment list entries must be scalars"}
			}
			name, value, hasValue := strings.Cut(entry.Value, "=")
			name = sanitizer.Identifier(strings.TrimSpace(name))
			entryField := fmt.Sprintf("%s[%d]", field, index)
			refs := extractComposeReferences(file, entry, entryField, value)
			if len(refs) == 0 && (!hasValue || looksCredential(name)) {
				refs = append(refs, composeReference(file, entry, entryField, name, domain.ConfidenceHigh))
			}
			hasLiteral := hasValue && strings.TrimSpace(composeExpression.ReplaceAllString(value, "")) != ""
			binding := domain.EnvironmentBinding{Name: name, Scope: "service." + serviceName, References: refs, HasLiteral: hasLiteral, Evidence: evidence(file, entry, entryField, "Service environment binding", domain.ConfidenceConfirmed)}
			if hasLiteral {
				binding.LiteralFingerprint = sanitizer.Fingerprint(value)
			}
			bindings = append(bindings, binding)
		}
	default:
		return nil, &ParseError{Path: file, Line: node.Line, Field: field, Msg: "environment must be a mapping or list"}
	}
	sort.Slice(bindings, func(i, j int) bool { return bindings[i].Name < bindings[j].Name })
	return bindings, nil
}

func parseEnvFiles(file string, node *yaml.Node, field string) ([]domain.FileReference, error) {
	var nodes []*yaml.Node
	if node.Kind == yaml.SequenceNode {
		nodes = node.Content
	} else {
		nodes = []*yaml.Node{node}
	}
	result := make([]domain.FileReference, 0, len(nodes))
	for index, item := range nodes {
		valueNode := item
		if item.Kind == yaml.MappingNode {
			pathNode, ok, err := yamlsafe.MappingValue(item, "path")
			if err != nil {
				return nil, structuralError(file, item, field, err)
			}
			if !ok {
				return nil, &ParseError{Path: file, Line: item.Line, Field: field, Msg: "env_file mapping requires path"}
			}
			valueNode = pathNode
		}
		if valueNode.Kind != yaml.ScalarNode {
			return nil, &ParseError{Path: file, Line: valueNode.Line, Field: field, Msg: "env_file path must be a scalar"}
		}
		result = append(result, domain.FileReference{Path: safeText(valueNode.Value), Evidence: evidence(file, valueNode, fmt.Sprintf("%s[%d]", field, index), "Environment file reference (not read)", domain.ConfidenceConfirmed)})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Path < result[j].Path })
	return result, nil
}

func parseSecretUses(file string, node *yaml.Node, field string) ([]domain.ComposeSecretUse, error) {
	if node.Kind != yaml.SequenceNode {
		return nil, &ParseError{Path: file, Line: node.Line, Field: field, Msg: "service secrets must be a list"}
	}
	result := make([]domain.ComposeSecretUse, 0, len(node.Content))
	for index, item := range node.Content {
		use := domain.ComposeSecretUse{Evidence: evidence(file, item, fmt.Sprintf("%s[%d]", field, index), "Compose secret use", domain.ConfidenceConfirmed)}
		if item.Kind == yaml.ScalarNode {
			use.Source = sanitizer.Identifier(item.Value)
		} else if item.Kind == yaml.MappingNode {
			source, ok, err := yamlsafe.MappingValue(item, "source")
			if err != nil {
				return nil, structuralError(file, item, field, err)
			}
			if !ok {
				return nil, &ParseError{Path: file, Line: item.Line, Field: field, Msg: "secret mapping requires source"}
			}
			use.Source = sanitizer.Identifier(source.Value)
			if target, found, _ := yamlsafe.MappingValue(item, "target"); found {
				use.Target = safeText(target.Value)
			}
		} else {
			return nil, &ParseError{Path: file, Line: item.Line, Field: field, Msg: "secret entry must be a scalar or mapping"}
		}
		result = append(result, use)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Source < result[j].Source })
	return result, nil
}

func parsePorts(file string, node *yaml.Node, field string) ([]domain.ComposePort, error) {
	if node.Kind != yaml.SequenceNode {
		return nil, &ParseError{Path: file, Line: node.Line, Field: field, Msg: "ports must be a list"}
	}
	ports := make([]domain.ComposePort, 0, len(node.Content))
	for index, item := range node.Content {
		itemField := fmt.Sprintf("%s[%d]", field, index)
		port := domain.ComposePort{Evidence: evidence(file, item, itemField, "Compose port mapping", domain.ConfidenceConfirmed)}
		var err error
		if item.Kind == yaml.ScalarNode {
			port, err = parseShortPort(item.Value, port)
		} else if item.Kind == yaml.MappingNode {
			port, err = parseLongPort(item, port)
		} else {
			err = errors.New("port entry must be a scalar or mapping")
		}
		if err != nil {
			return nil, &ParseError{Path: file, Line: item.Line, Field: itemField, Msg: err.Error()}
		}
		ports = append(ports, port)
	}
	sort.Slice(ports, func(i, j int) bool {
		if ports[i].Published != ports[j].Published {
			return ports[i].Published < ports[j].Published
		}
		return ports[i].Target < ports[j].Target
	})
	return ports, nil
}

func parseShortPort(value string, port domain.ComposePort) (domain.ComposePort, error) {
	value = safeText(value)
	base, protocol, hasProtocol := strings.Cut(value, "/")
	if hasProtocol {
		port.Protocol = protocol
	}
	parts := strings.Split(base, ":")
	switch len(parts) {
	case 1:
		port.Target = parts[0]
	case 2:
		port.Published, port.Target = parts[0], parts[1]
	default:
		port.HostIP, port.Published, port.Target = strings.Join(parts[:len(parts)-2], ":"), parts[len(parts)-2], parts[len(parts)-1]
	}
	if port.Target == "" {
		return port, errors.New("port target is required")
	}
	return port, nil
}

func parseLongPort(node *yaml.Node, port domain.ComposePort) (domain.ComposePort, error) {
	target, ok, err := yamlsafe.MappingValue(node, "target")
	if err != nil || !ok {
		return port, errors.New("long port mapping requires target")
	}
	port.Target = safeText(target.Value)
	if published, found, _ := yamlsafe.MappingValue(node, "published"); found {
		port.Published = safeText(published.Value)
	}
	if hostIP, found, _ := yamlsafe.MappingValue(node, "host_ip"); found {
		port.HostIP = safeText(hostIP.Value)
	}
	if protocol, found, _ := yamlsafe.MappingValue(node, "protocol"); found {
		port.Protocol = safeText(protocol.Value)
	}
	return port, nil
}

func parseVolumes(file string, node *yaml.Node, field string) ([]domain.ComposeVolume, error) {
	if node.Kind != yaml.SequenceNode {
		return nil, &ParseError{Path: file, Line: node.Line, Field: field, Msg: "volumes must be a list"}
	}
	volumes := make([]domain.ComposeVolume, 0, len(node.Content))
	for index, item := range node.Content {
		itemField := fmt.Sprintf("%s[%d]", field, index)
		volume := domain.ComposeVolume{Evidence: evidence(file, item, itemField, "Compose volume mount", domain.ConfidenceConfirmed)}
		var err error
		if item.Kind == yaml.ScalarNode {
			volume, err = parseShortVolume(item.Value, volume)
		} else if item.Kind == yaml.MappingNode {
			volume, err = parseLongVolume(item, volume)
		} else {
			err = errors.New("volume entry must be a scalar or mapping")
		}
		if err != nil {
			return nil, &ParseError{Path: file, Line: item.Line, Field: itemField, Msg: err.Error()}
		}
		classifyVolume(&volume)
		volumes = append(volumes, volume)
	}
	sort.Slice(volumes, func(i, j int) bool {
		if volumes[i].Target != volumes[j].Target {
			return volumes[i].Target < volumes[j].Target
		}
		return volumes[i].Source < volumes[j].Source
	})
	return volumes, nil
}

func parseShortVolume(value string, volume domain.ComposeVolume) (domain.ComposeVolume, error) {
	value = safeText(value)
	parts := strings.Split(value, ":")
	if len(parts) == 1 {
		volume.Target = parts[0]
		return volume, nil
	}
	mode := ""
	if last := parts[len(parts)-1]; last == "ro" || last == "rw" || strings.Contains(last, ",") {
		mode = last
		parts = parts[:len(parts)-1]
	}
	if len(parts) < 2 {
		return volume, errors.New("volume source and target are required")
	}
	volume.Target = parts[len(parts)-1]
	volume.Source = strings.Join(parts[:len(parts)-1], ":")
	volume.ReadOnly = strings.Contains(mode, "ro")
	return volume, nil
}

func parseLongVolume(node *yaml.Node, volume domain.ComposeVolume) (domain.ComposeVolume, error) {
	target, ok, _ := yamlsafe.MappingValue(node, "target")
	if !ok {
		return volume, errors.New("long volume mapping requires target")
	}
	volume.Target = safeText(target.Value)
	if source, found, _ := yamlsafe.MappingValue(node, "source"); found {
		volume.Source = safeText(source.Value)
	}
	if volumeType, found, _ := yamlsafe.MappingValue(node, "type"); found {
		volume.Type = safeText(volumeType.Value)
	}
	if readOnly, found, _ := yamlsafe.MappingValue(node, "read_only"); found {
		value, err := scalarBool(readOnly)
		if err != nil {
			return volume, err
		}
		volume.ReadOnly = value
	}
	return volume, nil
}

func classifyVolume(volume *domain.ComposeVolume) {
	normalizedSource := strings.ToLower(strings.ReplaceAll(volume.Source, "\\", "/"))
	normalizedTarget := strings.ToLower(strings.ReplaceAll(volume.Target, "\\", "/"))
	volume.DockerSocket = normalizedSource == "/var/run/docker.sock" || normalizedTarget == "/var/run/docker.sock" || strings.Contains(normalizedSource, "//./pipe/docker_engine")
	volume.HostBind = volume.Type == "bind" || strings.HasPrefix(volume.Source, ".") || strings.HasPrefix(volume.Source, "/") || strings.HasPrefix(volume.Source, "~") || windowsDrive.MatchString(volume.Source)
	volume.WritableHostBind = volume.HostBind && !volume.ReadOnly
}

func parseTopSecrets(file string, node *yaml.Node) ([]domain.ComposeSecret, error) {
	if node.Kind != yaml.MappingNode {
		return nil, &ParseError{Path: file, Line: node.Line, Field: "secrets", Msg: "top-level secrets must be a mapping"}
	}
	entries, err := yamlsafe.MappingEntries(node)
	if err != nil {
		return nil, structuralError(file, node, "secrets", err)
	}
	result := make([]domain.ComposeSecret, 0, len(entries))
	for _, entry := range entries {
		secret := domain.ComposeSecret{Name: sanitizer.Identifier(entry[0].Value), Evidence: evidence(file, entry[0], "secrets."+sanitizer.Identifier(entry[0].Value), "Compose secret declaration", domain.ConfidenceConfirmed)}
		if entry[1].Kind == yaml.MappingNode {
			if fileNode, found, _ := yamlsafe.MappingValue(entry[1], "file"); found {
				secret.File = safeText(fileNode.Value)
			}
			if external, found, externalErr := yamlsafe.MappingValue(entry[1], "external"); externalErr != nil {
				return nil, structuralError(file, entry[1], "secrets."+secret.Name+".external", externalErr)
			} else if found {
				if external.Kind == yaml.MappingNode {
					secret.External = true
				} else {
					secret.External, err = scalarBool(external)
					if err != nil {
						return nil, &ParseError{Path: file, Line: external.Line, Field: "secrets." + secret.Name + ".external", Msg: err.Error()}
					}
				}
			}
		} else if entry[1].Tag != "!!null" {
			return nil, &ParseError{Path: file, Line: entry[1].Line, Field: "secrets." + secret.Name, Msg: "secret declaration must be a mapping"}
		}
		result = append(result, secret)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result, nil
}

func parseNamedMapping(file string, node *yaml.Node, field string) ([]domain.NamedValue, error) {
	if node.Kind != yaml.MappingNode {
		return nil, &ParseError{Path: file, Line: node.Line, Field: field, Msg: "value must be a mapping"}
	}
	entries, err := yamlsafe.MappingEntries(node)
	if err != nil {
		return nil, structuralError(file, node, field, err)
	}
	result := make([]domain.NamedValue, 0, len(entries))
	for _, entry := range entries {
		result = append(result, domain.NamedValue{Name: sanitizer.Identifier(entry[0].Value), Evidence: evidence(file, entry[0], field+"."+sanitizer.Identifier(entry[0].Value), "Named Compose reference", domain.ConfidenceConfirmed)})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result, nil
}

func parseNamedList(file string, node *yaml.Node, field string) ([]domain.NamedValue, error) {
	if node.Kind == yaml.ScalarNode {
		return []domain.NamedValue{{Name: safeText(node.Value), Evidence: evidence(file, node, field, "Named Compose value", domain.ConfidenceConfirmed)}}, nil
	}
	if node.Kind != yaml.SequenceNode {
		return nil, &ParseError{Path: file, Line: node.Line, Field: field, Msg: "value must be a scalar or list"}
	}
	result := make([]domain.NamedValue, 0, len(node.Content))
	for index, child := range node.Content {
		if child.Kind != yaml.ScalarNode {
			return nil, &ParseError{Path: file, Line: child.Line, Field: field, Msg: "list entries must be scalars"}
		}
		result = append(result, domain.NamedValue{Name: safeText(child.Value), Evidence: evidence(file, child, fmt.Sprintf("%s[%d]", field, index), "Named Compose value", domain.ConfidenceConfirmed)})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result, nil
}

func parseNamedCollection(file string, node *yaml.Node, field string) ([]domain.NamedValue, error) {
	if node.Kind == yaml.MappingNode {
		return parseNamedMapping(file, node, field)
	}
	return parseNamedList(file, node, field)
}

func serviceSignals(file string, node *yaml.Node, service domain.ComposeService) []domain.StructuralSignal {
	var signals []domain.StructuralSignal
	for _, ref := range service.References {
		signals = append(signals, domain.StructuralSignal{Kind: "credential_passed_to_service", Description: "A credential-like variable reference is passed to this service.", Confidence: ref.Evidence.Confidence, Evidence: ref.Evidence})
	}
	for _, port := range service.Ports {
		if port.Published != "" {
			signals = append(signals, domain.StructuralSignal{Kind: "host_port_published", Description: "The service publishes a host port and may be externally reachable depending on host and network configuration.", Confidence: domain.ConfidenceMedium, Evidence: port.Evidence})
		}
	}
	if service.Privileged {
		signals = append(signals, composeSignal(file, node, "services."+service.Name+".privileged", "privileged_service", "Service enables privileged mode.", domain.ConfidenceConfirmed))
	}
	if service.HostNetwork {
		signals = append(signals, composeSignal(file, node, "services."+service.Name+".network_mode", "host_network", "Service uses the host network namespace.", domain.ConfidenceConfirmed))
	}
	for _, volume := range service.Volumes {
		if volume.DockerSocket {
			signals = append(signals, domain.StructuralSignal{Kind: "docker_socket_mount", Description: "Service mounts the Docker control socket or pipe.", Confidence: domain.ConfidenceConfirmed, Evidence: volume.Evidence})
		}
		if volume.WritableHostBind {
			signals = append(signals, domain.StructuralSignal{Kind: "writable_host_bind_mount", Description: "Service has a writable bind mount from the host.", Confidence: domain.ConfidenceHigh, Evidence: volume.Evidence})
		}
	}
	if !service.UserSpecified {
		signals = append(signals, composeSignal(file, node, "services."+service.Name+".user", "missing_explicit_non_root_user", "Service does not declare a user; this does not prove the container runs as root.", domain.ConfidenceLow))
	} else if explicitRootUser(service.User) {
		signals = append(signals, composeSignal(file, node, "services."+service.Name+".user", "explicit_root_user", "Service explicitly selects the root user.", domain.ConfidenceConfirmed))
	}
	if service.ProductionLike {
		signals = append(signals, composeSignal(file, node, "services."+service.Name, "production_like_service", "Service or profile name appears production-like.", domain.ConfidenceMedium))
	}
	return uniqueSignals(signals)
}

func collectServiceReferences(service domain.ComposeService) []domain.Reference {
	var refs []domain.Reference
	for _, binding := range service.Environment {
		refs = append(refs, binding.References...)
	}
	for _, secret := range service.Secrets {
		refs = append(refs, domain.Reference{
			Kind: domain.ReferenceComposeSecret, Name: secret.Source,
			Expression: "compose-secret:" + secret.Source, Evidence: secret.Evidence,
		})
	}
	return uniqueReferences(refs)
}

func sharedCredentials(services []domain.ComposeService) []domain.SharedCredential {
	type aggregate struct {
		services map[string]struct{}
		evidence []domain.Evidence
	}
	byName := make(map[string]*aggregate)
	for _, service := range services {
		seen := make(map[string]bool)
		for _, ref := range service.References {
			if seen[ref.Name] {
				continue
			}
			seen[ref.Name] = true
			item := byName[ref.Name]
			if item == nil {
				item = &aggregate{services: make(map[string]struct{})}
				byName[ref.Name] = item
			}
			item.services[service.Name] = struct{}{}
			item.evidence = append(item.evidence, ref.Evidence)
		}
	}
	var result []domain.SharedCredential
	for name, item := range byName {
		if len(item.services) < 2 {
			continue
		}
		services := make([]string, 0, len(item.services))
		for service := range item.services {
			services = append(services, service)
		}
		sort.Strings(services)
		sort.Slice(item.evidence, func(i, j int) bool {
			if item.evidence[i].Location.Line != item.evidence[j].Location.Line {
				return item.evidence[i].Location.Line < item.evidence[j].Location.Line
			}
			return item.evidence[i].Field < item.evidence[j].Field
		})
		result = append(result, domain.SharedCredential{Name: name, Services: services, Confidence: domain.ConfidenceConfirmed, Evidence: item.evidence})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result
}

var (
	composeExpression = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)(?::[-+?][^}]*)?\}`)
	windowsDrive      = regexp.MustCompile(`^[A-Za-z]:[\\/]`)
)

func extractComposeReferences(file string, node *yaml.Node, field, value string) []domain.Reference {
	matches := composeExpression.FindAllStringSubmatch(value, -1)
	refs := make([]domain.Reference, 0, len(matches))
	for _, match := range matches {
		refs = append(refs, composeReference(file, node, field, sanitizer.Identifier(match[1]), domain.ConfidenceConfirmed))
	}
	return uniqueReferences(refs)
}

func composeReference(file string, node *yaml.Node, field, name string, confidence domain.Confidence) domain.Reference {
	return domain.Reference{Kind: domain.ReferenceComposeVariable, Name: name, Expression: "${" + name + "}", Evidence: evidence(file, node, field, "Compose variable reference", confidence)}
}

func uniqueReferences(refs []domain.Reference) []domain.Reference {
	byKey := make(map[string]domain.Reference)
	for _, ref := range refs {
		if ref.Name != "" {
			byKey[ref.Name+"\x00"+ref.Evidence.Field] = ref
		}
	}
	result := make([]domain.Reference, 0, len(byKey))
	for _, ref := range byKey {
		result = append(result, ref)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Name != result[j].Name {
			return result[i].Name < result[j].Name
		}
		return result[i].Evidence.Field < result[j].Evidence.Field
	})
	return result
}

func uniqueSignals(signals []domain.StructuralSignal) []domain.StructuralSignal {
	byKey := make(map[string]domain.StructuralSignal)
	for _, item := range signals {
		byKey[item.Kind+"\x00"+item.Evidence.Field] = item
	}
	result := make([]domain.StructuralSignal, 0, len(byKey))
	for _, item := range byKey {
		result = append(result, item)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Kind != result[j].Kind {
			return result[i].Kind < result[j].Kind
		}
		return result[i].Evidence.Field < result[j].Evidence.Field
	})
	return result
}

func looksCredential(name string) bool {
	lower := strings.ToLower(name)
	for _, marker := range []string{"secret", "token", "password", "passwd", "credential", "api_key", "access_key", "private_key"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func productionLike(name string, profiles []domain.NamedValue) bool {
	values := []string{name}
	for _, profile := range profiles {
		values = append(values, profile.Name)
	}
	for _, value := range values {
		lower := strings.ToLower(value)
		if strings.Contains(lower, "prod") || lower == "live" || strings.Contains(lower, "production") {
			return true
		}
	}
	return false
}

func explicitRootUser(user string) bool {
	user = strings.ToLower(strings.TrimSpace(user))
	return user == "0" || user == "root" || strings.HasPrefix(user, "0:") || strings.HasPrefix(user, "root:")
}

func scalarBool(node *yaml.Node) (bool, error) {
	value, err := strconv.ParseBool(strings.ToLower(node.Value))
	if err != nil {
		return false, errors.New("value must be true or false")
	}
	return value, nil
}

func evidence(file string, node *yaml.Node, field, description string, confidence domain.Confidence) domain.Evidence {
	location := domain.Location{Path: file}
	if node != nil {
		location.Line, location.Column = node.Line, node.Column
	}
	return domain.Evidence{Description: description, Location: location, Field: field, Source: parserSource, Confidence: confidence}
}

func composeSignal(file string, node *yaml.Node, field, kind, description string, confidence domain.Confidence) domain.StructuralSignal {
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
