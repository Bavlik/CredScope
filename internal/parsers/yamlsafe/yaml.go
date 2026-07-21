// Package yamlsafe decodes bounded YAML documents and rejects abusive graphs.
package yamlsafe

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"

	"github.com/credscope/credscope/internal/discovery"
	"github.com/credscope/credscope/internal/input"
	"github.com/credscope/credscope/internal/sanitizer"
	"go.yaml.in/yaml/v3"
)

const (
	MaxDepth       = 64
	MaxNodes       = 100000
	MaxAliases     = 50
	MaxScalarBytes = 1 << 20
)

type ErrorKind string

const (
	ErrorMalformed  ErrorKind = "malformed_yaml"
	ErrorStructure  ErrorKind = "invalid_yaml_structure"
	ErrorComplexity ErrorKind = "yaml_complexity_limit"
)

type ParseError struct {
	Kind ErrorKind
	Path string
	Line int
	Msg  string
}

func (e *ParseError) Error() string {
	location := e.Path
	if e.Line > 0 {
		location += ":" + strconv.Itoa(e.Line)
	}
	return fmt.Sprintf("%s: %s: %s", e.Kind, location, e.Msg)
}

func Parse(root, file string) (*yaml.Node, string, error) {
	data, rel, err := input.ReadFile(root, file, discovery.DefaultMaxFileSize)
	if err != nil {
		return nil, "", &ParseError{Kind: ErrorStructure, Path: safePath(file), Msg: err.Error()}
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil {
		return nil, rel, &ParseError{Kind: ErrorMalformed, Path: rel, Line: yamlErrorLine(err), Msg: "invalid YAML syntax"}
	}
	if len(document.Content) == 0 {
		return nil, rel, &ParseError{Kind: ErrorStructure, Path: rel, Msg: "document is empty"}
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, rel, &ParseError{Kind: ErrorStructure, Path: rel, Msg: "multiple YAML documents are not allowed"}
	}
	state := validationState{active: make(map[*yaml.Node]bool)}
	if err := state.validate(&document, 0); err != nil {
		kind := state.kind
		if kind == "" {
			kind = ErrorComplexity
		}
		return nil, rel, &ParseError{Kind: kind, Path: rel, Line: state.line, Msg: err.Error()}
	}
	return &document, rel, nil
}

type validationState struct {
	nodes   int
	aliases int
	line    int
	kind    ErrorKind
	active  map[*yaml.Node]bool
}

func (s *validationState) validate(node *yaml.Node, depth int) error {
	if node == nil {
		return nil
	}
	if depth > MaxDepth {
		s.line = node.Line
		return fmt.Errorf("nesting exceeds %d levels", MaxDepth)
	}
	s.nodes++
	if s.nodes > MaxNodes {
		s.line = node.Line
		return fmt.Errorf("document exceeds %d nodes", MaxNodes)
	}
	if len(node.Value) > MaxScalarBytes {
		s.line = node.Line
		return fmt.Errorf("scalar exceeds %d bytes", MaxScalarBytes)
	}
	if node.Kind == yaml.AliasNode {
		s.aliases++
		if s.aliases > MaxAliases {
			s.line = node.Line
			return fmt.Errorf("document exceeds %d aliases", MaxAliases)
		}
		if node.Alias == nil {
			s.line = node.Line
			return errors.New("alias has no target")
		}
		if s.active[node.Alias] {
			s.line = node.Line
			return errors.New("cyclic YAML alias")
		}
		return nil
	}
	if node.Kind == yaml.MappingNode {
		if len(node.Content)%2 != 0 {
			s.line, s.kind = node.Line, ErrorStructure
			return errors.New("mapping has an unmatched key")
		}
		keys := make(map[string]struct{}, len(node.Content)/2)
		for index := 0; index < len(node.Content); index += 2 {
			key := node.Content[index]
			if key.Kind != yaml.ScalarNode {
				s.line, s.kind = key.Line, ErrorStructure
				return errors.New("mapping keys must be scalars")
			}
			if _, exists := keys[key.Value]; exists {
				s.line, s.kind = key.Line, ErrorStructure
				return errors.New("duplicate mapping key")
			}
			keys[key.Value] = struct{}{}
		}
	}
	s.active[node] = true
	defer delete(s.active, node)
	for _, child := range node.Content {
		if err := s.validate(child, depth+1); err != nil {
			return err
		}
	}
	return nil
}

func Dereference(node *yaml.Node) (*yaml.Node, error) {
	seen := make(map[*yaml.Node]bool)
	for node != nil && node.Kind == yaml.AliasNode {
		if node.Alias == nil || seen[node] {
			return nil, errors.New("invalid or cyclic YAML alias")
		}
		seen[node] = true
		node = node.Alias
	}
	return node, nil
}

func DocumentRoot(document *yaml.Node) (*yaml.Node, error) {
	if document == nil || document.Kind != yaml.DocumentNode || len(document.Content) != 1 {
		return nil, errors.New("expected one YAML document root")
	}
	return Dereference(document.Content[0])
}

func MappingValue(mapping *yaml.Node, key string) (*yaml.Node, bool, error) {
	entries, err := MappingEntries(mapping)
	if err != nil {
		return nil, false, err
	}
	for _, entry := range entries {
		if entry[0].Value == key {
			return entry[1], true, nil
		}
	}
	return nil, false, nil
}

func MappingEntries(mapping *yaml.Node) ([][2]*yaml.Node, error) {
	mapping, err := Dereference(mapping)
	if err != nil {
		return nil, err
	}
	if mapping == nil || mapping.Kind != yaml.MappingNode || len(mapping.Content)%2 != 0 {
		return nil, errors.New("expected a YAML mapping")
	}
	byKey := make(map[string][2]*yaml.Node, len(mapping.Content)/2)
	// YAML merge keys provide defaults. Explicit keys below always override them.
	for i := 0; i < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value != "<<" {
			continue
		}
		value, err := Dereference(mapping.Content[i+1])
		if err != nil {
			return nil, err
		}
		mergeNodes := []*yaml.Node{value}
		if value.Kind == yaml.SequenceNode {
			mergeNodes = value.Content
		}
		for _, mergeNode := range mergeNodes {
			merged, err := MappingEntries(mergeNode)
			if err != nil {
				return nil, fmt.Errorf("invalid YAML merge: %w", err)
			}
			for _, entry := range merged {
				if _, exists := byKey[entry[0].Value]; !exists {
					byKey[entry[0].Value] = entry
				}
			}
		}
	}
	for i := 0; i < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == "<<" {
			continue
		}
		value, err := Dereference(mapping.Content[i+1])
		if err != nil {
			return nil, err
		}
		byKey[mapping.Content[i].Value] = [2]*yaml.Node{mapping.Content[i], value}
	}
	keys := make([]string, 0, len(byKey))
	for key := range byKey {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	entries := make([][2]*yaml.Node, 0, len(keys))
	for _, key := range keys {
		entries = append(entries, byKey[key])
	}
	return entries, nil
}

var linePattern = regexp.MustCompile(`line ([0-9]+)`) // parser text is not returned

func yamlErrorLine(err error) int {
	match := linePattern.FindStringSubmatch(err.Error())
	if len(match) != 2 {
		return 0
	}
	line, _ := strconv.Atoi(match[1])
	return line
}

func safePath(path string) string {
	if path == "" {
		return "input"
	}
	return sanitizer.TerminalText(path)
}
