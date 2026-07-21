// Package mermaid renders a bounded, injection-resistant Markdown graph.
package mermaid

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"

	"github.com/credscope/credscope/internal/domain"
	"github.com/credscope/credscope/internal/reporters"
	"github.com/credscope/credscope/internal/sanitizer"
)

const (
	MaxNodes = 250
	MaxEdges = 500
)

type Reporter struct{}

func New() Reporter                               { return Reporter{} }
func (Reporter) Name() string                     { return "mermaid" }
func (Reporter) Validate(reporters.Options) error { return nil }

func (Reporter) Render(writer io.Writer, input reporters.Input, _ reporters.Options) error {
	fmt.Fprintln(writer, "# CredScope blast-radius graph")
	fmt.Fprintf(writer, "\nRepository: `%s`\n\nScoring policy: `%s`\n\nRule catalog: `%s`\n", markdown(input.Scan.Repository), markdown(input.Analysis.PolicyVersion), markdown(input.Analysis.RuleCatalogVersion))
	credentials := reporters.OrderedCredentials(input, false)
	if len(credentials) > 0 {
		fmt.Fprintln(writer, "\n## Credential summary\n\n| Credential | Score | Severity | Matched rules |\n| --- | ---: | --- | --- |")
		for _, credential := range credentials {
			ruleIDs := make([]string, 0, len(credential.MatchedRules))
			for _, match := range credential.MatchedRules {
				ruleIDs = append(ruleIDs, match.RuleID)
			}
			sort.Strings(ruleIDs)
			fmt.Fprintf(writer, "| %s | %d/100 | %s | %s |\n", markdown(credential.Credential.Label), credential.Score, markdown(string(credential.Severity)), strings.Join(ruleIDs, ", "))
		}
	}
	nodes := append([]domain.Node{}, input.Analysis.Graph.Nodes...)
	sort.Slice(nodes, func(i, j int) bool {
		if nodes[i].Type == domain.NodeCredential && nodes[j].Type != domain.NodeCredential {
			return true
		}
		if nodes[j].Type == domain.NodeCredential && nodes[i].Type != domain.NodeCredential {
			return false
		}
		return nodes[i].ID < nodes[j].ID
	})
	truncatedNodes := len(nodes) > MaxNodes
	if truncatedNodes {
		nodes = nodes[:MaxNodes]
	}
	included := make(map[string]bool, len(nodes))
	for _, node := range nodes {
		included[node.ID] = true
	}
	edgesByRelationship := make(map[string]domain.Edge)
	for _, edge := range input.Analysis.Graph.Edges {
		if included[edge.From] && included[edge.To] {
			key := edge.From + "\x00" + string(edge.Type) + "\x00" + edge.To
			if current, exists := edgesByRelationship[key]; !exists || edge.ID < current.ID {
				edgesByRelationship[key] = edge
			}
		}
	}
	edges := make([]domain.Edge, 0, len(edgesByRelationship))
	for _, edge := range edgesByRelationship {
		edges = append(edges, edge)
	}
	sort.Slice(edges, func(i, j int) bool { return edges[i].ID < edges[j].ID })
	truncatedEdges := len(edges) > MaxEdges
	if truncatedEdges {
		edges = edges[:MaxEdges]
	}
	if truncatedNodes || truncatedEdges {
		fmt.Fprintf(writer, "\n> Graph summarized at %d nodes and %d edges. The complete graph remains available in the analysis model.\n", len(nodes), len(edges))
	}
	fmt.Fprintln(writer, "\n```mermaid")
	fmt.Fprintln(writer, "graph TD")
	if len(nodes) == 0 {
		fmt.Fprintln(writer, "    empty_graph[\"No graph nodes\"]")
	} else {
		for _, node := range nodes {
			fmt.Fprintf(writer, "    %s[\"%s\"]\n", nodeID(node.ID), label(node.Label))
		}
		if truncatedNodes || truncatedEdges {
			fmt.Fprintln(writer, "    %% Graph bounded by CredScope policy; no external links are emitted.")
		}
		for _, edge := range edges {
			fmt.Fprintf(writer, "    %s -->|%s| %s\n", nodeID(edge.From), string(edge.Type), nodeID(edge.To))
		}
	}
	fmt.Fprintln(writer, "```")
	return nil
}

func nodeID(value string) string {
	sum := sha256.Sum256([]byte("credscope:mermaid-node:v1\x00" + value))
	return "n_" + hex.EncodeToString(sum[:8])
}

func label(value string) string {
	value = sanitizer.TerminalText(value)
	value = truncateRunes(value, 240)
	replacer := strings.NewReplacer("&", "&amp;", "\"", "&quot;", "<", "&lt;", ">", "&gt;", "`", "'", "%", "&#37;", "{", "&#123;", "}", "&#125;", "[", "&#91;", "]", "&#93;", "\\", "/", "-->", "—")
	return stripDirectives(replacer.Replace(value))
}

func truncateRunes(value string, limit int) string {
	runes := []rune(value)
	if len(runes) <= limit {
		return value
	}
	return string(runes[:limit-1]) + "…"
}

func markdown(value string) string {
	value = sanitizer.TerminalText(value)
	replacer := strings.NewReplacer("`", "'", "[", "(", "]", ")", "<", "(", ">", ")", "\\", "/", "%", "", "|", "/")
	return stripDirectives(replacer.Replace(value))
}

func stripDirectives(value string) string {
	return directivePattern.ReplaceAllStringFunc(value, func(match string) string {
		lower := strings.ToLower(match)
		if strings.HasSuffix(lower, "://") {
			return "redacted-url/"
		}
		if lower == "click" {
			return "directive"
		}
		return "operation"
	})
}

var directivePattern = regexp.MustCompile(`(?i)https?://|click|action`)
