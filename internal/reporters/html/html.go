// Package html renders a standalone, offline, auto-escaped HTML report.
package html

import (
	"fmt"
	"html/template"
	"io"
	"sort"
	"strings"

	"github.com/credscope/credscope/internal/domain"
	"github.com/credscope/credscope/internal/reporters"
	"github.com/credscope/credscope/internal/sanitizer"
)

const maxGraphNodes = 300
const maxGraphEdges = 600

type Reporter struct{}

func New() Reporter                               { return Reporter{} }
func (Reporter) Name() string                     { return "html" }
func (Reporter) Validate(reporters.Options) error { return nil }

type page struct {
	ToolName, ToolVersion, Repository, Started, Completed, Policy, Catalog string
	Summary                                                                reporters.Summary
	Credentials                                                            []credential
	Warnings                                                               []string
	Nodes                                                                  []graphNode
	Edges                                                                  []graphEdge
	GraphNote                                                              string
}
type credential struct {
	Label, Severity, Confidence string
	Score                       int
	Reachable                   domain.ReachableCounts
	Paths                       []string
	PathsOmitted                int
	Contributions               []contribution
	Remediations                []remediation
	Warnings                    []string
}
type contribution struct {
	Points                          int
	RuleID, Description, Confidence string
}
type remediation struct {
	ID, Title, Why, Action, Confidence string
	Priority                           int
}
type graphNode struct{ ID, Type, Label string }
type graphEdge struct{ ID, From, To, Relationship string }

func (Reporter) Render(writer io.Writer, input reporters.Input, _ reporters.Options) error {
	data := page{ToolName: safe(input.Tool.Name), ToolVersion: safe(input.Tool.Version), Repository: safe(input.Scan.Repository), Started: input.Scan.StartedAt.UTC().Format("2006-01-02T15:04:05Z07:00"), Completed: input.Scan.CompletedAt.UTC().Format("2006-01-02T15:04:05Z07:00"), Policy: safe(input.Analysis.PolicyVersion), Catalog: safe(input.Analysis.RuleCatalogVersion), Summary: reporters.Summarize(input)}
	for _, item := range reporters.OrderedCredentials(input, false) {
		selection := reporters.SelectEvidencePaths(input.Analysis.Graph, item.EvidencePaths, reporters.HTMLEvidencePathLimit)
		view := credential{Label: safe(item.Credential.Label), Severity: strings.ToUpper(safe(string(item.Severity))), Confidence: title(string(item.Confidence.Overall)), Score: item.Score, Reachable: item.Reachable, Warnings: safeStrings(item.Warnings), Paths: htmlPaths(selection.Paths), PathsOmitted: selection.Omitted}
		for _, factor := range item.Contributions {
			view.Contributions = append(view.Contributions, contribution{Points: factor.FinalContribution, RuleID: safe(factor.RuleID), Description: safe(factor.Description), Confidence: title(string(factor.Confidence))})
		}
		for _, action := range item.Remediations {
			view.Remediations = append(view.Remediations, remediation{ID: safe(action.ID), Title: safe(action.Title), Why: safe(action.Why), Action: safe(action.SuggestedAction), Confidence: title(string(action.Confidence)), Priority: action.Priority})
		}
		data.Credentials = append(data.Credentials, view)
	}
	data.Warnings = safeStrings(input.Analysis.Warnings)
	for _, warning := range input.ParserWarnings {
		data.Warnings = append(data.Warnings, safe(warning.Code+": "+warning.Message))
	}
	data.Warnings = append(data.Warnings, safeStrings(input.NonFatalErrors)...)
	sort.Strings(data.Warnings)
	nodeLimit := len(input.Analysis.Graph.Nodes)
	if nodeLimit > maxGraphNodes {
		nodeLimit = maxGraphNodes
	}
	included := make(map[string]bool, nodeLimit)
	for _, node := range input.Analysis.Graph.Nodes[:nodeLimit] {
		included[node.ID] = true
		data.Nodes = append(data.Nodes, graphNode{ID: safe(node.ID), Type: safe(string(node.Type)), Label: safe(node.Label)})
	}
	for _, edge := range input.Analysis.Graph.Edges {
		if len(data.Edges) >= maxGraphEdges {
			break
		}
		if included[edge.From] && included[edge.To] {
			data.Edges = append(data.Edges, graphEdge{ID: safe(edge.ID), From: safe(edge.From), To: safe(edge.To), Relationship: safe(string(edge.Type))})
		}
	}
	if len(input.Analysis.Graph.Nodes) > len(data.Nodes) || len(input.Analysis.Graph.Edges) > len(data.Edges) {
		data.GraphNote = fmt.Sprintf("Graph table was bounded to %d nodes and %d edges; the analysis model retains the complete graph.", len(data.Nodes), len(data.Edges))
	}
	return reportTemplate.Execute(writer, data)
}

func htmlPaths(paths []domain.EvidencePath) []string {
	result := make([]string, 0, len(paths))
	for _, path := range paths {
		if len(path.Nodes) < 2 {
			continue
		}
		labels := make([]string, 0, len(path.Nodes))
		for _, node := range path.Nodes {
			labels = append(labels, safe(node.Label))
		}
		result = append(result, strings.Join(labels, " → "))
	}
	return result
}

func safeStrings(items []string) []string {
	result := make([]string, len(items))
	for index, item := range items {
		result[index] = safe(item)
	}
	return result
}
func safe(value string) string { return sanitizer.TerminalText(value) }
func title(value string) string {
	value = safe(value)
	if value == "" {
		return "Unknown"
	}
	return strings.ToUpper(value[:1]) + value[1:]
}

var reportTemplate = template.Must(template.New("report").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'">
<title>CredScope security analysis</title>
<style>
:root{color-scheme:light dark;--bg:#f7f7f8;--panel:#fff;--text:#17202a;--muted:#5f6b76;--line:#d8dde3;--accent:#315efb} @media(prefers-color-scheme:dark){:root{--bg:#101216;--panel:#181c22;--text:#eef2f5;--muted:#a8b2bd;--line:#343b45;--accent:#8ca6ff}} *{box-sizing:border-box} body{margin:0;background:var(--bg);color:var(--text);font:15px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif} header,main,footer{max-width:1180px;margin:auto;padding:24px} h1,h2,h3{line-height:1.2} .muted{color:var(--muted)} .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}.card,.credential{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:18px;margin:14px 0}.metric{font-size:1.8rem;font-weight:700}.score{font-size:2.2rem;font-weight:750;color:var(--accent)} table{width:100%;border-collapse:collapse;display:block;overflow:auto} th,td{text-align:left;padding:8px;border-bottom:1px solid var(--line);vertical-align:top} code{overflow-wrap:anywhere} details{margin:10px 0} summary{cursor:pointer;font-weight:650} ol,ul{padding-left:24px}.pill{display:inline-block;border:1px solid var(--line);border-radius:999px;padding:2px 9px;margin-right:5px}@media(max-width:600px){header,main,footer{padding:14px}.credential{padding:13px}}@media print{body{background:#fff;color:#000}.card,.credential{break-inside:avoid;border-color:#aaa}details{display:block}details>summary{display:none}}
</style>
</head>
<body>
<header><h1>CredScope security analysis</h1><p class="muted">{{.ToolName}} {{.ToolVersion}} · Repository {{.Repository}} · Scoring {{.Policy}} · Rules {{.Catalog}}</p><p class="muted">Scan {{.Started}} – {{.Completed}}</p></header>
<main>
<section aria-labelledby="summary"><h2 id="summary">Summary</h2><div class="grid"><div class="card"><div class="metric">{{.Summary.CredentialCount}}</div>Credentials</div><div class="card"><div class="metric">{{.Summary.HighestScore}}</div>Highest score</div><div class="card"><div class="metric">{{.Summary.Critical}}</div>Critical</div><div class="card"><div class="metric">{{.Summary.High}}</div>High</div><div class="card"><div class="metric">{{.Summary.Medium}}</div>Medium</div></div></section>
<section aria-labelledby="credentials"><h2 id="credentials">Credential analyses</h2>{{if not .Credentials}}<p>No credential blast-radius paths were identified from the available static evidence.</p>{{end}}{{range .Credentials}}<article class="credential"><h3>{{.Severity}} — {{.Label}}</h3><div class="score">{{.Score}}/100</div><p><span class="pill">Confidence {{.Confidence}}</span><span class="pill">Workflows {{.Reachable.Workflows}}</span><span class="pill">Jobs {{.Reachable.Jobs}}</span><span class="pill">Services {{.Reachable.Services}}</span></p><details><summary>Score breakdown</summary><table><thead><tr><th>Points</th><th>Rule</th><th>Description</th><th>Confidence</th></tr></thead><tbody>{{range .Contributions}}<tr><td>+{{.Points}}</td><td>{{.RuleID}}</td><td>{{.Description}}</td><td>{{.Confidence}}</td></tr>{{end}}</tbody></table></details><details><summary>Highest-value evidence paths</summary><ul>{{range .Paths}}<li><code>{{.}}</code></li>{{else}}<li>No reachable path details.</li>{{end}}</ul>{{if .PathsOmitted}}<p class="muted">{{.PathsOmitted}} additional relevant paths are omitted from this view. The bounded graph table below retains the corresponding components and relationships.</p>{{end}}</details><details open><summary>Recommended actions</summary><ol>{{range .Remediations}}<li><strong>{{.Title}}</strong> ({{.ID}}, priority {{.Priority}}, {{.Confidence}})<br>{{.Why}}<br>{{.Action}}</li>{{else}}<li>No rule-based recommendation was triggered.</li>{{end}}</ol></details>{{if .Warnings}}<details><summary>Limitations</summary><ul>{{range .Warnings}}<li>{{.}}</li>{{end}}</ul></details>{{end}}</article>{{end}}</section>
<section aria-labelledby="graph"><h2 id="graph">Static reachability graph</h2>{{if .GraphNote}}<p>{{.GraphNote}}</p>{{end}}<details><summary>Nodes ({{len .Nodes}})</summary><table><thead><tr><th>ID</th><th>Type</th><th>Label</th></tr></thead><tbody>{{range .Nodes}}<tr><td><code>{{.ID}}</code></td><td>{{.Type}}</td><td>{{.Label}}</td></tr>{{end}}</tbody></table></details><details><summary>Edges ({{len .Edges}})</summary><table><thead><tr><th>From</th><th>Relationship</th><th>To</th></tr></thead><tbody>{{range .Edges}}<tr><td><code>{{.From}}</code></td><td>{{.Relationship}}</td><td><code>{{.To}}</code></td></tr>{{end}}</tbody></table></details></section>
{{if .Warnings}}<section aria-labelledby="warnings"><h2 id="warnings">Repository warnings</h2><ul>{{range .Warnings}}<li>{{.}}</li>{{end}}</ul></section>{{end}}
</main><footer><p>Static evidence only. CredScope does not validate credentials, inspect cloud IAM, or confirm external network exposure.</p></footer>
</body></html>
`))
