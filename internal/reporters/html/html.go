// Package html renders a standalone, offline, auto-escaped HTML report.
package html

import (
	"fmt"
	"html/template"
	"io"
	"sort"
	"strings"

	"github.com/Bavlik/CredScope/internal/domain"
	"github.com/Bavlik/CredScope/internal/reporters"
	"github.com/Bavlik/CredScope/internal/sanitizer"
)

const maxGraphNodes, maxGraphEdges = 300, 600

type Reporter struct{}

func New() Reporter                               { return Reporter{} }
func (Reporter) Name() string                     { return "html" }
func (Reporter) Validate(reporters.Options) error { return nil }

type page struct {
	ToolName, ToolVersion, Repository, Started, Completed, Policy, Catalog, Profile, ProfileReason, ProfileAssumptions string
	Summary                                                                                                            reporters.Summary
	Credentials                                                                                                        []credential
	Warnings                                                                                                           []string
	Nodes                                                                                                              []graphNode
	Edges                                                                                                              []graphEdge
	GraphNote                                                                                                          string
	IgnoredCount                                                                                                       int
}
type credential struct {
	Label, Severity, Confidence, Classification, ClassificationConfidence, ClassificationReason string
	Score                                                                                       int
	Reachable                                                                                   domain.ReachableCounts
	Paths                                                                                       []string
	PathsOmitted                                                                                int
	Contributions                                                                               []contribution
	Remediations                                                                                []remediation
	Warnings                                                                                    []string
}
type contribution struct {
	Points                                     int
	RuleID, Description, Confidence, Condition string
	ProfileChanged                             bool
}
type remediation struct {
	ID, Title, Why, Action, Confidence string
	Priority                           int
}
type graphNode struct{ ID, Type, Label string }
type graphEdge struct{ ID, From, To, Relationship, EvidenceKind string }

func (Reporter) Render(writer io.Writer, input reporters.Input, _ reporters.Options) error {
	data := page{ToolName: safe(input.Tool.Name), ToolVersion: safe(input.Tool.Version), Repository: safe(input.Scan.Repository), Started: input.Scan.StartedAt.UTC().Format("2006-01-02T15:04:05Z07:00"), Completed: input.Scan.CompletedAt.UTC().Format("2006-01-02T15:04:05Z07:00"), Policy: safe(input.Analysis.PolicyVersion), Catalog: safe(input.Analysis.RuleCatalogVersion), Profile: safe(string(input.Analysis.Profile.Selected)), ProfileReason: safe(input.Analysis.Profile.Reason), ProfileAssumptions: strings.Join(safeStrings(input.Analysis.Profile.Assumptions), "; "), Summary: reporters.Summarize(input), IgnoredCount: input.Analysis.IgnoredCount}
	for _, item := range reporters.OrderedCredentials(input, false) {
		selection := reporters.SelectEvidencePaths(input.Analysis.Graph, item.EvidencePaths, reporters.HTMLEvidencePathLimit)
		view := credential{Label: safe(item.Credential.Label), Severity: strings.ToUpper(safe(string(item.Severity))), Confidence: title(string(item.Confidence.Overall)), Classification: safe(string(item.Credential.Classification)), ClassificationConfidence: title(string(item.Credential.ClassificationConfidence)), ClassificationReason: safe(item.Credential.ClassificationReason), Score: item.Score, Reachable: item.Reachable, Warnings: safeStrings(item.Warnings), Paths: htmlPaths(selection.Paths), PathsOmitted: selection.Omitted}
		for _, factor := range item.Contributions {
			view.Contributions = append(view.Contributions, contribution{Points: factor.FinalContribution, RuleID: safe(factor.RuleID), Description: safe(factor.Description), Confidence: title(string(factor.Confidence)), Condition: safe(factor.ConditionStatus), ProfileChanged: factor.ProfileChanged})
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
		data.Nodes = append(data.Nodes, graphNode{safe(node.ID), safe(string(node.Type)), safe(node.Label)})
	}
	for _, edge := range input.Analysis.Graph.Edges {
		if len(data.Edges) >= maxGraphEdges {
			break
		}
		if included[edge.From] && included[edge.To] {
			data.Edges = append(data.Edges, graphEdge{safe(edge.ID), safe(edge.From), safe(edge.To), safe(string(edge.Type)), safe(string(edge.EvidenceKind))})
		}
	}
	if len(input.Analysis.Graph.Nodes) > len(data.Nodes) || len(input.Analysis.Graph.Edges) > len(data.Edges) {
		data.GraphNote = fmt.Sprintf("Graph table was bounded to %d nodes and %d edges; the analysis model retains the complete graph.", len(data.Nodes), len(data.Edges))
	}
	return reportTemplate.Execute(writer, data)
}

func htmlPaths(paths []domain.EvidencePath) []string {
	var result []string
	for _, p := range paths {
		if len(p.Nodes) < 2 {
			continue
		}
		labels := make([]string, 0, len(p.Nodes))
		for _, node := range p.Nodes {
			labels = append(labels, safe(node.Label))
		}
		result = append(result, strings.Join(labels, " → ")+" ["+safe(string(p.EvidenceKind))+"]")
	}
	return result
}
func safeStrings(items []string) []string {
	result := make([]string, len(items))
	for i, item := range items {
		result[i] = safe(item)
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
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'">
<title>CredScope static analysis</title><style>
:root{color-scheme:light dark;--bg:#f7f7f8;--panel:#fff;--text:#17202a;--muted:#5f6b76;--line:#d8dde3;--accent:#315efb} @media(prefers-color-scheme:dark){:root{--bg:#101216;--panel:#181c22;--text:#eef2f5;--muted:#a8b2bd;--line:#343b45;--accent:#8ca6ff}} *{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.55 system-ui,sans-serif}header,main,footer{max-width:1180px;margin:auto;padding:24px}h1,h2,h3{line-height:1.2}.muted{color:var(--muted)}.notice{border-left:4px solid var(--accent);padding:12px 16px;background:var(--panel)}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}.card,.credential{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:18px;margin:14px 0}.metric{font-size:1.8rem;font-weight:700}.score{font-size:2.2rem;font-weight:750;color:var(--accent)}table{width:100%;border-collapse:collapse;display:block;overflow:auto}th,td{text-align:left;padding:8px;border-bottom:1px solid var(--line);vertical-align:top}code{overflow-wrap:anywhere}details{margin:10px 0}summary{cursor:pointer;font-weight:650}.pill{display:inline-block;border:1px solid var(--line);border-radius:999px;padding:2px 9px;margin:2px}@media(max-width:600px){header,main,footer{padding:14px}.credential{padding:13px}}
</style></head><body><header><h1>CredScope static analysis</h1><p class="muted">{{.ToolName}} {{.ToolVersion}} · Repository {{.Repository}} · Scoring {{.Policy}} · Rules {{.Catalog}}</p><p>Environment profile: <strong>{{.Profile}}</strong> — {{.ProfileReason}}</p><p>Profile assumptions: {{.ProfileAssumptions}}</p></header><main>
<section class="notice"><h2>Limitations</h2><p>CredScope performs deterministic static analysis. It does not validate whether credentials are active, execute repository content, prove runtime data flow, prove external network exposure, replace secret scanners, or provide complete vulnerability scanning.</p></section>
<section><h2>Summary</h2><div class="grid"><div class="card"><div class="metric">{{.Summary.CredentialCount}}</div>Items analyzed</div><div class="card"><div class="metric">{{.Summary.HighestScore}}</div>Highest risk score</div><div class="card"><div class="metric">{{.Summary.Critical}}</div>Critical</div><div class="card"><div class="metric">{{.Summary.High}}</div>High</div><div class="card"><div class="metric">{{.IgnoredCount}}</div>Ignored</div></div><p>Severity thresholds: 0–19 Informational; 20–39 Low; 40–59 Medium; 60–79 High; 80–100 Critical.</p></section>
<section><h2>Analyzed items</h2>{{if not .Credentials}}<p>No credential or configuration references were identified.</p>{{end}}{{range .Credentials}}<article class="credential"><h3>{{.Severity}} — {{.Label}}</h3><div class="score">Risk {{.Score}}/100</div><p><span class="pill">Evidence confidence {{.Confidence}}</span><span class="pill">Classification {{.Classification}}</span><span class="pill">Classification confidence {{.ClassificationConfidence}}</span></p><p>{{.ClassificationReason}}</p><details><summary>Risk score breakdown</summary><table><thead><tr><th>Risk points</th><th>Rule</th><th>Condition</th><th>Evidence confidence</th><th>Profile changed risk</th></tr></thead><tbody>{{range .Contributions}}<tr><td>+{{.Points}}</td><td>{{.RuleID}} — {{.Description}}</td><td>{{.Condition}}</td><td>{{.Confidence}}</td><td>{{.ProfileChanged}}</td></tr>{{end}}</tbody></table></details><details><summary>Static evidence paths</summary><ul>{{range .Paths}}<li><code>{{.}}</code></li>{{else}}<li>No path details.</li>{{end}}</ul>{{if .PathsOmitted}}<p>{{.PathsOmitted}} additional relevant paths omitted.</p>{{end}}</details><details><summary>Recommended actions</summary><ol>{{range .Remediations}}<li><strong>{{.Title}}</strong> ({{.ID}})<br>{{.Why}}<br>{{.Action}}</li>{{else}}<li>No rule-based recommendation was triggered.</li>{{end}}</ol></details></article>{{end}}</section>
<section><h2>Typed graph</h2><p>Confirmed data-flow edges and inferred exposure context are distinct from network topology. Topology edges do not claim credential transmission.</p>{{if .GraphNote}}<p>{{.GraphNote}}</p>{{end}}<details><summary>Nodes ({{len .Nodes}})</summary><table><tr><th>ID</th><th>Type</th><th>Label</th></tr>{{range .Nodes}}<tr><td><code>{{.ID}}</code></td><td>{{.Type}}</td><td>{{.Label}}</td></tr>{{end}}</table></details><details><summary>Edges ({{len .Edges}})</summary><table><tr><th>From</th><th>Relationship</th><th>Evidence kind</th><th>To</th></tr>{{range .Edges}}<tr><td><code>{{.From}}</code></td><td>{{.Relationship}}</td><td>{{.EvidenceKind}}</td><td><code>{{.To}}</code></td></tr>{{end}}</table></details></section>
{{if .Warnings}}<section><h2>Repository warnings</h2><ul>{{range .Warnings}}<li>{{.}}</li>{{end}}</ul></section>{{end}}</main><footer><p>Generated fully offline; no external scripts, styles, fonts, or network requests are used.</p></footer></body></html>`))
