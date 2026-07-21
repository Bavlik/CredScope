# Reporting

`credscope scan` now runs discovery, bounded parsing, graph construction, rule matching, scoring, remediation, and one selected reporter. All reporters consume the same immutable Phase 3 result and write only to a supplied `io.Writer`; they do not open files, access the network, or execute repository content.

## Formats

`terminal` is the default. It shows a severity summary, credentials ordered by descending score then identifier, reachability counts, bounded human-readable evidence paths, score contributions, recommendations, warnings, and policy versions. Evidence is ranked by security relevance and path length; bookkeeping endpoints and longer cyclic variants to the same component are omitted. The default shows at most 10 paths per credential and `--verbose` at most 40, with an exact count of additional relevant paths. `--verbose` also adds safe source evidence and remediation actions. `--quiet` removes non-essential headings and repository warning detail. Color is limited to severity labels and is disabled by `--no-color` or when stdout is not a character device.

`json` implements schema version `1`. Its stable top-level fields are `schema_version`, `tool`, `scan`, `policies`, `summary`, `credentials`, `graph`, `repository_warnings`, `parser_warnings`, and `non_fatal_errors`. To avoid repeating every path prefix, the report retains one deterministic shortest path for each reachable endpoint. Path edges reference canonical graph edge IDs and omit duplicated edge evidence; graph edges and matched rules retain that evidence. Rule and remediation path references are normalized to the retained paths. The complete normalized graph remains present, so no reachable component or relationship is discarded. See [report-schema-v1.json](report-schema-v1.json) and [the generated example](examples/credscope-report.json).

`sarif` emits SARIF 2.1.0 with one result for each actionable rule and credential. Zero-weight analysis warnings remain in JSON/terminal/HTML but are not uploaded as alerts. Results contain stable catalog descriptors, normalized repository-relative URIs, real line numbers only when available, related evidence locations, remediation text, policy properties, and a stable `credentialRule/v1` partial fingerprint. See [the generated example](examples/credscope.sarif).

`html` is one standalone offline document. It uses Go HTML template contextual escaping, no JavaScript, no external fonts or assets, and no analytics or network requests. A restrictive CSP allows only its embedded CSS. Native semantic landmarks, tables, and keyboard-accessible `details` elements support navigation. Each credential shows at most 20 highest-value paths with an exact omitted count. Graph tables are bounded to 300 nodes and 600 edges. See [the generated example](examples/credscope-report.html).

`mermaid` emits Markdown containing a credential score/rule summary and a `graph TD` block. Node identifiers are stable hashes; labels remove controls, URLs, directives, click syntax, quotes, and graph-breaking syntax. Identical source/relationship/target edges are emitted once even when the internal graph holds distinct evidence records. No `click` directive or external link is emitted. Output is bounded to 250 nodes and 500 edges with a visible summary warning. See [the generated example](examples/blast-radius.md).

All formats write to stdout when `--output` is omitted, including SARIF, HTML, and Mermaid. JSON, SARIF, HTML, and Mermaid are pretty-printed when written to a file; stdout JSON and SARIF are compact for pipelines.

## Thresholds

`minimum-score` filters actionable terminal display and threshold evaluation. Complete machine reports retain every credential analysis. `fail-on` selects the minimum severity that returns exit code 1. Both conditions must be met. `fail-on none` never returns exit code 1.

Accepted severities are `none`, `informational`, `low`, `medium`, `high`, and `critical`.

| Exit code | Meaning |
| ---: | --- |
| 0 | Analysis completed and the configured threshold was not exceeded |
| 1 | Analysis completed, the report was emitted, and the threshold was exceeded |
| 2 | Invalid command usage or configuration |
| 3 | Malformed or unsupported analysis input |
| 4 | Analysis or report generation/write failure |

## Secure file output

Reports are fully rendered in memory before publication. Relative output paths resolve from the analyzed repository root. Missing parent directories beneath that root are created component by component with owner-only permissions where supported. Existing symbolic links, Windows reparse points, non-directory parent components, root escape, parent traversal, directories used as the final target, and attempts to overwrite a discovered workflow, Compose file, selected configuration, or Gitleaks report are rejected. A newly created empty parent is removed after failed publication where practical; recursive cleanup is never used. File output uses an owner-only temporary file in the destination directory, flushes it, and publishes only after rendering succeeds. Existing regular reports are preserved until the staged replacement can be finalized.

For example, `credscope scan . --format html --output reports/credscope-report.html` safely creates `reports` inside the selected root when it does not exist.

An empty scan is successful and reports: “No credential blast-radius paths were identified from the available static evidence.” CredScope does not claim the repository is secure.
