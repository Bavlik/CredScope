# CredScope

> Map the blast radius of leaked credentials before attackers do.

CredScope is a deterministic security analysis tool that maps detected credential references to the workflows, services, permissions, environments, and infrastructure they may reach. It is offline-first, does not execute repository content, and is designed to compile into a single cross-platform executable.

> CredScope is a deterministic security analysis engine. It does not use LLMs, external AI APIs, telemetry, or cloud processing.

## Development status

The repository currently contains the completed Phase 1–4 implementation for `v0.1.0`: secure discovery and parsing, deterministic reachability analysis, rule catalog v1, scoring policy v1, remediation, the complete scan CLI, and terminal, JSON, SARIF, standalone HTML, and Mermaid reports. GitHub Action packaging, CI/release automation, community files, and the final release audit remain later phases.

## Current commands

```text
credscope scan [repository]
credscope version
credscope rules list
credscope explain CRD101
```

`scan` now executes the complete static pipeline and emits the selected report:

```bash
credscope scan testdata/vulnerable \
  --gitleaks-report gitleaks.json \
  --verbose
```

```bash
credscope scan . --format json --output credscope.json
credscope scan . --format sarif --output credscope.sarif --fail-on high
credscope scan . --format html --output credscope-report.html
credscope scan . --format mermaid --output blast-radius.md
```

All formats write to stdout when `--output` is omitted. File output is root-confined, staged, owner-only where supported, and refuses to overwrite detected analysis inputs.

Embedding example:

```go
parsed, err := credscope.ParseRepository(ctx, root, credscope.DefaultConfig(), gitleaksReport)
result, err := credscope.Analyze(ctx, parsed, credscope.AnalysisOptions{})
```

The result contains stable graph nodes and edges, credential evidence paths, matched rules, score breakdowns, confidence summaries, reachability counts, warnings, and deduplicated remediations. See [architecture](docs/architecture.md), [scoring policy v1](docs/scoring.md), and [rule catalog v1](docs/rules.md).

## Reports and CI thresholds

- Terminal: concise human report with optional safe `--verbose` evidence and automatic color detection.
- JSON: stable schema version 1 with full graph and credential analyses.
- SARIF: SARIF 2.1.0 with one deduplicated result per actionable rule and credential.
- HTML: standalone offline report with contextual escaping, CSP, responsive/print styles, and no JavaScript.
- Mermaid: bounded Markdown graph with stable safe IDs and sanitized labels.

`--minimum-score` controls terminal display and threshold eligibility. `--fail-on` controls the minimum failing severity. Exit code 1 is returned only when both conditions are met, after the report has been emitted. See [reporting](docs/reporting.md), [configuration](docs/configuration.md), and [safe examples](docs/examples/).

## Supported inputs

- Gitleaks JSON arrays and single finding objects. Raw `Secret` and `Match` values are consumed only to create irreversible fingerprints and are never returned.
- GitHub Actions workflows under `.github/workflows/*.yml` and `.yaml`.
- Root-level `docker-compose.yml`, `docker-compose.yaml`, `compose.yml`, and `compose.yaml` files.

See [input parsing](docs/inputs.md) for parsed fields, structural signals, security boundaries, and current limitations.

## Build and test

Go 1.26 or a supported newer release is required.

```bash
go mod download
go test ./...
go test -race ./...
go vet ./...
go build ./cmd/credscope
```

## Configuration

Copy `.credscope.yml.example` to `.credscope.yml` and adjust it as needed. CLI flags override configuration values, and configuration values override built-in defaults. Unknown YAML fields, unsupported versions, parent-directory traversal, invalid thresholds, and conflicting output modes are rejected.

## Security properties

- Secret-bearing domain fields do not exist; only labels and irreversible, domain-separated fingerprints are modeled.
- Terminal output strips ANSI and control characters from repository-controlled values.
- Discovery is confined to the selected root, does not follow symlinks, skips common generated directories, and rejects oversized supported inputs.
- Explicit inputs cannot traverse outside the repository root.
- Report writes are root-confined, reject symlinks, use temporary files, and request owner-only permissions.
- Configuration input is size-limited, single-document, and decoded with strict known-field checking.
- YAML inputs are single-document and bounded by file size, scalar size, depth, node count, alias count, and duplicate-key checks.
- Shell commands, workflows, reusable workflows, Compose services, env files, and containers are never executed or resolved over the network.
- Literal environment values and shell bodies are represented by fingerprints and redacted structure rather than retained verbatim.
- Graph and path traversal is deterministic, cycle-safe, and depth-limited.
- Scores use documented rule weights and confidence multipliers; Unknown runtime conditions contribute no points.
- Recommendations are advisory and never modify analyzed files.
- Every reporter consumes the same immutable analysis model and performs no network or process execution.
- HTML is standalone and escaped; Mermaid directives and external links from repository content are suppressed.
- Report output cannot replace discovered workflows, Compose files, configuration, or the selected Gitleaks report.

See [configuration documentation](docs/configuration.md) and the [foundation security model](docs/security-model.md).

## License

The final open-source license and community files are scheduled for the productization phase; the repository is not ready for public redistribution until that phase is complete.
