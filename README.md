# CredScope

> Map the blast radius of leaked credentials before attackers do.

CredScope is a deterministic security analysis tool that maps detected credential references to the workflows, services, permissions, environments, and infrastructure they may reach. It is offline-first, does not execute repository content, and is designed to compile into a single cross-platform executable.

> CredScope is a deterministic security analysis engine. It does not use LLMs, external AI APIs, telemetry, or cloud processing.

## Development status

The repository currently contains the completed Phase 1 foundation, Phase 2 input layer, and Phase 3 deterministic analysis core for `v0.1.0`: secure discovery and parsing, a credential reachability graph, evidence-path traversal, rule catalog v1, scoring policy v1, explicit confidence, and rule-based remediation. Security report formats remain a later phase and are not represented as complete here.

## Current commands

```text
credscope scan [repository]
credscope version
credscope rules list
credscope explain CRD101
```

At this phase, `scan` securely discovers and validates supported repository inputs, then prints an input inventory. With `--verbose`, it also prints parser counts. The analysis core is available to Go embedders through `pkg/credscope`; CLI reporting is intentionally deferred to Phase 4.

```bash
credscope scan testdata/vulnerable \
  --gitleaks-report gitleaks.json \
  --verbose
```

Only terminal inventory output is currently available. The reserved JSON, SARIF, HTML, and Mermaid formats return an explicit unsupported-format error until the reporting phase is implemented.

Embedding example:

```go
parsed, err := credscope.ParseRepository(ctx, root, credscope.DefaultConfig(), gitleaksReport)
result, err := credscope.Analyze(ctx, parsed, credscope.AnalysisOptions{})
```

The result contains stable graph nodes and edges, credential evidence paths, matched rules, score breakdowns, confidence summaries, reachability counts, warnings, and deduplicated remediations. See [architecture](docs/architecture.md), [scoring policy v1](docs/scoring.md), and [rule catalog v1](docs/rules.md).

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

See [configuration documentation](docs/configuration.md) and the [foundation security model](docs/security-model.md).

## License

The final open-source license and community files are scheduled for the productization phase; the repository is not ready for public redistribution until that phase is complete.
