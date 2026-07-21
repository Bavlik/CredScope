# Architecture

CredScope is split into security boundaries that move from untrusted input to safe, deterministic models:

```text
repository files / Gitleaks JSON
  -> discovery and bounded readers
  -> scanner-neutral parsed repository
  -> directed reachability graph
  -> evidence-path traversal
  -> rule catalog v1
  -> scoring policy v1
  -> remediation results
  -> reporter-independent presentation input
  -> terminal / JSON / SARIF / HTML / Mermaid
```

Phase 4 completes this pipeline while retaining strict separation between analysis and presentation. Phase 5 adds repository automation around that runtime without changing the analysis model.

## Package responsibilities

- `internal/graph` builds graph nodes and evidence-sensitive edges from `domain.ParsedRepository`, then performs bounded cycle-safe traversal.
- `internal/rules` owns the data-driven rule catalog and matches structural graph evidence. Parsers do not contain scoring logic.
- `internal/scoring` applies scoring policy v1 to deduplicated rule matches.
- `internal/remediation` maps matched rules to safe recommendations without modifying repository files.
- `internal/analysis` orchestrates the four stages and returns `domain.AnalysisResult`.
- `internal/reporters` defines normalized scan metadata, summary, ordering, and threshold semantics.
- `internal/reporters/{terminal,jsonreport,sarif,html,mermaid}` render to caller-supplied writers without filesystem or network access.
- `internal/cli` validates configuration, runs the pipeline, buffers a complete report, and delegates file publication to `internal/safefile`.
- `pkg/credscope` exposes `Analyze` for embedding.
- `internal/actionrunner` is a GitHub-hosted automation boundary. It validates Action inputs, constructs argv without shell evaluation, builds the checked-in CLI source, preserves CLI exit codes, and writes only numeric/enumerated Action summaries.

## Graph model

Node types are `Credential`, `Finding`, `File`, `Workflow`, `Trigger`, `Job`, `Step`, `Permission`, `Environment`, `ExternalAction`, `ReusableWorkflow`, `ComposeService`, `PortExposure`, `VolumeMount`, `ComposeSecret`, `EnvFile`, and `Repository`.

Relationship types are `DETECTED_IN`, `REFERENCED_BY`, `PASSED_TO`, `EXPOSED_TO`, `EXECUTED_BY`, `TRIGGERED_BY`, `DEPENDS_ON`, `HAS_PERMISSION`, `USES_ENVIRONMENT`, `RUNS_ACTION`, `CALLS_WORKFLOW`, `PUBLISHES_PORT`, `MOUNTS`, `USES_SECRET`, `LOADS_ENV_FILE`, `SHARED_WITH`, and `PROPAGATES_TO`.

Node IDs and edge IDs are full SHA-256 values with domain-separated structural inputs. Credential IDs use safe reference names, never secret values. Equivalent nodes and equivalent evidence-bearing edges are deduplicated. Nodes and edges are sorted by ID before they leave the builder.

Workflow-level credential environment bindings propagate to ordinary jobs and their steps. They are not assumed to cross into reusable-workflow jobs. Job-level bindings propagate to that job's steps. References in one job do not make sibling jobs reachable unless inheritance or another explicit structural relationship supports it.

## Evidence paths

Traversal starts at each credential and returns every distinct reachable path prefix. Each path contains node IDs and labels, edge IDs and relationship types, source locations, evidence type, parser source, and confidence. Missing line information remains missing.

Traversal uses a per-path visited set, so cycles such as Compose service-sharing edges terminate. The default maximum depth is 12. A path at the limit is marked `truncated` when unvisited successors remain. Path IDs are stable hashes of their ordered node and edge IDs, and final paths are deduplicated and sorted. Analysis fails closed above 10,000 paths for one credential or 50,000 paths for one repository rather than returning an understated score.

Human reporters rank and bound a presentation-only subset; this does not change scoring. JSON schema v1 serializes one shortest representative path per reachable endpoint and relies on the included normalized graph for complete relationships and canonical edge evidence. This removes redundant prefixes while preserving IDs, reachable components, rules, and evidence.

## Determinism

The engine does not use wall-clock values, randomness, network data, cloud state, map iteration order, or machine-specific repository roots in graph identity. Repeated analysis of identical parsed data produces byte-stable JSON when encoded with Go's standard encoder.

## Public API

```go
parsed, err := credscope.ParseRepository(ctx, root, credscope.DefaultConfig(), report)
result, err := credscope.Analyze(ctx, parsed, credscope.AnalysisOptions{})
```

Both operations remain offline and inert.

## Report publication

Reporters do not open paths. The CLI renders to memory first, then either writes stdout or invokes the root-confined staged writer. Relative destinations resolve from the analyzed root. The writer safely creates missing parent directories inside that root, rejects symbolic links and Windows reparse points component by component, rejects directories, root escape, and known input-file destinations, and uses atomic staged replacement. This keeps presentation failures from partially replacing an existing report.

## Repository automation

The composite Action builds the repository source rather than downloading an unreleased artifact. CI runs the full Linux quality and race suite once, native smoke builds on Linux/Windows/macOS, and a separate five-target compile matrix. Security workflows isolate CodeQL, govulncheck, Gitleaks history scanning, and pull-request dependency review. The tag-only release workflow delegates artifact assembly to GoReleaser.

These workflows may use GitHub APIs, caches, and release infrastructure. The compiled CredScope CLI remains offline and has no dependency on the Action runner or release tooling.
