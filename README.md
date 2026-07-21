# CredScope

> Map the blast radius of leaked credentials before attackers do.

CredScope is a deterministic security analysis tool that maps detected credential references to the workflows, services, permissions, environments, and infrastructure they may reach. It is offline-first, does not execute repository content, and is designed to compile into a single cross-platform executable.

> CredScope is a deterministic security analysis engine. It does not use LLMs, external AI APIs, telemetry, or cloud processing.

## Development status

The repository currently contains the completed Phase 1 foundation for `v0.1.0`: the Cobra CLI, stable domain model, strict versioned configuration, root-confined input discovery, sanitization, safe report-file writing, and focused tests. Scanner adapters, workflow and Compose parsing, graph analysis, scoring, and reporters belong to subsequent implementation phases and are not represented as complete here.

## Current commands

```text
credscope scan [repository]
credscope version
credscope rules list
credscope explain CRD101
```

At this phase, `scan` securely discovers supported repository inputs and prints an inventory. It does not yet parse or score them.

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

## Security properties in the foundation

- Secret-bearing domain fields do not exist; only labels and irreversible, domain-separated fingerprints are modeled.
- Terminal output strips ANSI and control characters from repository-controlled values.
- Discovery is confined to the selected root, does not follow symlinks, skips common generated directories, and rejects oversized supported inputs.
- Explicit inputs cannot traverse outside the repository root.
- Report writes are root-confined, reject symlinks, use temporary files, and request owner-only permissions.
- Configuration input is size-limited, single-document, and decoded with strict known-field checking.

See [configuration documentation](docs/configuration.md) and the [foundation security model](docs/security-model.md).

## License

The final open-source license and community files are scheduled for the productization phase; the repository is not ready for public redistribution until that phase is complete.
