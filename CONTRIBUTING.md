# Contributing to CredScope

CredScope welcomes focused bug fixes, tests, documentation improvements, and design proposals that preserve its deterministic, offline-first security boundary.

## Development setup

Install Go 1.26, clone the repository, and run:

```bash
go mod download
go test -count=1 ./...
go vet ./...
go build ./cmd/credscope
```

Run `gofmt` on changed Go files. Linux contributors should also run `go test -race ./...`. If available, run `govulncheck ./...`, `gitleaks git .`, and a GoReleaser snapshot.

## Security requirements

- Never add raw secret values to domain models, logs, fixtures, or reports.
- Use clearly fake test values and do not include private repository content or personal data.
- Preserve path confinement, symlink and reparse-point checks, resource limits, deterministic ordering, output sanitization, and restrictive HTML CSP behavior.
- Keep dependency and network edges separate from confirmed static data flow.
- Add negative tests for security-sensitive changes.
- Do not add runtime network access, telemetry, cloud authentication, or repository execution.

For substantial behavior changes, open an issue describing the threat-model and compatibility impact before implementation. Pull requests should be focused, explain behavior and security impact, update relevant documentation, and pass CI.

Contributions are licensed under Apache-2.0. Follow the [Code of Conduct](CODE_OF_CONDUCT.md), and report vulnerabilities through [SECURITY.md](SECURITY.md), not public issues.
