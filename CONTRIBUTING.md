# Contributing to CredScope

Thank you for helping improve CredScope. Contributions should preserve its deterministic, offline-first, secret-safe design.

## Before opening a change

For substantial features, open a proposal first so scope and security boundaries can be agreed. Bug fixes, tests, and documentation corrections can go directly to a pull request. Never include real credentials, private repository content, personal data, or proprietary workflow files in an issue or test fixture.

## Development setup

CredScope requires Go 1.26 or a supported newer release.

```bash
go mod download
go test -count=1 ./...
go vet ./...
go build ./cmd/credscope
```

`make verify` runs the Unix convenience workflow; Make is optional. Windows equivalents are documented in [docs/contributing.md](docs/contributing.md).

## Security expectations

- Never add a raw-secret field to a domain model.
- Do not log source shell bodies or environment values.
- Keep filesystem access root-confined and symlink-safe.
- Keep ordering and identifiers deterministic.
- Do not add runtime network access, telemetry, cloud authentication, or code execution.
- Add focused negative and leakage tests for security-sensitive changes.

All commits must be formatted with `gofmt`. Pull requests should be focused, explain behavioral and security impact, update relevant documentation, and pass CI. Contributions are licensed under Apache-2.0.

Please follow the [Code of Conduct](CODE_OF_CONDUCT.md) and report vulnerabilities through [SECURITY.md](SECURITY.md), not public issues.
