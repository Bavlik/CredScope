# Contributing to CredScope

Focused bug fixes, tests, documentation improvements, and security-preserving proposals are welcome.

## Development

Install Go 1.26, clone the repository, then run:

```bash
go mod download
go test -count=1 ./...
go vet ./...
go build ./cmd/credscope
```

Run `gofmt` on changed Go files. Linux contributors should also run:

```bash
go test -race -count=1 ./...
```

## Security Requirements

- Never add real credentials, private repository content, or personal data.
- Use clearly fake test values.
- Preserve path confinement, input limits, deterministic ordering, and output sanitization.
- Do not add telemetry, runtime network access, cloud authentication, or repository execution.
- Add negative tests for security-sensitive behavior.

## Pull Requests

Keep pull requests focused, explain the user-visible and security impact, update relevant documentation, and ensure CI passes.

Report vulnerabilities privately through `SECURITY.md`, not through public issues.

## Documentation Guidelines

Documentation contributions are encouraged. When updating documentation:

- Keep content clear, concise, and technically accurate.
- Update examples when features or commands change.
- Follow the existing Markdown style used throughout the repository.
- Verify that all links and referenced files remain valid.
- Prefer small, focused documentation changes in each pull request.

Contributions are licensed under Apache-2.0.
