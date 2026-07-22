# Contributing to CredScope

Focused bug fixes, tests, documentation improvements, and security-preserving proposals are welcome.

## Development

Install Go 1.26, clone the repository, then run:

```bash
go mod download
go test -count=1 ./...
go vet ./...
go build ./cmd/credscope

Run gofmt on changed Go files. Linux contributors should also run:

go test -race -count=1 ./...
Security requirements
Never add real credentials, private repository content, or personal data.
Use clearly fake test values.
Preserve path confinement, input limits, deterministic ordering, and output sanitization.
Do not add telemetry, runtime network access, cloud authentication, or repository execution.
Add negative tests for security-sensitive behavior.
Pull requests

Keep pull requests focused, explain the user-visible and security impact, update relevant documentation, and ensure CI passes.

Report vulnerabilities privately through SECURITY.md, not through public issues.

Contributions are licensed under Apache-2.0.


4. Press `Ctrl + S`
5. Close Notepad

Then run:

```powershell
git diff --check
git status --short