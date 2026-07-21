# Development guide

The short contribution policy is in [CONTRIBUTING.md](../CONTRIBUTING.md). This page records reproducible developer commands.

## Unix-like systems

```bash
make fmt
make test
make test-race
make vet
make build
make smoke
make reports
make verify
```

`make vuln` requires `govulncheck`; `make release-snapshot` requires GoReleaser. Make is a convenience only.

## Windows PowerShell

```powershell
gofmt -w (Get-ChildItem cmd,internal,pkg,scripts -Recurse -Filter *.go).FullName
go test -count=1 ./...
go vet ./...
go mod verify
go build -trimpath -o .tmp-build\credscope.exe ./cmd/credscope
.\.tmp-build\credscope.exe version
git diff --check
```

The race detector requires CGO and a compatible C compiler. If unavailable on Windows, do not disable race tests; use the Linux CI job, which runs `go test -race -count=1 ./...` with GCC available.

## Pull requests

Keep changes focused and add security tests for untrusted input, path handling, sanitization, secret leakage, process execution boundaries, deterministic ordering, and report escaping as relevant. Generated reports belong only in `docs/examples`; transient reports belong in `.tmp-reports`, which is ignored.

Executable workflow Actions must use verified full commit SHAs with a human-readable version comment. Dependabot is configured to keep Go modules and GitHub Actions current.
