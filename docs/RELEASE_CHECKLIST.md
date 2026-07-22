# v0.2.0 release checklist

- [ ] All local Go tests pass.
- [ ] `go vet ./...` passes.
- [ ] Linux `go test -race ./...` passes in a supported environment.
- [ ] `govulncheck ./...` passes when available.
- [ ] `gitleaks git .` passes when available.
- [ ] `go build ./cmd/credscope` passes.
- [ ] `goreleaser check` passes.
- [ ] GoReleaser snapshot passes.
- [ ] Windows amd64 and arm64 archives contain a root `credscope.exe` and no test fixtures or generated reports.
- [ ] PowerShell release helpers parse without errors.
- [ ] WinGet manifests contain reviewed metadata and no invented release hashes.
- [ ] Generated examples match schema v2 and contain no raw secrets.
- [ ] Documentation matches implemented flags and behavior.
- [ ] v0.1.0 remains unchanged.
- [ ] Maintainer separately approves any tag and publication.
- [ ] Final WinGet URLs and SHA-256 values are generated only after release assets exist.
