# v0.2.0 release checklist

- [ ] All local Go tests pass.
- [ ] `go vet ./...` passes.
- [ ] Linux `go test -race ./...` passes in a supported environment.
- [ ] `govulncheck ./...` passes when available.
- [ ] `gitleaks git .` passes when available.
- [ ] `go build ./cmd/credscope` passes.
- [ ] GoReleaser snapshot passes.
- [ ] Generated examples match schema v2 and contain no raw secrets.
- [ ] Documentation matches implemented flags and behavior.
- [ ] v0.1.0 remains unchanged.
- [ ] Maintainer separately approves any tag and publication.
