# v0.1.0 release checklist

This checklist is intentionally incomplete until every item is verified in Phase 6.

## Source and policy

- [ ] Worktree and index are clean.
- [ ] Version and changelog are correct.
- [ ] Rule catalog v1, scoring policy v1, JSON schema v1, and documented exit codes are unchanged or deliberately versioned.
- [ ] All third-party Action commit pins are re-verified against official tags.
- [ ] Public repository owner, module path, security reporting, and installation URLs are confirmed.

## Quality and security

- [ ] `gofmt` verification passes.
- [ ] `go test -count=1 ./...` passes.
- [ ] Linux `go test -race -count=1 ./...` passes.
- [ ] `go vet ./...` and `go mod verify` pass.
- [ ] govulncheck passes.
- [ ] CodeQL completes without unresolved release-blocking findings.
- [ ] Gitleaks history scan passes with only narrowly scoped synthetic-fixture allowances.
- [ ] Dependency review is enabled and passing.
- [ ] Complete Action smoke test passes, including threshold exit code 1.

## Reports and artifacts

- [ ] All five report formats parse or render correctly.
- [ ] Repeat scans preserve scores, rule IDs, graph IDs, and normalized security data.
- [ ] Known synthetic raw values are absent from reports, logs, errors, archives, binaries, and checksums.
- [ ] Linux amd64/arm64, macOS amd64/arm64, and Windows amd64 binaries build.
- [ ] GoReleaser snapshot completes and every archive has the expected files and names.
- [ ] Release binary version, full commit, and commit-derived build date are correct.
- [ ] SHA-256 checksums verify for every archive.
- [ ] Reproducibility expectations are tested and documented.
- [ ] SBOMs and attestations are verified if enabled; otherwise their absence is documented.

## Publication

- [ ] No binary, `dist` directory, temporary report, local toolchain, raw secret, personal path, token, or private URL is staged.
- [ ] README installation and Action examples point only to real public refs.
- [ ] Final Phase 6 report approves `v0.1.0` publication.
- [ ] Semantic version tag is created only after approval.
- [ ] Tag-triggered workflow completes.
- [ ] GitHub Release artifacts, checksums, notes, and permissions are inspected.
- [ ] Major Action ref is created only after the released Action is verified.
