# v0.1.0 release checklist

Local Phase 6 evidence is recorded in [RELEASE_CANDIDATE.md](RELEASE_CANDIDATE.md). Unchecked remote items remain publication blockers.

## Source and policy

- [ ] Worktree and index are clean.
- [x] Version and changelog are correct for an untagged release candidate.
- [x] Rule catalog v1, scoring policy v1, JSON schema v1, and documented exit codes are unchanged.
- [x] All third-party Action commit pins are re-verified against official tags.
- [ ] Public repository owner, module path, security reporting, and installation URLs are confirmed.

## Quality and security

- [x] `gofmt` verification passes.
- [ ] `go test -count=1 ./...` passes without local execution-policy intervention. All test assertions pass, but Windows Application Control blocks one temporary test executable; its fixed-path equivalent passes.
- [ ] Linux `go test -race -count=1 ./...` passes.
- [x] `go vet ./...` and `go mod verify` pass.
- [x] govulncheck passes.
- [ ] CodeQL completes without unresolved release-blocking findings.
- [x] Gitleaks worktree and history scans pass with only narrowly scoped ignored-output and synthetic-fixture allowances.
- [ ] Dependency review is enabled and passing.
- [x] Local Action runner tests pass for exits 0 through 4, spaces, metacharacters, empty inputs, and safe outputs. The real GitHub-hosted Action job remains unchecked.

## Reports and artifacts

- [x] All five report formats parse or render correctly.
- [x] Repeat scans preserve scores, rule IDs, graph IDs, and normalized security data.
- [x] Known synthetic raw values are absent from generated reports, release archives, extracted binaries, and checksums; intentional test fixtures remain clearly synthetic.
- [x] Linux amd64/arm64, macOS amd64/arm64, and Windows amd64 binaries build.
- [x] GoReleaser snapshot completes and every archive has the expected files and names.
- [x] Release binary version, full commit, and commit-derived build date are correct in the local snapshot.
- [x] SHA-256 checksums verify for every archive.
- [x] Reproducibility expectations are tested and documented; two local snapshot runs produced byte-identical archive checksums.
- [x] SBOMs and attestations are not enabled; their absence and status are documented.

## Publication

- [ ] No binary, `dist` directory, temporary report, local toolchain, raw secret, personal path, token, or private URL is staged.
- [ ] README installation and Action examples point only to real public refs.
- [ ] Final Phase 6 report approves `v0.1.0` publication.
- [ ] Semantic version tag is created only after approval.
- [ ] Tag-triggered workflow completes.
- [ ] GitHub Release artifacts, checksums, notes, and permissions are inspected.
- [ ] Major Action ref is created only after the released Action is verified.
