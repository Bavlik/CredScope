# Release process

CredScope uses GoReleaser v2 configuration and a tag-only GitHub workflow. The workflow pins GoReleaser `v2.17.0`; Dependabot maintains the surrounding Action revision. Phase 5 prepares automation; it does not create a tag or release.

## Version metadata

Development builds report `dev`, commit `none`, and build date `unknown`. GoReleaser injects:

- `main.version` from the semantic tag;
- `main.commit` from the full Git commit;
- `main.date` from the commit's ISO-8601 committer timestamp, exported as `BUILD_DATE` by the workflow.

Builds use `CGO_ENABLED=0`, `-trimpath`, stripped symbols, and an empty Go build ID. Archive timestamps use the source commit timestamp. The same source commit, Go toolchain, GoReleaser version, and `BUILD_DATE` are expected to produce equivalent program content; Phase 6 must test this claim against snapshot artifacts.

## Artifact matrix

- Linux: amd64, arm64 (`tar.gz`)
- macOS: amd64, arm64 (`tar.gz`)
- Windows: amd64 (`zip`)
- `checksums.txt` using SHA-256

Each archive includes the binary, `LICENSE`, `README.md`, and `CHANGELOG.md` under a versioned directory.

## Maintainer flow

1. Complete [RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md).
2. Confirm a clean worktree and reviewed changelog.
3. Run `goreleaser release --snapshot --clean` with `BUILD_DATE` set to the source commit timestamp.
4. Inspect every archive, binary version, checksum, permission, and leakage result.
5. Create a signed or otherwise verified semantic tag only after approval.
6. Push the tag; `.github/workflows/release.yml` creates the GitHub Release and uploads artifacts.

The workflow never creates or pushes a tag and does not run on ordinary branch pushes. Its only elevated permission is `contents: write`, limited to the tag-triggered release job.

SBOM generation, attestations, keyless signing, installers, and container publication are deferred until they can be configured and verified reliably. No private signing key is required or stored by the current repository.
