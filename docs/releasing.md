# Release process

CredScope uses GoReleaser v2 configuration and a tag-only GitHub workflow. The workflow pins GoReleaser `v2.17.0`; Dependabot maintains the surrounding Action revision. The local release-candidate audit exercises the same configuration without creating a tag or release.

For an untagged release candidate, maintainers set `CREDSCOPE_SNAPSHOT_VERSION=0.1.0`, `CREDSCOPE_BUILD_COMMIT` to the exact candidate commit, and `CREDSCOPE_BUILD_TIMESTAMP` to that commit's Unix timestamp only in the local process, then run with `--snapshot`. These environment overrides retain version `0.1.0`, real commit metadata, and stable file times without creating a Git tag or altering repository history. Tagged builds use GoReleaser's Git metadata directly.

## Version metadata

Development builds report `dev`, commit `none`, and build date `unknown`. GoReleaser injects:

- `main.version` from the semantic tag;
- `main.commit` from the full Git commit;
- `main.date` from the commit's ISO-8601 committer timestamp, exported as `BUILD_DATE` by the workflow.

Builds use `CGO_ENABLED=0`, `-trimpath`, stripped symbols, and an empty Go build ID. Archive timestamps use the source commit timestamp. The same source commit, Go toolchain, GoReleaser version, and `BUILD_DATE` are expected to produce equivalent program content. Snapshot comparisons are part of the local release-candidate audit; GitHub publication reproducibility remains a remote release check.

## Artifact matrix

- Linux: amd64, arm64 (`tar.gz`)
- macOS: amd64, arm64 (`tar.gz`)
- Windows: amd64 (`zip`)
- `checksums.txt` using SHA-256

Each archive includes the binary, `LICENSE`, `README.md`, and `CHANGELOG.md` under a versioned directory.

## Maintainer flow

1. Complete [RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md).
2. Confirm a clean worktree and reviewed changelog.
3. Run `goreleaser release --snapshot --clean` with `BUILD_DATE` set to the commit's ISO-8601 timestamp and the three untagged-candidate overrides described above.
4. Inspect every archive, binary version, checksum, permission, and leakage result.
5. Create a signed or otherwise verified semantic tag only after approval.
6. Push the tag; `.github/workflows/release.yml` creates the GitHub Release and uploads artifacts.

The workflow never creates or pushes a tag and does not run on ordinary branch pushes. Its only elevated permission is `contents: write`, limited to the tag-triggered release job.

SBOM generation, attestations, keyless signing, installers, and container publication are deferred until they can be configured and verified reliably. No private signing key is required or stored by the current repository.
