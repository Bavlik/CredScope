# Releasing CredScope v0.2.0

Release publication is a maintainer-only operation. The workflow uses GitHub Actions, GoReleaser, and Microsoft WinGet tooling, all of which are available without a paid service. Existing tags and artifacts, especially v0.1.0, are immutable.

The release workflow grants `contents: write` only to its release job because GitHub's built-in `GITHUB_TOKEN` needs that permission to create a GitHub Release and upload archives and `checksums.txt`. No repository secret or external publishing credential is required.

## Maintainer workflow

1. **Review changes.** Review the complete diff, release notes, archive file list, WinGet templates, security-sensitive scripts, and version metadata. Confirm that generated binaries and reports are not tracked.

2. **Run tests and release checks.** On the clean release-candidate branch, run:

   ```powershell
   go test ./...
   go vet ./...
   .\scripts\release-check.ps1 -Version 0.2.0 -ExpectedBranch feat/release-distribution
   ```

   `release-check.ps1` checks the clean tree, branch, local and remote tag absence, version consistency, required files, tests, vet, and `goreleaser check`. It never publishes.

3. **Merge to `main`.** Merge only after review and CI succeed. On the resulting clean `main`, rerun `release-check.ps1` with its default branch setting before tagging.

4. **Create an annotated v0.2.0 tag.** This is the first publishing action and requires explicit maintainer approval:

   ```powershell
   git tag -a v0.2.0 -m "CredScope v0.2.0"
   ```

5. **Push the tag.** Push only the reviewed tag:

   ```powershell
   git push origin v0.2.0
   ```

6. **Verify GitHub Actions.** Confirm the tag-only release workflow checked out the tagged SHA, downloaded modules, passed tests and vet, and completed GoReleaser before publishing artifacts.

7. **Verify checksums.** Download `checksums.txt` and at least the Windows x64 and arm64 archives. Calculate SHA-256 locally and compare every value with the published checksum file.

8. **Test on a clean Windows environment.** Test the appropriate archive without disabling SmartScreen, Defender, or other Windows security controls. Confirm:

   ```powershell
   .\credscope.exe version
   .\credscope.exe scan .
   ```

9. **Generate final WinGet manifests.** After the release assets exist, run the helper with the GitHub Release asset base URL:

   ```powershell
   .\scripts\update-winget-manifest.ps1 `
     -Version 0.2.0 `
     -ReleaseUrl https://github.com/Bavlik/CredScope/releases/download/v0.2.0
   ```

   The helper downloads both Windows archives and `checksums.txt`, verifies their hashes and archive layout, and writes the real URLs and SHA-256 values. It never submits a pull request.

10. **Validate manifests locally.** Run:

    ```powershell
    winget validate --manifest .\packaging\winget\Bavlik.CredScope\0.2.0
    winget install --manifest .\packaging\winget\Bavlik.CredScope\0.2.0
    ```

    Local manifest installation may require enabling WinGet's documented local-manifest setting. Do not enable installer hash overrides or malware-scan bypasses.

    WinGetCreate is optional, free tooling. For the first package submission, run `wingetcreate new` interactively with the two published archive URLs and compare its output with the reviewed local manifests. For later published versions, update without submission:

    ```powershell
    wingetcreate update Bavlik.CredScope --version 0.2.0 --urls "https://github.com/Bavlik/CredScope/releases/download/v0.2.0/credscope_0.2.0_windows_amd64.zip|x64" "https://github.com/Bavlik/CredScope/releases/download/v0.2.0/credscope_0.2.0_windows_arm64.zip|arm64"
    ```

    Do not add `--submit` during local preparation.

11. **Submit a manual PR to `microsoft/winget-pkgs`.** Copy the three validated manifests into the community repository's required `manifests/b/Bavlik/CredScope/0.2.0/` path, review the PR diff, and submit manually. No CredScope script performs this step.

12. **Wait for Microsoft validation and approval.** Do not advertise WinGet availability until the package is present in the public WinGet source.

13. **Test install, use, upgrade, and uninstall.** After acceptance, use a clean normal-user Windows account:

    ```powershell
    winget install --id Bavlik.CredScope -e
    credscope version
    credscope scan .
    winget upgrade --id Bavlik.CredScope -e
    winget uninstall --id Bavlik.CredScope -e
    ```

    Upgrade testing becomes meaningful when a newer package version exists; for the first publication, verify install and uninstall tracking.

14. **Confirm CI validation.** Ensure the default branch remains green for Go tests, vet, race testing, GoReleaser snapshots, PowerShell syntax, WinGet manifest structure, and tracked-binary hygiene.

CredScope's Windows binaries are currently unsigned. Code signing is not required for this zero-cost release path, and users must not be told to weaken Windows security controls.
