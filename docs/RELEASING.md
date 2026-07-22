# Releasing CredScope

Releases are maintainer-only operations. Published tags and artifacts must not be replaced or force-moved.

## Release process

1. Update `VERSION`, `CHANGELOG.md`, documentation, and package metadata.

2. Merge the reviewed changes into a clean `main` branch.

3. Run the release checks:

```powershell
go test -count=1 ./...
go vet ./...
.\scripts\release-check.ps1 -Version <X.Y.Z> -ExpectedBranch main
```

4. Create and push an annotated tag:

```powershell
git tag -a v<X.Y.Z> -m "CredScope v<X.Y.Z>"
git push origin v<X.Y.Z>
```

5. Confirm that the tag-only GitHub Actions release workflow succeeds and publishes the archives and `checksums.txt`.

6. Verify the published SHA-256 checksums and test the Windows archive without disabling any Windows security controls.

7. Generate and validate the WinGet manifests:

```powershell
.\scripts\update-winget-manifest.ps1 `
  -Version <X.Y.Z> `
  -ReleaseUrl "https://github.com/Bavlik/CredScope/releases/download/v<X.Y.Z>"

winget validate --manifest ".\packaging\winget\Bavlik.CredScope\<X.Y.Z>"
```

8. Submit the validated manifests manually to the Microsoft WinGet community repository.

9. Do not advertise WinGet availability until Microsoft accepts the package.

CredScope Windows binaries are currently unsigned. Never instruct users to disable SmartScreen, Defender, Smart App Control, or other security controls.