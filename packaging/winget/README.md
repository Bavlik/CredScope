# WinGet packaging

CredScope uses WinGet's ZIP portable-package support. The release archives contain a root `credscope.exe`; WinGet installs the selected architecture in the current user's portable package directory, creates the managed `credscope` command link, and tracks the package for upgrade and uninstall. No custom installer or administrator access is required for the planned user-scope package.

A version directory under `Bavlik.CredScope/<version>/` must only be committed once it contains real, finalized values. Do not commit a manifest with a placeholder URL, a placeholder hash, an invented hash, or a zero hash. `internal/repositoryquality` has a test (`TestWinGetPortableManifestsAreConsistent`) that fails the build if any committed manifest directory contains anything other than a real `https://github.com/Bavlik/CredScope/releases/download/...` URL and a real 64-character SHA-256.

The checked-in `0.2.0` manifest is finalized against the published v0.2.0 GitHub Release and its real checksums.

To prepare manifests for a new version (for example, after a v0.2.1 GitHub Release is published — this repository may currently be ahead of its last published release, in which case no directory for the new version exists yet and that is expected), publish and verify the GitHub Release first, then run:

```powershell
.\scripts\update-winget-manifest.ps1 `
  -Version 0.2.1 `
  -ReleaseUrl https://github.com/Bavlik/CredScope/releases/download/v0.2.1
```

The script downloads `checksums.txt` plus both Windows archives, verifies the published checksums and root executable layout, and writes finalized manifests only from real downloaded release assets — it has no placeholder mode. Then run:

```powershell
winget validate --manifest .\packaging\winget\Bavlik.CredScope\0.2.1
```

Microsoft's free WinGetCreate utility can generate a comparison manifest with `wingetcreate new` for the first submission. Once `Bavlik.CredScope` exists in the community source, `wingetcreate update` can prepare later versions. Do not use WinGetCreate's submission option during local preparation. Submission remains a manual pull request to `microsoft/winget-pkgs`.
