# WinGet packaging

CredScope uses WinGet's ZIP portable-package support. WinGet installs the selected architecture in the current user's portable package directory, creates the managed `credscope` command link, and tracks the package for upgrade and uninstall. No custom installer or administrator access is required for the planned user-scope package.

Release archives have not always used the same internal layout: archives published before the directory-wrap change in `CHANGELOG` `[0.2.1]` place `credscope.exe` at the archive root, while later archives wrap it in a `credscope_<version>_<os>_<arch>/` directory. `scripts/update-winget-manifest.ps1` does not assume either layout — it dot-sources `scripts/winget-manifest-functions.ps1` and calls `Resolve-PortableExecutableRelativePath`, which opens each downloaded ZIP and locates the single `credscope.exe` entry wherever it actually is, failing clearly if it is missing, duplicated, or at an absolute or path-traversing location. The manifest's `RelativeFilePath` is always set to that real, verified, forward-slash-normalized path, so it stays correct across archive layout changes.

A version directory under `Bavlik.CredScope/<version>/` must only be committed once it contains real, finalized values. Do not commit a manifest with a placeholder URL, a placeholder hash, an invented hash, or a zero hash. `internal/repositoryquality` has a test (`TestWinGetPortableManifestsAreConsistent`) that fails the build if any committed manifest directory contains anything other than a real `https://github.com/Bavlik/CredScope/releases/download/...` URL and a real 64-character SHA-256.

The checked-in `0.2.0` manifest is finalized against the published v0.2.0 GitHub Release and its real checksums (flat archive layout, `RelativeFilePath: credscope.exe`). The checked-in `0.2.2` manifest is finalized against the published v0.2.2 GitHub Release (directory-wrapped archive layout, `RelativeFilePath: credscope_0.2.2_windows_<arch>/credscope.exe`).

To prepare manifests for a new version, publish and verify the GitHub Release first, then run:

```powershell
.\scripts\update-winget-manifest.ps1 `
  -Version 0.2.3 `
  -ReleaseUrl https://github.com/Bavlik/CredScope/releases/download/v0.2.3
```

The script downloads `checksums.txt` plus both Windows archives, verifies the published checksums and the real archive-relative executable path, and writes finalized manifests only from real downloaded release assets — it has no placeholder mode. Then run:

```powershell
winget validate --manifest .\packaging\winget\Bavlik.CredScope\0.2.3
```

Microsoft's free WinGetCreate utility can generate a comparison manifest with `wingetcreate new` for the first submission. Once `Bavlik.CredScope` exists in the community source, `wingetcreate update` can prepare later versions. Do not use WinGetCreate's submission option during local preparation. Submission remains a manual pull request to `microsoft/winget-pkgs`.
