# WinGet packaging

CredScope uses WinGet's ZIP portable-package support. The release archives contain a root `credscope.exe`; WinGet installs the selected architecture in the current user's portable package directory, creates the managed `credscope` command link, and tracks the package for upgrade and uninstall. No custom installer or administrator access is required for the planned user-scope package.

The checked-in v0.2.0 installer manifest intentionally contains obvious URL and SHA-256 placeholders. It cannot pass final WinGet validation until GitHub Release assets exist. Do not replace those fields with invented hashes.

After publishing and verifying the v0.2.0 GitHub Release, run:

```powershell
.\scripts\update-winget-manifest.ps1 `
  -Version 0.2.0 `
  -ReleaseUrl https://github.com/Bavlik/CredScope/releases/download/v0.2.0
```

The script downloads `checksums.txt` plus both Windows archives, verifies the published checksums and root executable layout, and writes finalized manifests. Then run:

```powershell
winget validate --manifest .\packaging\winget\Bavlik.CredScope\0.2.0
```

Microsoft's free WinGetCreate utility can generate a comparison manifest with `wingetcreate new` for the first submission. Once `Bavlik.CredScope` exists in the community source, `wingetcreate update` can prepare later versions. Do not use WinGetCreate's submission option during local preparation. Submission remains a manual pull request to `microsoft/winget-pkgs`.
