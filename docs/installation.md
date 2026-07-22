# Installation

## Windows users

After v0.2.0 is published and accepted into the WinGet community source, install CredScope for the current user:

```powershell
winget install --id Bavlik.CredScope -e
credscope version
credscope scan .
```

WinGet's portable-package support manages the command link, upgrades, and uninstall tracking. Normal users do not need Go, Git, a source checkout, a manual executable download, administrator access, or a manual PATH edit.

CredScope's Windows binaries are currently unsigned. Verify published SHA-256 checksums and do not disable SmartScreen, Defender, or other Windows security controls. The WinGet command is unavailable until both the GitHub Release and Microsoft's manifest approval are complete.

## Manual GitHub Release archive

Download the correct archive and `checksums.txt` from the same GitHub Release. Compare `Get-FileHash -Algorithm SHA256` output with the published checksum before extracting. Manual archive installation does not provide WinGet-managed upgrades or uninstallation.

## Developers

Install Git and Go 1.26, then run:

```bash
git clone https://github.com/Bavlik/CredScope.git
cd CredScope
go run ./cmd/credscope version
go run ./cmd/credscope scan /path/to/repository
```

Build locally with `go build -o credscope ./cmd/credscope`, or on Windows with `go build -o credscope.exe ./cmd/credscope`.

CredScope is Apache-2.0 licensed. No payment or commercial license is required.
