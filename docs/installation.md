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

## Linux users

Two installation methods are supported.

### Portable GitHub Release archive

Download the archive for your architecture and `checksums.txt` from the same GitHub Release, verify the checksum, then extract into a scratch directory so the bundled `LICENSE`, `README.md`, and other documentation files do not scatter across your working directory:

```bash
version=0.2.3
arch=amd64   # or arm64

workdir="$(mktemp -d)"
cd "$workdir"

curl -LO "https://github.com/Bavlik/CredScope/releases/download/v${version}/credscope_${version}_linux_${arch}.tar.gz"
curl -LO "https://github.com/Bavlik/CredScope/releases/download/v${version}/checksums.txt"
sha256sum --ignore-missing -c checksums.txt

tar -xzf "credscope_${version}_linux_${arch}.tar.gz"
sudo install -m 0755 "credscope_${version}_linux_${arch}/credscope" /usr/local/bin/credscope

cd - >/dev/null
rm -rf "$workdir"

credscope version
```

The archive extracts into a single `credscope_<version>_linux_<arch>/` directory. Manual archive installation does not provide APT-managed upgrades or uninstallation.

### Debian/Kali/Ubuntu via Cloudsmith APT

CredScope publishes `.deb` packages to a Cloudsmith APT repository for Debian, Kali, and Ubuntu:

```bash
curl -1sLf 'https://dl.cloudsmith.io/public/bavlik/credscope/cfg/setup/bash.deb.sh' | sudo -E bash
sudo apt update
sudo apt install credscope
credscope version
```

APT manages upgrades and uninstallation (`sudo apt remove credscope`).

The `bavlik/credscope` Cloudsmith repository is public open-source hosting, so no authentication is required to add it or install packages. This path has been tested on Kali Linux.

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
