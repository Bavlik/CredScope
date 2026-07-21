# Installation

CredScope is pre-release. No tag, GitHub Release, installer, package-manager entry, or container image exists yet.

## Current supported method

Build from a trusted checkout with Go 1.26 or a supported newer release:

```bash
go mod verify
go build -trimpath -o credscope ./cmd/credscope
./credscope version
```

Windows PowerShell:

```powershell
go mod verify
go build -trimpath -o credscope.exe ./cmd/credscope
.\credscope.exe version
```

You can also run the safe demonstration without installing:

```bash
go run ./cmd/credscope scan testdata/vulnerable --gitleaks-report gitleaks.json --no-color
```

## After the first release

GoReleaser is configured to produce archives for Linux amd64/arm64, macOS amd64/arm64, and Windows amd64, plus SHA-256 checksums. After Phase 6 verifies the release pipeline and the official repository identity, the project can document concrete download URLs and a tagged command of this form:

```text
go install <verified-module>/cmd/credscope@v0.1.0
```

This is illustrative, not a currently functional installation command.

Checksum-verifying shell and PowerShell installers are intentionally deferred. A trustworthy installer requires a confirmed public repository owner, published archives, and stable checksum filenames. Container packaging is also deferred until an immutable runtime base and registry identity are selected and audited.

The composite GitHub Action can be tested from the checked-out repository today with `uses: ./`; external `OWNER/credscope@v1` usage becomes valid only after the public repository and version ref exist.
