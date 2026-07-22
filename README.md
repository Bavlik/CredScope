# CredScope

CredScope is an experimental, offline-first CLI for analyzing static credential exposure and reachability context in Docker Compose, GitHub Actions, and imported Gitleaks reports.

> Review findings before acting on them. CredScope is not a complete vulnerability scanner and should not be the sole basis for a security decision.

![CredScope terminal report](docs/images/example-terminal-report.svg)

## What CredScope analyzes

- Docker Compose files at the repository root.
- GitHub Actions workflows under `.github/workflows/`.
- Imported Gitleaks JSON reports.
- Credential references, permissions, ports, mounts, dependencies, and shared network topology.

Supported report formats:

- Terminal
- HTML
- JSON
- SARIF 2.1.0
- Mermaid

## Installation

### GitHub Release

CredScope v0.2.0 is available from GitHub Releases for Windows, Linux, and macOS.

Download the archive for your operating system and architecture together with `checksums.txt`, then verify the SHA-256 checksum before extracting it.

Windows example:

```powershell
Get-FileHash .\credscope_0.2.0_windows_amd64.zip -Algorithm SHA256
```

CredScope Windows binaries are currently unsigned. Do not disable SmartScreen, Defender, Smart App Control, or other Windows security controls.

### WinGet

The WinGet manifests are prepared and awaiting acceptance into the Microsoft community repository.

After acceptance, installation will be:

```powershell
winget install --id Bavlik.CredScope -e
```

See [installation documentation](docs/installation.md).

## Quick start

```powershell
credscope version
credscope scan .
credscope scan C:\path\to\repository
credscope scan . --format html --output credscope-report.html
```

## Gitleaks integration

Generate a Gitleaks JSON report:

```bash
gitleaks git --report-format json --report-path gitleaks.json
```

Import it into CredScope:

```bash
credscope scan . --gitleaks-report gitleaks.json
```

CredScope fingerprints and discards imported `Secret` and `Match` values. Raw secret values are not included in reports.

For reports containing an absolute container path prefix:

```bash
credscope scan . \
  --gitleaks-report gitleaks.json \
  --gitleaks-path-prefix /repo
```

## Configuration

Copy [`.credscope.yml.example`](.credscope.yml.example) to `.credscope.yml`.

```yaml
version: 2
profile: auto

ignore:
  paths:
    - value: docs/examples/**
      reason: Checked-in redacted report examples
```

See:

- [Configuration](docs/CONFIGURATION.md)
- [Rules](docs/RULES.md)
- [Scoring](docs/SCORING.md)

## GitHub Action

```yaml
permissions:
  contents: read
  security-events: write

steps:
  - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4.3.1
  - uses: Bavlik/CredScope@v0.2.0
    with:
      path: .
      gitleaks-report: gitleaks.json
      profile: ci
      format: sarif
      output: credscope.sarif
```

See [GitHub Action usage](docs/github-action.md).

## Security model

CredScope does not:

- Validate whether credentials are active.
- Execute repository content, workflows, or containers.
- Make network requests or contact credential providers.
- Prove runtime data flow or external network exposure.
- Replace Gitleaks or another secret scanner.

Repository discovery, imported reports, configuration, and output writes remain confined to the selected repository root.

See [the threat model](docs/THREAT_MODEL.md) and [SECURITY.md](SECURITY.md).

## Documentation

- Architecture
- Configuration
- Inputs
- Reporting
- Rules
- Scoring
- Release process

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

Use fake test values and preserve the project's security, determinism, path-confinement, and output-safety guarantees.

## License

Licensed under the Apache License 2.0.

Created and maintained by Abdallah Alotaibi ([@Bavlik](https://github.com/Bavlik)).

---

### Documentation Update

This README was updated to improve documentation clarity and formatting.
