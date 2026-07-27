# Changelog

All notable changes to CredScope are documented here. The project follows [Semantic Versioning](https://semver.org/).

## [0.2.1] - Unreleased

This section prepares v0.2.1. No v0.2.1 tag or release has been created.

### Added

- Debian package generation (`nfpms`) producing signed-metadata `.deb` packages for `linux/amd64` and `linux/arm64`, installing `credscope` to `/usr/bin` with `LICENSE`, `NOTICE`, and `README.md` under `/usr/share/doc/credscope/`.
- Cloudsmith APT publishing preparation in the tag-triggered release workflow, gated on the `CLOUDSMITH_REPOSITORY` repository variable and the `CLOUDSMITH_API_KEY` secret, using the official pinned Cloudsmith CLI.
- Documentation for installing CredScope on Debian/Kali/Ubuntu through Cloudsmith APT, and for safe portable-archive installation on Linux.
- `docs/README.md` documentation index.
- CI validation of the GoReleaser snapshot build: `goreleaser check`, presence and contents of Linux/Windows/macOS archives, `.deb` package metadata and contents via `dpkg-deb`, and archive/package safety checks (no `testdata`, generated reports, or credential-like files).

### Changed

- Portable release archives (`.zip`/`.tar.gz`) now wrap their contents in a single `credscope_<version>_<os>_<arch>/` directory instead of scattering `LICENSE`, `README.md`, and other files into the extraction directory.
- Repository cleanup: removed an accidentally generated HTML scan report from `testdata/vulnerable/reports/`, tightened `.gitignore` against generated reports, coverage output, `.deb` packages, editor/OS junk, and local secrets, and added a documentation index at `docs/README.md`.

## [0.2.0] - 2026-07-22

### Added

- Source-aware credential and configuration classification.
- Environment profiles for auto, local, CI, staging, and production assumptions.
- Reason-required false-positive controls in `.credscope.yml`.
- Safe Gitleaks path-prefix normalization for container-generated reports.
- Typed graph edges and explicit evidence kinds.
- WinGet portable-package manifests for planned normal-user Windows installation.
- Safe local release and WinGet manifest helper scripts.

### Changed

- Corrected reachability semantics so dependency and network topology do not imply credential transmission.
- Separated risk scores from evidence confidence.
- Bumped deterministic JSON reporting to schema v2; see [the migration notes](docs/CONFIGURATION.md#json-schema-v2-migration).
- Cleaned up technical documentation and retained source installation for developers.
- Prepared deterministic GoReleaser archives for Windows, Linux, and macOS on amd64 and arm64.
- Changed `credscope version` to display version, commit, and UTC build time on separate lines.
- Reordered installation documentation around the planned WinGet normal-user path while retaining source instructions for developers.

### Security

- Added regression coverage for classification, topology isolation, profile behavior, allowlist reasons, unsafe ignore paths, Gitleaks prefix confinement, secret-safe JSON, offline HTML, SARIF validity, Mermaid deduplication, and terminal sanitization.

## [0.1.0] - 2026-07-21

### Added

- Gitleaks JSON, GitHub Actions, and Docker Compose static parsing.
- Deterministic graph construction, rule catalog v1, scoring policy v1, and remediation guidance.
- Terminal, JSON, SARIF 2.1.0, standalone HTML, and Mermaid reports.
- Root-confined discovery and report writing, resource limits, sanitization, CI workflows, and GoReleaser packaging.
