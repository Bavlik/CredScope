# Changelog

All notable changes to CredScope are documented here. The project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

This section prepares the experimental v0.2.0 release. No v0.2.0 tag or release has been created.

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
