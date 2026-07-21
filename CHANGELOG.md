# Changelog

All notable changes to CredScope are documented here. The project follows [Semantic Versioning](https://semver.org/) after its first tagged release.

## [Unreleased]

No changes are currently scheduled beyond the release candidate.

## [0.1.0] - Release candidate (not tagged)

### Added

- Secure repository discovery, strict configuration, sanitization, and staged report writing.
- Gitleaks JSON, GitHub Actions, and Docker Compose input parsing.
- Deterministic graph construction, rule catalog v1, scoring policy v1, confidence, and remediation.
- Terminal, JSON schema v1, SARIF 2.1.0, standalone HTML, and Mermaid reports.
- Pre-release composite GitHub Action, CI and security workflows, and GoReleaser packaging.
- Apache-2.0 licensing and open-source governance documentation.

### Changed

- Safely create missing report parent directories inside the analyzed root while rejecting traversal, symbolic links, and Windows reparse points.
- Rank and bound human evidence paths without changing graph traversal or scoring.
- Compact JSON schema v1 by retaining one shortest path per endpoint and referencing canonical graph evidence.
- Deduplicate identical Mermaid source/relationship/target edges.
- Add fail-closed graph, evidence-path, discovery-count, and display-text resource limits.

### Security

- Expanded hostile-input, path-confinement, Action exit propagation, resource-limit, fuzz, and leakage verification.

No `v0.1.0` release has been published yet.
