# v0.1.0 release-candidate audit

Audit date: 2026-07-21

This document records the local Phase 6 audit. It is not a release announcement. No tag, remote push, package, container, or GitHub Release has been created.

## Local verification

- All ordinary Go packages and tests passed. Windows Application Control blocked one freshly generated `repositoryquality.test.exe`; the same fixed-path binary passed all five repository-quality tests. Four Windows-only symlink/case-sensitivity tests were skipped because the local account lacks symlink privilege or because the filesystem is case-insensitive.
- `go vet ./...`, `go mod tidy`, `go mod verify`, `git diff --check`, and govulncheck completed successfully.
- The Windows race build reached the expected local prerequisite failure because GCC is unavailable. The exact Linux race command remains in CI and must pass remotely.
- Bounded 15-second fuzz campaigns passed for terminal sanitization, bounded YAML validation, Mermaid label sanitization, and report-path confinement. The Gitleaks fuzz seeds pass, but Windows Application Control blocked its randomized fuzz worker executable.
- Gitleaks found no leaks in the current source tree or five-commit Git history after narrow exclusions for ignored toolchains, generated release output, temporary reports, and the intentional synthetic Gitleaks fixture.
- Linux amd64/arm64, macOS amd64/arm64, and Windows amd64 builds succeeded with CGO disabled.
- All five reporters were generated from the vulnerable synthetic fixture. JSON and SARIF parsed successfully, HTML retained its CSP and contained no script or external resource, Mermaid contained no duplicate edge, and no generated report contained the known synthetic raw value.
- Repeated scans produced identical credential analyses, graph data, policies, scores, severities, rule IDs, and remediation ordering after excluding scan-time metadata.
- The GoReleaser snapshot built five archives and SHA-256 checksums. Archive contents are limited to the platform binary, README, LICENSE, and CHANGELOG under one versioned directory. Two clean snapshot runs with identical commit-derived metadata produced byte-identical checksums for all five archives.

## Phase 6 changes

- Missing output parents are created component by component beneath the analyzed root. Traversal, links, Windows reparse points, source overwrites, and unsafe existing components remain rejected.
- Terminal evidence is ranked and bounded to 10 paths by default and 40 in verbose mode. HTML initially presents 20 ranked paths. Both give an exact omitted count.
- JSON schema v1 now retains one deterministic shortest path per reachable endpoint, references canonical graph evidence, and deduplicates evidence and path IDs. The vulnerable fixture decreased from 4,152,666 bytes to 1,083,185 bytes (73.92%) without changing its schema version or security result.
- Mermaid edges are normalized by source, relationship, and target. The vulnerable fixture decreased from 87 emitted edges with 7 duplicates to 80 emitted edges with 0 duplicates.
- Discovery, graph construction, evidence traversal, human labels, and Mermaid output now have explicit fail-closed or summarizing resource bounds documented in the security model.

## Security conclusions

No CLI runtime dependency imports `net/http` or `os/exec`. The CLI remains static-analysis-only and performs no network requests, process execution, workflow execution, container startup, telemetry, authentication, report upload, or automatic remediation. Hostile control characters, bidi format controls, HTML and Mermaid syntax, shell metacharacters, Windows/UNC paths, traversal, aliases, deep YAML, long Unicode, and repeated references are covered by unit, integration, fuzz-seed, and resource-limit tests.

## Release classification

- **BLOCKER:** Establish the factual public repository owner and remote; run the Linux race job, real composite Action smoke job, CodeQL, dependency review, Gitleaks workflow, and tag-triggered GoReleaser dry run from that remote; verify the final release commit and approve the tag.
- **IMPORTANT:** Decide whether the first public release will add GitHub artifact attestations. Attestations require the real remote workflow context and were not simulated locally.
- **NON-BLOCKING:** A checksum-verifying installer and minimal container image remain intentionally absent and are not claimed features.
- **DEFERRED:** SBOM generation is not enabled because the required external generator was not part of the audited local toolchain. It may be added after a separately verified supply-chain change.

The repository is locally ready as a `v0.1.0` release candidate. It is not publicly releasable until every BLOCKER above is satisfied.
