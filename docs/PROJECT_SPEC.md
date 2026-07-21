# CredScope project specification

This repository-owned specification records implemented behavior and remaining `v0.1.0` scope. It is authoritative when older external prompts are unavailable.

## Product vision

CredScope deterministically maps detected credentials and secret references to workflows, services, permissions, environments, and exposed infrastructure so developers can understand static credential blast radius and remediation priorities.

## Security boundaries

CredScope is offline-first and has zero AI runtime dependency. It never executes analyzed repository code, workflows, shell commands, or containers; authenticates to cloud accounts; resolves remote workflows; sends source or secrets over the network; or stores and displays raw secret values. It uses safe labels and domain-separated irreversible fingerprints. It does not claim credential validity, effective cloud IAM permissions, exploitability, or definite internet exposure.

Discovery and explicit inputs remain inside a canonical repository root, reject symlinks, enforce size limits, and ignore common generated directories. YAML is single-document and bounded by aliases, depth, node count, and scalar size. Report files are staged with owner-only permissions and cannot overwrite protected analysis inputs.

## Implemented architecture

- Phase 1: Cobra CLI foundation, strict versioned configuration, root-confined discovery, safe file primitives, domain vocabulary, and sanitization.
- Phase 2: scanner-neutral Gitleaks import, GitHub Actions parsing, Docker Compose parsing, safe fixtures, typed malformed-input errors, and parser security tests.
- Phase 3: stable directed graph and evidence paths, catalog v1, scoring policy v1, confidence model, cross-component rules, remediation catalog, and embedding API.
- Phase 4: complete `scan` orchestration plus terminal, JSON schema v1, SARIF 2.1.0, standalone HTML, and bounded Mermaid reporters with threshold exit behavior.
- Phase 5: source-built composite GitHub Action, least-privilege CI and security workflows, pinned third-party Actions, deterministic GoReleaser packaging, Apache-2.0 governance files, and pre-release installation/release documentation.
- Phase 6 release candidate: secure nested report publication, ranked bounded human evidence, compact schema-v1 JSON paths, Mermaid edge normalization, explicit resource ceilings, fuzz coverage, and final local release verification.

The pipeline is discovery → parsing/ingestion → graph construction → evidence traversal → rule matching → scoring → remediation → selected reporter.

## Current CLI

Supported commands are `credscope scan [repository]`, `credscope version`, `credscope rules list`, and `credscope explain RULE_ID`. Scan supports Gitleaks input, all five report formats, secure output files, failure severity, minimum score, include/exclude patterns, strict configuration, no-color, quiet, and verbose modes. CLI flags override `.credscope.yml`, which overrides defaults.

Exit codes are 0 success, 1 threshold exceeded after report generation, 2 usage/configuration, 3 malformed input, and 4 analysis/report failure.

## Stable policies

Rule catalog `v1` defines the 27 `CRD1xx`–`CRD5xx` rules documented in `docs/rules.md`. Scoring policy `v1` uses documented weights, bounded component adjustments, integer half-up rounding, confidence multipliers of 100/90/70/40/0, and a score cap of 100. Duplicate findings, graph elements, paths, rules, and remediations are deterministically suppressed.

## Current productization behavior

The composite Action supports GitHub-hosted Linux runners, validates all documented inputs without shell evaluation, preserves CLI exit codes, and exposes safe score/severity/count outputs. It builds the checked-in source so pre-release local Action tests do not rely on nonexistent artifacts. It does not upload reports automatically.

CI runs formatting, tests, Linux race detection, vet, module verification, CLI/report validation, native platform smoke builds, and the five required cross-compilation targets. Separate workflows provide CodeQL, govulncheck, Gitleaks history scanning, and dependency review. GoReleaser is configured for tag-only archive and checksum publication with commit-derived version metadata.

## Release-candidate status

The repository is prepared as a local `v0.1.0` release candidate. Local tests, report validation, cross-compilation, dependency and secret scanning, clean-room verification, and archive inspection are recorded in [RELEASE_CANDIDATE.md](RELEASE_CANDIDATE.md). Public release remains blocked on a real GitHub owner/remote and the first successful remote Linux race, Action, CodeQL, dependency-review, Gitleaks, and tag-workflow checks. No release tag, GitHub Release, installer, container, SBOM, or attestation exists yet.

## Explicit exclusions for v0.1.0

Kubernetes, Terraform, cloud IAM API analysis, Azure, GitLab CI, secret validity verification, a backend, database, telemetry, source upload, LLMs, external AI APIs, and automatic source remediation are excluded.

## Definition of done for v0.1.0

The CLI and five formats must build and pass unit, integration, parser, security, leakage, deterministic, and cross-platform checks; the reusable Action and least-privilege CI/security/release workflows must exist; documentation, fixtures, community files, license, changelog, and roadmap must be complete; release artifacts must be reproducible and contain no secret material; and all local and remote checks must be factually reported. Local release-candidate readiness is distinct from public publication approval.
