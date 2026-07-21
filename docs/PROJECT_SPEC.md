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

The pipeline is discovery → parsing/ingestion → graph construction → evidence traversal → rule matching → scoring → remediation → selected reporter.

## Current CLI

Supported commands are `credscope scan [repository]`, `credscope version`, `credscope rules list`, and `credscope explain RULE_ID`. Scan supports Gitleaks input, all five report formats, secure output files, failure severity, minimum score, include/exclude patterns, strict configuration, no-color, quiet, and verbose modes. CLI flags override `.credscope.yml`, which overrides defaults.

Exit codes are 0 success, 1 threshold exceeded after report generation, 2 usage/configuration, 3 malformed input, and 4 analysis/report failure.

## Stable policies

Rule catalog `v1` defines the 27 `CRD1xx`–`CRD5xx` rules documented in `docs/rules.md`. Scoring policy `v1` uses documented weights, bounded component adjustments, integer half-up rounding, confidence multipliers of 100/90/70/40/0, and a score cap of 100. Duplicate findings, graph elements, paths, rules, and remediations are deterministically suppressed.

## Remaining scope

Phase 5 is productization: reusable GitHub Action, CI/security workflows, GoReleaser, cross-platform release workflow, open-source community files, license, changelog, roadmap, and release documentation. Phase 6 is the final audit: run all checks in the intended release environment, inspect generated artifacts and leakage, exercise the documented demo, and decide whether `v0.1.0` is publishable.

## Explicit exclusions for v0.1.0

Kubernetes, Terraform, cloud IAM API analysis, Azure, GitLab CI, secret validity verification, a backend, database, telemetry, source upload, LLMs, external AI APIs, and automatic source remediation are excluded.

## Definition of done for v0.1.0

The CLI and five formats must build and pass unit, integration, parser, security, leakage, deterministic, and cross-platform checks; the reusable Action and least-privilege CI/security/release workflows must exist; documentation, fixtures, community files, license, changelog, and roadmap must be complete; release artifacts must be reproducible and contain no secret material; and all final Phase 6 checks must be factually reported. Phase 4 alone does not satisfy this release definition.
