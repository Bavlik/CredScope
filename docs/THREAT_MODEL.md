# Threat model

## Assets

CredScope protects repository contents, imported scanner output, local filesystem boundaries, CI logs, generated reports, and the integrity of security conclusions.

## Untrusted inputs

Repository paths, YAML keys and values, workflow expressions, Compose configuration, Gitleaks JSON, configuration patterns and reasons, command-line values, and report output paths are untrusted.

## Defenses

- Repository-confined discovery and explicit file resolution.
- Symlink and Windows reparse-point rejection for sensitive reads and writes.
- Size, file-count, YAML, graph, traversal, and report-view bounds.
- Strict configuration decoding and traversal rejection.
- Transient raw-secret handling with irreversible fingerprints and secret-safe domain models.
- Terminal control-character removal, HTML auto-escaping and restrictive CSP, sanitized Mermaid identifiers, safe SARIF locations, and JSON HTML escaping.
- Deterministic ordering, deduplication, and stable rule identifiers.
- Exact-prefix normalization for container-generated Gitleaks paths.

## Trust and evidence semantics

Imported scanner findings have stronger classification authority than variable names. Public frontend prefixes default to public configuration unless a scanner finding independently indicates secret-like material. Name suffixes are indicators, not proof.

Data availability, explicit forwarding, dependency topology, network paths, and host-port exposure are separate relationships. Only confirmed static data-flow edges support propagation claims. Dependency and network edges are topology only. Runtime behavior and external exposure remain unknown unless supported by evidence outside CredScope’s current static model.

## Out of scope

CredScope does not validate active credentials, execute repository content, inspect running containers, resolve effective cloud IAM, fetch remote workflows, prove runtime data flow, prove internet exposure, replace secret scanners, or provide complete vulnerability scanning.

## Residual risks

Parsers intentionally model a bounded subset of GitHub Actions expressions and Docker Compose behavior. Scanner findings and heuristics can be false positives. Runtime defaults, deployment overlays, firewall rules, and external systems may materially change risk. Users must review findings with deployment and provider context.
