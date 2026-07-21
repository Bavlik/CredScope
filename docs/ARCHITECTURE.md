# Architecture

CredScope is a local Go command with five stages:

1. Root-confined discovery selects supported GitHub Actions and Docker Compose files.
2. Strict parsers and the Gitleaks adapter produce secret-safe, scanner-neutral models.
3. Classification combines source syntax, imported findings, conservative name heuristics, and explicit configuration overrides.
4. Graph construction, rule evaluation, profile-aware risk scoring, and confidence summarization produce deterministic analysis.
5. Terminal, HTML, JSON, SARIF, and Mermaid reporters serialize the same analysis model.

The command does not fetch remote workflows, start containers, execute shell blocks, evaluate repository code, or contact credential providers.

## Typed graph semantics

Core v2 edge types include:

- `configured_in`
- `available_to_service`
- `available_to_process`
- `referenced_by_process`
- `mounted_as_secret`
- `explicitly_forwarded_to`
- `depends_on`
- `network_reachable`
- `exposes_port`
- `reads_env_file`

Every edge also has an evidence kind:

- `confirmed_static_data_flow`
- `inferred_exposure_context`
- `network_topology_only`
- `unknown_runtime_behavior`

Credential evidence traversal excludes `network_topology_only` edges. A credential available to an API service can raise the impact of compromise of that API service, but an API dependency on Redis does not imply the credential was transmitted to Redis. Published ports describe the directly receiving service’s exposure context, not credential flow through adjacent services.

## Safety boundaries

Raw Gitleaks `Secret` and `Match` values are used transiently for domain-separated fingerprints and redaction, then discarded. Repository-controlled strings pass through format-specific sanitization. Input sizes, graph size, evidence paths, and rendered graph views are bounded. File discovery and report writes reject traversal, unsafe symlinks, and Windows reparse points.

Stable sorting and hashed identifiers keep repeated analysis deterministic for the same parsed input and timestamps.
