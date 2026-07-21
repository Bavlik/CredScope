# Project specification

CredScope is a deterministic, offline-first static credential exposure and reachability analyzer for Docker Compose and GitHub Actions.

The command imports Gitleaks findings, parses supported repository configuration, classifies references, constructs a typed static graph, evaluates stable rules, and renders terminal, HTML, JSON, SARIF, or Mermaid output.

Design requirements:

- Never execute repository content or contact credential providers.
- Never serialize raw secret values.
- Keep paths repository-confined and reject unsafe symlinks and reparse points.
- Bound input sizes, discovery counts, graph size, path traversal, and display output.
- Keep ordering and stable identifiers deterministic.
- Separate risk from confidence.
- Separate confirmed static data flow, inferred exposure context, network topology, and unknown runtime behavior.
- Treat scanner findings as stronger classification evidence than variable-name heuristics.

CredScope does not validate credentials, prove runtime data flow, prove external network exposure, replace secret scanners, or provide complete vulnerability scanning.
