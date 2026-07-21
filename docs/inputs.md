# Input adapters and parsers

Phase 2 converts untrusted scanner and YAML input into deterministic, scanner-neutral Go models. It performs no graph construction or scoring.

## Gitleaks JSON

The adapter accepts the standard Gitleaks JSON array form and a single finding object. It imports rule ID, description, repository-relative file, start line, commit hash, safe commit metadata, tags, credential type, reference label, and an irreversible fingerprint.

`Secret` and `Match` are private input-only fields. They are never present in `domain.Finding`, errors, logs, or serialized results. Commit message bodies are represented only by a fingerprint. Equivalent findings are deduplicated and sorted by path, line, rule, and stable finding ID.

Absolute finding paths and `..` traversal are rejected. Relative Windows separators are normalized to `/`.

## GitHub Actions

The parser reads discovered `.github/workflows/*.yml` and `.yaml` files and extracts:

- workflow name and triggers;
- workflow and job permissions;
- jobs, dependencies, environments, outputs, and steps;
- workflow, job, and step environment bindings;
- secret, environment, and GitHub context references;
- action and reusable-workflow references, immutable SHA status, and artifact upload/download classification;
- inert shell-command fingerprints, line counts, and canonical references.

Structural signals include `pull_request_target`, missing explicit permissions, write permissions, mutable third-party actions, secrets in pull-request workflows, secrets passed to shell or third-party actions, secret outputs, broad environment propagation, and potentially attacker-influenced GitHub context interpolation. A third-party classification is structural and is never a claim that an action is malicious.

Reusable workflows are represented as unresolved. CredScope does not fetch local or remote referenced workflow content during Phase 2.

## Docker Compose

The parser supports the four discovered root filenames and extracts services, mapping and list-form environments, env files, Compose secrets, short and long port syntax, exposed ports, networks, short and long volume syntax, privilege, host networking, dependencies, health checks, restart policy, profiles, user, and working directory.

Structural signals include credential variables or Compose secrets passed to a service, credentials shared by services, published host ports, privileged mode, Docker socket mounts, writable host bind mounts, host networking, production-like names, a missing explicit non-root user, and an explicitly selected root user.

A published port means the service may be reachable depending on host and network configuration. It is not evidence of definite internet exposure. A missing `user` field is low-confidence evidence about configuration only and does not prove the image runs as root.

`env_file` and Compose secret file paths are recorded but never opened automatically.

## Safe local examples

```bash
# Safe input set
credscope scan testdata/safe --verbose

# Synthetic vulnerable input set with a Gitleaks report
credscope scan testdata/vulnerable \
  --gitleaks-report gitleaks.json \
  --verbose
```

The fixtures use only obviously synthetic identifiers and values. No workflow, shell block, action, Compose service, env file, or secret file is executed or contacted.

## Current limitations

- GitHub expression parsing recognizes direct dotted context references; it is not a complete evaluator for the GitHub expression language.
- Compose interpolation recognizes `${NAME}` and the standard `:-`, `:+`, and `:?` modifier forms. Values are not expanded.
- Remote and local reusable workflow contents are not followed.
- Docker image defaults, runtime reachability, environment-file contents, and effective container users are not inspected.
- Gitleaks findings without secret material use a metadata-derived correlation fingerprint, which does not prove two credentials are identical.
- Phase 2 produces parsed models only. Graphs, scores, remediations, and JSON/SARIF/HTML/Mermaid reports do not exist yet.
