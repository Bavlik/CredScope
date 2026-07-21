# Inputs

CredScope accepts untrusted local repository content and converts it to bounded, deterministic, secret-safe models.

## Gitleaks JSON

Array and single-object reports are supported. CredScope imports rule ID, description, repository-relative path, line, safe commit metadata, tags, reference label, and an irreversible fingerprint. Raw `Secret`, `Match`, and commit-message bodies are not serialized.

Finding paths must be repository-relative unless an exact absolute `--gitleaks-path-prefix` is configured. Prefix mismatches, traversal, and unsafe absolute paths fail the scan. Findings under test directories receive a `test_fixture_candidate` hint but are not automatically ignored.

## GitHub Actions

CredScope parses workflow triggers, permissions, jobs, dependencies, environments, outputs, steps, environment bindings, secret references, action references, reusable-workflow references, and inert shell-reference metadata. It does not execute shell blocks or fetch reusable workflows.

## Docker Compose

CredScope parses root-level Compose files, including services, environment bindings, env files, secrets, ports, networks, volumes, privilege, host networking, dependencies, health checks, restart policies, profiles, users, and working directories.

Every environment binding can be classified without retaining its value. `env_file` and Compose secret file paths are recorded but not opened automatically. Dependencies and shared networks are topology context only and never imply credential transmission.

GitHub expression and Compose interpolation support is intentionally bounded rather than a complete runtime evaluator.
