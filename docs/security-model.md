# Security model

## Runtime trust boundary

Repository paths, filenames, configuration, scanner reports, and YAML inputs are untrusted. The selected repository root and CLI arguments are operator-controlled. CredScope does not execute analyzed files, workflows, containers, hooks, or repository scripts.

The implementation provides these controls:

- Directory walking remains under a canonical repository root and does not follow symbolic links.
- Explicit input files are checked component by component for symlinks and must resolve beneath the root.
- Recognized inputs are regular files no larger than 10 MiB by default.
- Common high-volume directories are skipped even when broad include patterns are supplied.
- Configuration is limited to 1 MiB, rejects symlinks and non-regular files, accepts one YAML document, and enables strict known-field decoding.
- Secret values have no field in the scanner-neutral domain model. Identity uses a full, domain-separated SHA-256 fingerprint for correlation, not authentication.
- Repository-controlled terminal strings have ANSI escapes and control characters removed.
- Report output uses a root-confined writer that rejects symlink destinations and writes with owner-only permissions.
- Gitleaks `Secret` and `Match` fields exist only in a private adapter input structure. They are converted immediately to a domain-separated SHA-256 fingerprint and cannot be represented by the public finding model.
- Gitleaks metadata is checked against the known raw input value before it enters domain models, preventing the same value from being copied through descriptions, tags, paths, or commit metadata.
- Workflow and Compose YAML is limited to one document, 10 MiB, 64 levels, 100,000 nodes, 50 aliases, and 1 MiB per scalar. Duplicate and complex mapping keys are rejected.
- Shell bodies are never retained verbatim. The model contains an irreversible fingerprint, line count, canonical expression references, and a redacted marker.
- Environment literals are represented by an irreversible fingerprint. Environment and secret expressions retain reference names, not resolved values.
- YAML syntax errors are converted to typed errors that do not include source snippets.
- Graph identities are domain-separated hashes of safe structural keys and never contain credential values.
- Graph edges retain typed, source-located evidence and explicit confidence; missing evidence is not fabricated.
- Traversal uses per-path cycle detection and a configurable maximum depth (12 by default).
- Rule matching and scoring consume only scanner-neutral parsed models and do not reopen files, execute content, or access the network.
- Scoring is integer-only, versioned, bounded at 100, and suppresses duplicate rule inflation.
- Unknown runtime conditions contribute zero points and remain explicit warnings.
- Remediation is advisory only and never rewrites workflows or Compose files.
- Reporters operate only on the secret-safe analysis model and a supplied writer; they cannot open repository paths, run processes, or make network requests.
- Machine-readable stdout contains report data only. Diagnostics are written to stderr.
- HTML uses contextual escaping, no JavaScript or external resources, and a restrictive Content Security Policy.
- Mermaid labels remove directives, external URLs, control characters, and graph-breaking syntax; click directives are never emitted.
- SARIF locations are repository-relative and include a line only when evidence provides one.
- Reports are completely rendered before owner-only staged publication, and detected analysis inputs cannot be overwritten.

## Analysis boundary

Phase 4 adds terminal, JSON, SARIF, HTML, and Mermaid rendering. It does not authenticate to cloud providers, inspect running containers, validate credentials, resolve remote workflows, prove exploitability, or claim effective cloud permissions or definite internet exposure.

## Automation boundary

The Phase 5 composite Action runs only on GitHub-hosted Linux. A small Go entrypoint validates each Action input and passes it as a distinct process argument; repository paths and metacharacters are never evaluated by a shell. The Action builds CredScope from its checked-in source, runs the selected report, preserves exit codes 0 through 4, and performs a second non-failing JSON render only to derive numeric summary outputs. It does not upload reports or request permissions.

GitHub-hosted CI and release workflows necessarily use GitHub network services and download pinned development tools. This does not add network access to the CredScope CLI. Executable Actions are pinned to verified full commit SHAs, dependencies are reviewed, and the Gitleaks allowlist is limited to the synthetic raw-secret input fixture. Release publication has not run and remains subject to Phase 6 review.

## Residual risks

Filesystem authorization can change concurrently after validation. CredScope minimizes the validation-to-use window and refuses symlinks, but callers should run it in a workspace not writable by untrusted concurrent users. Fingerprints must never be used as access-control or cryptographic authentication values.

Building the composite Action executes the trusted CredScope source and the Go toolchain, not the analyzed repository. As with any source-based Action, consumers should pin the Action to a reviewed commit or immutable release ref after publication.
