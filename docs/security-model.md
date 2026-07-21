# Security model

## Phase 1 and Phase 2 trust boundary

Repository paths, filenames, configuration, future scanner reports, and future YAML inputs are untrusted. The selected repository root and CLI arguments are operator-controlled. CredScope does not execute analyzed files, workflows, containers, hooks, or repository scripts.

The implementation provides these controls:

- Directory walking remains under a canonical repository root and does not follow symbolic links.
- Explicit input files are checked component by component for symlinks and must resolve beneath the root.
- Recognized inputs are regular files no larger than 10 MiB by default.
- Common high-volume directories are skipped even when broad include patterns are supplied.
- Configuration is limited to 1 MiB, rejects symlinks and non-regular files, accepts one YAML document, and enables strict known-field decoding.
- Secret values have no field in the scanner-neutral domain model. Identity uses a full, domain-separated SHA-256 fingerprint for correlation, not authentication.
- Repository-controlled terminal strings have ANSI escapes and control characters removed.
- Future report output can use a root-confined writer that rejects symlink destinations and writes with owner-only permissions.
- Gitleaks `Secret` and `Match` fields exist only in a private adapter input structure. They are converted immediately to a domain-separated SHA-256 fingerprint and cannot be represented by the public finding model.
- Gitleaks metadata is checked against the known raw input value before it enters domain models, preventing the same value from being copied through descriptions, tags, paths, or commit metadata.
- Workflow and Compose YAML is limited to one document, 10 MiB, 64 levels, 100,000 nodes, 50 aliases, and 1 MiB per scalar. Duplicate and complex mapping keys are rejected.
- Shell bodies are never retained verbatim. The model contains an irreversible fingerprint, line count, canonical expression references, and a redacted marker.
- Environment literals are represented by an irreversible fingerprint. Environment and secret expressions retain reference names, not resolved values.
- YAML syntax errors are converted to typed errors that do not include source snippets.

## Non-goals through Phase 2

Phase 2 parses Gitleaks, GitHub Actions, and Docker Compose into scanner-neutral structural models. It does not infer graph reachability, calculate risk scores, generate remediation, generate security reports, authenticate to cloud providers, inspect running containers, validate credentials, resolve remote workflows, or make claims about effective cloud permissions. Those features belong to later phases.

## Residual risks

Filesystem authorization can change concurrently after validation. CredScope minimizes the validation-to-use window and refuses symlinks, but callers should run it in a workspace not writable by untrusted concurrent users. Fingerprints must never be used as access-control or cryptographic authentication values.
