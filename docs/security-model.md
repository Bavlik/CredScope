# Security model

## Phase 1 trust boundary

Repository paths, filenames, configuration, future scanner reports, and future YAML inputs are untrusted. The selected repository root and CLI arguments are operator-controlled. CredScope does not execute analyzed files, workflows, containers, hooks, or repository scripts.

The Phase 1 implementation provides these controls:

- Directory walking remains under a canonical repository root and does not follow symbolic links.
- Explicit input files are checked component by component for symlinks and must resolve beneath the root.
- Recognized inputs are regular files no larger than 10 MiB by default.
- Common high-volume directories are skipped even when broad include patterns are supplied.
- Configuration is limited to 1 MiB, rejects symlinks and non-regular files, accepts one YAML document, and enables strict known-field decoding.
- Secret values have no field in the scanner-neutral domain model. Identity uses a full, domain-separated SHA-256 fingerprint for correlation, not authentication.
- Repository-controlled terminal strings have ANSI escapes and control characters removed.
- Future report output can use a root-confined writer that rejects symlink destinations and writes with owner-only permissions.

## Non-goals in Phase 1

Phase 1 does not parse Gitleaks, GitHub Actions, or Docker Compose content. It does not infer reachability, calculate scores, generate security reports, authenticate to cloud providers, validate credentials, or make claims about effective cloud permissions. Those controls and their tests must be added alongside the later analysis phases.

## Residual risks

Filesystem authorization can change concurrently after validation. CredScope minimizes the validation-to-use window and refuses symlinks, but callers should run it in a workspace not writable by untrusted concurrent users. Fingerprints must never be used as access-control or cryptographic authentication values.
