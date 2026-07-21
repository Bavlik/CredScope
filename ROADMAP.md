# Roadmap

## v0.1.0 release audit

- Run the complete Phase 6 security and reproducibility audit.
- Exercise CI, CodeQL, govulncheck, Gitleaks, dependency review, and the local Action on GitHub-hosted runners.
- Validate a GoReleaser snapshot and inspect every archive and checksum.
- Confirm the final repository owner and public installation URLs.
- Enable private vulnerability reporting and verify all third-party Action pins.

## Later, non-blocking candidates

- Additional scanner adapters behind the existing scanner-neutral interface.
- More GitHub Actions and Compose structural rules with versioned policy changes.
- Checksum-verifying installer scripts after the official repository identity and first release exist.
- Optional keyless artifact attestations and SBOM generation after release-pipeline validation.
- Optional minimal container packaging with a verified immutable base image.

Kubernetes, Terraform, cloud IAM API analysis, secret validity checks, automatic remediation, a backend, a database, telemetry, and AI runtime dependencies are not part of `v0.1.0`.
