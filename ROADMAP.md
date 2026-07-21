# Roadmap

## v0.1.0 remote release gates

- Create the official repository and confirm its public owner and installation URLs.
- Exercise Linux race testing, the reusable Action, CodeQL, Gitleaks, dependency review, and release automation on GitHub-hosted runners.
- Re-verify the candidate commit metadata in the tag-triggered GoReleaser workflow.
- Enable private vulnerability reporting and verify all third-party Action pins.

## Later, non-blocking candidates

- Additional scanner adapters behind the existing scanner-neutral interface.
- More GitHub Actions and Compose structural rules with versioned policy changes.
- Checksum-verifying installer scripts after the official repository identity and first release exist.
- Optional keyless artifact attestations and SBOM generation after release-pipeline validation.
- Optional minimal container packaging with a verified immutable base image.

Kubernetes, Terraform, cloud IAM API analysis, secret validity checks, automatic remediation, a backend, a database, telemetry, and AI runtime dependencies are not part of `v0.1.0`.
