# v0.2.0 local release preparation

This document records the intended local verification scope for the experimental v0.2.0 change set. It does not authorize tagging, pushing, publishing, or changing v0.1.0.

Required local checks:

- Go tests and vet.
- Build and source-run smoke tests.
- Vulnerability and secret scanning when tools are available.
- GoReleaser snapshot when configured tooling is available.
- Report validation and raw-secret leakage checks.
- Documentation and metadata review.
- Final diff review for unsupported claims and accidental personal data.

Linux race testing remains a Linux/CI check when the active environment does not support it.
