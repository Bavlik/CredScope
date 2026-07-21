# Security policy

## Supported versions

CredScope is currently pre-release. Until `v0.1.0` is published, security fixes are made on the default branch only. After the first stable release, the latest minor release line will receive security fixes; older pre-release builds are not supported.

## Reporting a vulnerability

Do not open a public issue containing a vulnerability exploit, repository source, credentials, tokens, or unredacted scanner output.

Use GitHub private vulnerability reporting for this repository once it is enabled. If that channel is not visible, open a public issue containing only a request for a private maintainer contact; do not include sensitive details. The project does not publish a security email address at this time.

Please include:

- the affected CredScope version or commit;
- the operating system and architecture;
- a minimal synthetic reproduction with all credentials replaced by obvious fake values;
- the expected and observed behavior;
- security impact and any proposed mitigation;
- whether the issue is already public.

Maintainers will acknowledge reports when the repository's private reporting channel is operational. No response-time SLA is promised during the pre-release period.

## Scope and limitations

CredScope performs deterministic static analysis. It does not validate credentials, authenticate to cloud providers, prove effective IAM permissions, resolve remote reusable workflows, inspect running containers, or establish definite external reachability. Reports are advisory and must not be treated as proof that a repository or deployment is secure.

See [the security model](docs/security-model.md) for trust boundaries and residual risks.
