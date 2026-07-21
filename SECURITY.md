# Security policy

## Supported versions

CredScope v0.2.0 is being prepared as an experimental release. Security fixes are made on the latest maintained release line and the default branch. v0.1.0 remains immutable as a historical release.

## Reporting a vulnerability

Do not open a public issue containing exploit details, repository source, credentials, tokens, personal data, or unredacted scanner output.

Use GitHub private vulnerability reporting for [Bavlik/CredScope](https://github.com/Bavlik/CredScope/security/advisories/new). If that channel is unavailable, open a public issue containing only a request for private maintainer contact; do not include sensitive details.

Include the affected version or commit, operating system and architecture, a minimal reproduction using clearly fake credentials, expected and observed behavior, impact, and whether the issue is already public. No response-time guarantee is offered.

## Security boundary

CredScope does not validate whether credentials are active, execute repository content, prove runtime data flow, prove external network exposure, replace secret scanners, or provide complete vulnerability scanning. It imports scanner findings and analyzes static exposure context.

The CLI is designed to remain offline, bound input sizes, reject unsafe paths and symlinks, avoid raw-secret serialization, sanitize repository-controlled output, and preserve deterministic ordering. See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).
