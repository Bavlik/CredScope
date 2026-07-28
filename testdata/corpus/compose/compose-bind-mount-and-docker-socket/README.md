# compose-bind-mount-and-docker-socket

**Scenario.** The `agent` service references `AGENT_TOKEN` and mounts both
`/var/run/docker.sock` (the host Docker socket) and a writable host bind
mount (`./data:/app/data`, no read-only flag).

**Threat or safety property.** A container with the host Docker socket
mounted can generally control the host's container runtime; a writable host
bind mount can generally write to the host filesystem. Both materially
raise the operational impact of that container's compromise, independent
of whether a credential is present — but their combination with a
credential-holding service is what this fixture demonstrates.

**Relevant inputs.** `repository/compose.yml`.

**Expected behavior.** `CRD301` matches `AGENT_TOKEN`. `CRD304` ("Credential
reaches Docker socket mount") and `CRD307` ("Credential reaches writable
host bind mount") both match.

**Expected non-behavior.** CredScope does not claim host compromise
occurred — only that static configuration places a credential-holding
service alongside these two high-impact mount types.

**Covered rule/evidence concepts.** `CRD301`, `CRD304`, `CRD307`;
`mounts_volume` edge.

**Why the fixture is safe.** `AGENT_TOKEN` is only ever a `${VAR}`
reference; the mounted paths are configuration values, never dereferenced by
CredScope.
