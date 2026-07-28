# compose-credential-published-port

**Scenario.** One Compose service, `api`, references `DEPLOY_TOKEN` (a
credential-shaped variable name) and publishes port 8443 bound to
`0.0.0.0`.

**Threat or safety property.** This is the positive control for connecting
a credential's availability to a service with published network exposure
context — the core signal `CRD303` is built on.

**Relevant inputs.** `repository/compose.yml`.

**Expected behavior.** `CRD301` ("Credential passed to Compose service")
and `CRD303` ("Credential reaches published host port") both match for
`DEPLOY_TOKEN`.

**Expected non-behavior.** CredScope does not claim the credential is
proven to be internet-reachable at runtime — only that static evidence
places it in a service with a published, non-loopback port binding. See
docs/THREAT_MODEL.md's trust-and-evidence-semantics section.

**Covered rule/evidence concepts.** `CRD301`, `CRD303`;
`confirmed_static_data_flow` (credential to service) and
`inferred_exposure_context` (port exposure) evidence; `available_to_service`
and `exposes_port` edges.

**Why the fixture is safe.** `DEPLOY_TOKEN` is only ever a `${VAR}`
substitution reference; no literal value is present anywhere.
