# integrated-gitleaks-compose-published

**Scenario.** A Gitleaks finding for `PUBLIC_API_TOKEN` connects to a
Compose service that publishes a host port bound to `0.0.0.0`, analyzed
under the `production` profile.

**Threat or safety property.** This is the canonical integrated scenario:
an imported scanner finding whose credential name is also statically
referenced by a service with published-port exposure context, under a
profile that increases published-port risk weighting.

**Relevant inputs.** `input/gitleaks.json`; `repository/compose.yml`;
`config.profile: production`.

**Expected behavior.** `CRD101`, `CRD301`, and `CRD303` all match. The
`production` profile's published-port risk adjustment (+30%, per
docs/SCORING.md) is reflected in the credential's score contribution
metadata.

**Expected non-behavior.** CredScope does not claim the token is proven
reachable from the public internet at runtime — only that static evidence
places an imported finding in a service with a published, non-loopback
port under a profile that treats that as higher-risk.

**Covered rule/evidence concepts.** `CRD101`, `CRD301`, `CRD303`; profile
adjustment metadata.

**Why the fixture is safe.** The only "secret" is the fixed
`CREDSCOPE_TEST_CANARY_INTEGRATED_COMPOSE_001` marker.
