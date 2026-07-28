# integrated-isolated-lower-impact

**Scenario.** A Gitleaks finding for `DEV_ONLY_TOKEN` connects to a single
Compose service with no published ports, attached only to an internal
network, analyzed under the `local` profile.

**Threat or safety property.** This case is the deliberate contrast point
against `integrated-gitleaks-actions-higher-impact` and
`integrated-gitleaks-compose-published`: the same import-plus-reference
mechanics, but with materially less static context and a profile that
reduces rather than increases weighting. It demonstrates that CredScope's
scoring is genuinely context-sensitive rather than assigning a flat score
to every imported finding.

**Relevant inputs.** `input/gitleaks.json`; `repository/compose.yml`;
`config.profile: local`.

**Expected behavior.** `CRD101` and `CRD301` match. No published-port,
elevated-permission, or cross-service-sharing rule fires. The `local`
profile's risk-reduction adjustment (−60% for published-port context, per
docs/SCORING.md — not applicable here since no port is published, but
representative of the profile's overall posture) keeps the credential's
severity below the higher-impact integrated cases.

**Expected non-behavior.** No claim is made that this credential is safe to
leave unrotated — only that its statically observable reachability is
narrower than the higher-impact contrast cases.

**Covered rule/evidence concepts.** `CRD101`, `CRD301`; `local` profile
selection.

**Why the fixture is safe.** The only "secret" is the fixed
`CREDSCOPE_TEST_CANARY_INTEGRATED_ISOLATED_001` marker.
