# compose-negative-control-no-credential

**Scenario.** One service sets `LOG_LEVEL` and `FEATURE_FLAG_NEW_UI` —
neither credential-shaped — and publishes a port bound only to
`127.0.0.1`.

**Threat or safety property.** This is the negative control other Compose
cases are contrasted against: it proves CredScope does not classify
ordinary operational configuration as a credential, and that loopback-only
port bindings do not trigger published-port risk.

**Relevant inputs.** `repository/compose.yml`.

**Expected behavior.** Analysis succeeds with an empty credentials list.

**Expected non-behavior.** No `CRD301` or `CRD303` match — there is no
credential-shaped variable, and the published port is loopback-only.

**Covered rule/evidence concepts.** None — the empty `credentials` array in
`expected.json` is the checked fact.

**Why the fixture is safe.** Contains no credential-shaped variable names
and no non-loopback port exposure.
