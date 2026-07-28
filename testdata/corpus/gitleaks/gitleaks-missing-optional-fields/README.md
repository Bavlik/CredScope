# gitleaks-missing-optional-fields

**Scenario.** A Gitleaks finding supplies only `RuleID`, `StartLine`, and
`File`. Every optional field is absent, including `Secret`, `Match`, `Key`,
and `Fingerprint`.

**Threat or safety property.** Real-world Gitleaks configurations and
custom rules do not always populate every field. CredScope must degrade
gracefully: derive a synthetic, deterministic fingerprint from the
available structural fields (rule ID, file, line) rather than failing or
producing an empty/unstable identity.

**Relevant inputs.** `input/gitleaks.json` with only three fields set.

**Expected behavior.** Analysis succeeds. The credential's label falls back
to the rule ID (`generic-api-key`) since `Key` is absent, and its
fingerprint is a stable `sha256:`-prefixed digest derived from
`RuleID + File + StartLine` since no `Secret`, `Match`, or `Fingerprint`
value was available to derive it from.

**Expected non-behavior.** No error is raised for the missing fields; no
placeholder or empty-string identity fields appear in the rendered output.

**Covered rule/evidence concepts.** `CRD101`; fallback identity derivation
in the Gitleaks adapter.

**Why the fixture is safe.** No field in this fixture contains any
secret-like value at all, so no canary declaration is required or present.
