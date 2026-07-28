# integrated-multi-finding-deterministic-ordering

**Scenario.** Four independently imported findings — `ALPHA_TOKEN` and
`BETA_TOKEN` referenced by a workflow, `GAMMA_TOKEN` and `DELTA_TOKEN`
referenced by a Compose service — analyzed together.

**Threat or safety property.** CredScope's determinism guarantee must hold
as the number of credentials and graph nodes grows, not just in
single-credential cases. Credential and graph ordering must be stable and
reproducible regardless of input array order or internal map iteration
order.

**Relevant inputs.** `input/gitleaks.json` (four findings);
`repository/.github/workflows/ci.yml`; `repository/compose.yml`.

**Expected behavior.** Four credentials are analyzed. `CRD101` and `CRD102`
match `ALPHA_TOKEN`/`BETA_TOKEN`; `CRD101` and `CRD301` match
`GAMMA_TOKEN`/`DELTA_TOKEN`. Output ordering is stable and matches the
committed golden files; the corpus runner additionally re-analyzes this
case from the same parsed input and asserts byte-identical output on every
test run.

**Expected non-behavior.** No credential's presence or score depends on the
order findings appeared in the source JSON array.

**Covered rule/evidence concepts.** `CRD101`, `CRD102`, `CRD301`;
determinism at scale.

**Why the fixture is safe.** All four "secrets" are fixed
`CREDSCOPE_TEST_CANARY_INTEGRATED_ORDER_*` markers.
