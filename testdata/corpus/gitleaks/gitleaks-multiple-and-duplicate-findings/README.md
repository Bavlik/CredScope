# gitleaks-multiple-and-duplicate-findings

**Scenario.** A Gitleaks report contains three logically distinct findings,
one of which (`GAMMA_SECRET`) appears twice with byte-identical fields —
the same shape a real second scan of unchanged history would produce.

**Threat or safety property.** Re-importing the same scanner output (or a
scanner reporting the same finding more than once) must not inflate risk
scoring or produce duplicate credentials in the report. Content-derived
finding IDs must dedupe exact repeats while keeping genuinely distinct
findings separate.

**Relevant inputs.** `input/gitleaks.json` with findings `ALPHA_TOKEN`,
`BETA_KEY`, and two identical `GAMMA_SECRET` entries.

**Expected behavior.** Exactly three credential subjects are produced.
`CRD101` matches all three. Rendered output is stable across repeated
analysis (enforced by the corpus runner on every invocation, not only this
case).

**Expected non-behavior.** The duplicate `GAMMA_SECRET` entry does not
produce a fourth credential and does not double its score contribution.

**Covered rule/evidence concepts.** `CRD101`; deduplication behavior in the
Gitleaks adapter's content-addressed finding IDs.

**Why the fixture is safe.** All three "secrets" are fixed
`CREDSCOPE_TEST_CANARY_GITLEAKS_MULTI_*` markers declared as forbidden
output strings.
