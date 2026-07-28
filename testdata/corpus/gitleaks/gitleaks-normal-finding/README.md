# gitleaks-normal-finding

**Scenario.** A Gitleaks JSON report with a single finding is imported
against a repository that has no GitHub Actions workflows or Docker Compose
files at all.

**Threat or safety property.** CredScope must be able to import a scanner
finding and produce a deterministic, secret-safe analysis even when there is
no further static context connecting it to anything else. This is the
narrowest possible positive control for imported-finding handling.

**Relevant inputs.**
- `input/gitleaks.json` — one finding with distinct `Secret` and `Match`
  values, both set to the same canary marker.
- `repository/` — deliberately empty of workflows and Compose files.

**Expected behavior.** Analysis succeeds. One credential subject is
produced. `CRD101` ("Credential finding imported") matches. The credential's
fingerprint is an irreversible `sha256:`-prefixed digest, never the raw
canary value.

**Expected non-behavior.** No workflow- or Compose-related rules fire, since
there are no workflows or Compose services to connect the finding to. No
raw `Secret` or `Match` value appears anywhere in the rendered output.

**Covered rule/evidence concepts.** `CRD101`; `confirmed_static_data_flow`
evidence kind (the finding-to-credential edge itself).

**Why the fixture is safe.** The only "secret" value is the fixed marker
`CREDSCOPE_TEST_CANARY_GITLEAKS_NORMAL_001`, declared in `case.yaml` as a
forbidden output string and enforced by the corpus runner on every render.
