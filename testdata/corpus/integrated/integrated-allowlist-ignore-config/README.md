# integrated-allowlist-ignore-config

**Scenario.** Two Gitleaks findings (`IGNORED_FIXTURE_TOKEN`,
`ACTIVE_PROD_TOKEN`) and a workflow referencing two variables
(`STAGING_DEBUG_TOKEN`, `ACTIVE_PROD_TOKEN`). `.credscope.yml` sets
`profile: production` and declares two reasoned ignore entries: one by
finding rule ID, one by variable name.

**Threat or safety property.** Reviewed, reasoned suppressions must
actually remove the covered item from the analyzed credentials list while
leaving unrelated credentials fully analyzed — and every suppression must
be recorded in `ignored_items` with its reason, never silently.

**Relevant inputs.** `input/gitleaks.json` (two findings);
`repository/.github/workflows/deploy.yml`;
`config/.credscope.yml` (two ignore entries, `profile: production`).

**Expected behavior.** `credentials` contains exactly one entry,
`ACTIVE_PROD_TOKEN`, with `CRD101`, `CRD102`, and `CRD203` matching it under
the `production` profile. `ignored_items` contains two entries — one
`kind: finding` targeting `test-fixture-finding`, one `kind: variable`
targeting `STAGING_DEBUG_TOKEN` — each with its configured reason.
`ignored_count` is `2`.

**Expected non-behavior.** `IGNORED_FIXTURE_TOKEN` and
`STAGING_DEBUG_TOKEN` do not appear in `credentials`, and no rule matches
them. The ignore reasons are ordinary configuration text, never a secret
value.

**Covered rule/evidence concepts.** `CRD101`, `CRD102`, `CRD203`;
`ignore.findings`/`ignore.variables` suppression; `production` profile
selection.

**Why the fixture is safe.** Both "secrets" are fixed
`CREDSCOPE_TEST_CANARY_INTEGRATED_ALLOWLIST_*` markers, present regardless
of whether their credential is ultimately suppressed.
