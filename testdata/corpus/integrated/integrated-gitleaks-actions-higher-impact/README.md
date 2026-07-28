# integrated-gitleaks-actions-higher-impact

**Scenario.** An imported Gitleaks finding for `PROD_DEPLOY_TOKEN` connects
to a workflow that stacks several independently higher-impact static
conditions: `pull_request_target` triggering, `permissions: contents:
write`, a `production` environment, a third-party action given the token,
and a direct shell reference to the same token.

**Threat or safety property.** Combining an imported scanner finding with
rich, high-impact static context should produce a substantially higher risk
score than the same finding in isolation — this case is the contrast point
for `gitleaks-normal-finding` and for `integrated-isolated-lower-impact`.

**Relevant inputs.** `input/gitleaks.json`;
`repository/.github/workflows/deploy.yml`.

**Expected behavior.** `CRD101`, `CRD102`, `CRD104`, `CRD201`, `CRD203`,
`CRD204`, and `CRD208` all match. The credential's score is materially
higher than in the isolated-finding baseline case.

**Expected non-behavior.** CredScope does not claim the token was actually
exfiltrated, that the third-party action is malicious, or that the pull
request trigger was actually exploited — only that these static conditions
are simultaneously present.

**Covered rule/evidence concepts.** `CRD101`, `CRD102`, `CRD104`, `CRD201`,
`CRD203`, `CRD204`, `CRD208`.

**Why the fixture is safe.** The only "secret" is the fixed
`CREDSCOPE_TEST_CANARY_INTEGRATED_ACTIONS_001` marker; the workflow itself
contains only `${{ secrets.PROD_DEPLOY_TOKEN }}` expressions.
