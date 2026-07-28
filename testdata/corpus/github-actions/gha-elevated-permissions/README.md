# gha-elevated-permissions

**Scenario.** A `workflow_dispatch` workflow declares `permissions:
write-all` at the top level and uses a secret directly inside a step's
`run:` text.

**Threat or safety property.** Broad, undifferentiated write permissions
materially increase what a compromised credential or workflow run could do.
CredScope must surface this as a distinct, higher-impact condition compared
to a workflow with scoped or read-only permissions.

**Relevant inputs.** `repository/.github/workflows/release.yml`.

**Expected behavior.** `CRD202` ("Workflow grants write-all") matches.
`CRD203` ("Secret passed to shell") and `CRD102` ("Credential referenced by
workflow") also match for `RELEASE_TOKEN`.

**Expected non-behavior.** CredScope does not claim the credential was
exfiltrated or that any specific write action occurred — only that the
workflow's static permission grant is broad and the credential is reachable
within it.

**Covered rule/evidence concepts.** `CRD202`, `CRD203`, `CRD102`;
`has_permission` edge.

**Why the fixture is safe.** No real secret value is present; only a
`${{ secrets.RELEASE_TOKEN }}` expression.
