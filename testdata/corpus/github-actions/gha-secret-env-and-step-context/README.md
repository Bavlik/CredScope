# gha-secret-env-and-step-context

**Scenario.** One workflow references three different secrets, one at each
environment-binding scope: `WORKFLOW_LEVEL_TOKEN` (workflow `env:`),
`JOB_LEVEL_TOKEN` (job `env:`), and `STEP_LEVEL_TOKEN` (step `env:`, also
referenced directly inside a step's `run:` shell text).

**Threat or safety property.** Static evidence about *where* a credential
reference lives (workflow/job/step scope) and *how* it reaches a shell
(indirect environment variable vs. direct inline expression) is the raw
material for every downstream GitHub Actions rule. This case is the
positive control proving the parser captures all three scopes and both
exposure shapes correctly.

**Relevant inputs.** `repository/.github/workflows/context.yml`.

**Expected behavior.** Three credentials are analyzed. `CRD102` ("Credential
referenced by workflow") matches all three. `CRD203` ("Secret passed to
shell") matches `STEP_LEVEL_TOKEN`, whose value is referenced directly
inside `run:` text, not just bound to an environment variable.

**Expected non-behavior.** `WORKFLOW_LEVEL_TOKEN` and `JOB_LEVEL_TOKEN` are
only ever referenced indirectly through `$VAR` shell interpolation of an
environment binding — the parser does not claim `CRD203` for them, since
that rule specifically flags a secret expression appearing directly in
shell text.

**Covered rule/evidence concepts.** `CRD102`, `CRD203`;
`confirmed_static_data_flow` evidence; `configured_in` and
`referenced_by_process` edges.

**Why the fixture is safe.** The workflow contains no real secret values —
only `${{ secrets.NAME }}` expressions, which are references, never
resolved values.
