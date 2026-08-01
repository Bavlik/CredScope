# gha-nested-composite-action-resolved

**Scenario.** A purely structural fixture. A workflow job runs a single step
that invokes a repository-local composite action via
`uses: ./.github/actions/deploy`. That action's own single internal step in
turn invokes a second repository-local composite action via
`uses: ./.github/actions/authenticate`. Both action directories contain
exactly one `action.yml`, each declaring `runs.using: composite`. There is no
secret, no `with:` binding, and no declared action input anywhere in this
fixture.

**Threat or safety property.** Phase CA3A resolves repository-local nested
composite-action references — a composite action's own internal `uses:`
step, not only a workflow step's — and represents the resolution
structurally in the graph: a second canonical `composite_action` node for
`.github/actions/authenticate`, connected to the existing (CA1-established)
`.github/actions/deploy` canonical node by a structural, non-traversable
edge. This case proves both structural relationships (workflow -> deploy,
and deploy -> authenticate) are purely structural — neither may ever become
a path a credential can traverse, and neither may change a credential's
score, matched rules, or remediation. Because the fixture has no secret and
no `with:` binding, it also proves CA3A never itself creates a credential
node or activates CA2's existing top-level binding/usage chain.

**Relevant inputs.**
`repository/.github/workflows/deploy.yml`,
`repository/.github/actions/deploy/action.yml`,
`repository/.github/actions/authenticate/action.yml`.

**Expected behavior.** Analysis succeeds. The graph contains two
`composite_action` nodes — one for `.github/actions/deploy`, one for
`.github/actions/authenticate` — and exactly two `runs_action` edges, both
carrying `structural_call_only` evidence: one from the workflow call-site
node to the `deploy` canonical node (CA1), and one from the `deploy`
canonical node to the `authenticate` canonical node (CA3A). Neither edge is
traversable.

**Expected non-behavior.** No credential node, `composite_action_input_binding`
node, or `composite_action_input_usage` node is created anywhere in this
fixture — there is no secret and no declared input for CA2 to bind or
forward. No credential evidence path ever includes either `composite_action`
node (both structural edges are excluded from traversal). No rule fires, and
neither score nor remediation is affected, because either composite action
exists. No input, environment, or output data flow is modeled across either
structural relationship. No cycle or depth diagnostic is produced: this
two-level chain is far below the maximum nesting depth.

**Covered rule/evidence concepts.** `structural_call_only` evidence kind on
two `runs_action` edges, one CA1-established and one newly added by CA3A.

**Why the fixture is safe.** Neither composite action declares any input,
secret, or credential. Both composite actions' own steps are harmless
(`uses:` chaining and a placeholder `echo` command, never executed by
CredScope and only ever represented as a redacted, fingerprinted
`ShellCommand`).
