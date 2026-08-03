# gha-nested-composite-action-confirmed-input-flow

**Scenario.** A workflow step invokes a repository-local composite action via
`uses: ./.github/actions/deploy` and passes `${{ secrets.PROD_TOKEN }}` as the
entire value of the `token` input under `with:` (Phase CA2). The `deploy`
action declares `token` as a required input and its single internal step
invokes a second repository-local composite action,
`./.github/actions/authenticate`, forwarding `token` onward as the entire
value of `authenticate`'s own `credential` input (Phase CA3B). The
`authenticate` action declares `credential` as a required input and its
single internal step reads `${{ inputs.credential }}` inside its `run:`
command.

**Threat or safety property.** Phase CA3B proves the complete, truthful,
call-path-specific chain:

```
NodeCredential(PROD_TOKEN)
-> deploy's call-specific binding(token)
-> deploy's call-specific usage (at the authenticate nested step)
-> authenticate's call-specific binding(credential)
-> authenticate's call-specific usage (at the login step)
```

CredScope never infers this nested flow from the mere existence of the
`authenticate` step's CA2 usage record (which alone only proves `token` is
read somewhere inside that step, not specifically through its `with:`
mapping) — it independently inspects that step's exact `with:` binding,
proves it is a clean, whole-value `${{ inputs.token }}` forward, and only
then extends the chain one level deeper.

**Relevant inputs.**
`repository/.github/workflows/deploy.yml`,
`repository/.github/actions/deploy/action.yml`,
`repository/.github/actions/authenticate/action.yml`.

**Expected behavior.** Analysis succeeds. The graph contains:
- one `composite_action_input_binding` node (labeled `token`) and one
  `composite_action_input_usage` node (labeled `authenticate`) from CA2's
  root chain;
- one further `composite_action_input_binding` node (labeled `credential`)
  and one further `composite_action_input_usage` node (labeled `login`) from
  CA3B's nested chain;
- `explicitly_forwarded_to` edges, all carrying `confirmed_static_data_flow`
  evidence, connecting: PROD_TOKEN's credential node to the `token` binding,
  the `token` binding to the `authenticate` usage, the `authenticate` usage
  to the `credential` binding, and the `credential` binding to the `login`
  usage;
- two `composite_action` canonical nodes (`deploy`, `authenticate`) and two
  `runs_action` structural edges carrying `structural_call_only` evidence
  (one CA1 workflow-call-site edge, one CA3A nested-call edge), both
  coexisting with, and remaining excluded from traversal alongside, the
  confirmed chain above.

**Expected non-behavior.** No cross-call contamination: nothing in this
fixture creates a second root call or a second secret, so isolation between
independent call paths is exercised by unit tests, not this corpus case. No
edge ever points at either canonical `composite_action` node. No rule fires,
and no score, severity, or remediation changes because the nested chain
exists. No raw `with:` value text (`${{ inputs.token }}`,
`${{ secrets.PROD_TOKEN }}`), no action input default, and no shell command
body ever appears in any node's metadata.

**Covered rule/evidence concepts.** `confirmed_static_data_flow` evidence on
the new CA3B `explicitly_forwarded_to` edges, extending CA2's existing root
chain of the same evidence kind; `structural_call_only` evidence remains on
CA1's and CA3A's unchanged structural edges.

**Why the fixture is safe.** `PROD_TOKEN` is a synthetic secret name with no
literal value; both composite actions' own steps are harmless (`uses:`
chaining and a placeholder `authenticate` command, never executed by
CredScope and only ever represented as a redacted, fingerprinted
`ShellCommand`).
