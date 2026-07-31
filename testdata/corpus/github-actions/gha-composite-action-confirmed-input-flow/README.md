# gha-composite-action-confirmed-input-flow

**Scenario.** A workflow step invokes a repository-local composite action via
`uses: ./.github/actions/deploy` and passes `${{ secrets.PROD_TOKEN }}` as the
entire value of the `token` input under `with:`. The action directory
contains exactly one `action.yml`, declares `runs.using: composite`, declares
`token` as a required input, and its single internal step reads
`${{ inputs.token }}` inside its `run:` command.

**Threat or safety property.** Phase CA2 establishes a confirmed static flow
from a workflow-step call-site `with:` binding, through a call-specific
`composite_action_input_binding` node, to a call-specific
`composite_action_input_usage` node representing the action's own internal
step usage — without merging the workflow's global, name-based
`PROD_TOKEN` credential identity with the composite action's declared input
identity, and without making CA1's existing structural
`composite_action` node traversable. This case proves the new chain is
alias-preserving, confirmed, and traversable, while the pre-existing generic
workflow-step reference edge for `PROD_TOKEN` continues to exist unchanged
alongside it.

**Relevant inputs.**
`repository/.github/workflows/deploy.yml`,
`repository/.github/actions/deploy/action.yml`.

**Expected behavior.** Analysis succeeds. The graph contains one
`composite_action_input_binding` node (labeled `token`) and one
`composite_action_input_usage` node (labeled `deploy`, the internal step's
own `id`), connected by `explicitly_forwarded_to` edges carrying
`confirmed_static_data_flow` evidence: `PROD_TOKEN`'s credential node forwards
to the binding node, which forwards to the usage node. `PROD_TOKEN`'s
existing generic step-level reference edge (from the pre-existing whole-step
`with:` reference sweep) remains present and unchanged.

**Expected non-behavior.** No new edge ever points at the canonical
`composite_action` node created by CA1. No rule fires, and no score,
severity, or remediation changes because the new binding/usage chain exists.
No raw `with:` value text (`${{ secrets.PROD_TOKEN }}`), no action input
default, and no shell command body ever appears in any node's metadata.

**Covered rule/evidence concepts.** `confirmed_static_data_flow` evidence on
new `explicitly_forwarded_to` edges reaching the new
`composite_action_input_binding`/`composite_action_input_usage` node types;
`structural_call_only` evidence remains on CA1's unchanged
`composite_action` edge.

**Why the fixture is safe.** `PROD_TOKEN` is a synthetic secret name with no
literal value; the composite action's own step runs a harmless placeholder
`deploy` command whose body is never executed by CredScope and is only ever
represented as a redacted, fingerprinted `ShellCommand`.
