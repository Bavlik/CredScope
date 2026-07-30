# gha-local-composite-action-resolved

**Scenario.** A workflow job declares a job-level secret in `env:` and runs a
single step that invokes a repository-local composite action via
`uses: ./.github/actions/deploy`. The action directory contains exactly one
`action.yml`, which declares `runs.using: composite`.

**Threat or safety property.** Phase CA1 resolves repository-local composite
action references and represents the resolution structurally in the graph:
one canonical `composite_action` node per resolved directory, connected to
the existing (unchanged) workflow-step call-site node by a structural,
non-traversable edge. This case proves that relationship is purely
structural — it must never become a path a credential can traverse, and it
must never change a credential's score, matched rules, or remediation.

**Relevant inputs.**
`repository/.github/workflows/deploy.yml`,
`repository/.github/actions/deploy/action.yml`.

**Expected behavior.** Analysis succeeds. The graph contains a
`composite_action` node for `.github/actions/deploy` and a `runs_action` edge
from the call-site node to it, carrying `structural_call_only` evidence.
`DEPLOY_TOKEN` is analyzed exactly as it would be without the composite
action present — its reachability is governed entirely by the job's
`env:` binding.

**Expected non-behavior.** No credential evidence path ever includes the
`composite_action` node (the structural edge is excluded from traversal). No
rule fires because of the composite action itself. No input, environment, or
output data flow is modeled for the action's own declared `inputs`/`outputs`.

**Covered rule/evidence concepts.** `structural_call_only` evidence kind on a
`runs_action` edge.

**Why the fixture is safe.** `DEPLOY_TOKEN` is a synthetic secret name with no
literal value; the composite action's own step runs a harmless `echo`.
