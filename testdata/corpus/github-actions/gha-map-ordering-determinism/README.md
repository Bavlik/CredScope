# gha-map-ordering-determinism

**Scenario.** `repository/` and `repository-alt/` each contain one workflow
file that is semantically identical — same triggers, permissions, env
bindings, job, and step — but with YAML mapping keys written in a different
order at the workflow, job, and step levels.

**Threat or safety property.** CredScope's determinism guarantee must hold
regardless of incidental source formatting. A YAML mapping's key order is
not semantically meaningful; if analysis output changed based on it, two
functionally identical workflows could receive different risk scores
depending on how a human happened to type them.

**Relevant inputs.**
`repository/.github/workflows/order.yml` and
`repository-alt/.github/workflows/order.yml`.

**Expected behavior.** Both repositories analyze to the same per-credential
classification, score, severity, and matched rule IDs. `repository/`'s
rendered output additionally matches the committed
`expected.json`/`expected.sarif` golden files byte-for-byte, including
exact evidence line numbers.

**Expected non-behavior.** Neither file's key ordering causes a different
set of matched rules, a different score, or a different classification.
(Evidence `line` numbers and the content-addressed node/edge/path IDs
derived from them do legitimately differ between the two fixtures, since
the same content sits on different source lines — that is not a
determinism violation and is intentionally excluded from the
cross-repository comparison; see case.yaml's notes.)

**Covered rule/evidence concepts.** `CRD102`, `CRD203`; general output
determinism (see docs/TEST_CORPUS.md's normalization and determinism
sections).

**Why the fixture is safe.** No real secret value is present in either
file; only `${{ secrets.NAME }}` expressions.
