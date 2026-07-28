# integrated-clean-repository-empty-results

**Scenario.** A repository with one GitHub Actions workflow, one Compose
file, and an explicitly empty Gitleaks report (`[]`) — all three supported
input types present, none containing any credential-shaped material.

**Threat or safety property.** A fully clean repository across every
currently supported input type must produce a well-formed, schema-valid
report with an empty `credentials` array — not an error, not a degenerate
or missing report structure.

**Relevant inputs.** `input/gitleaks.json` (`[]`);
`repository/.github/workflows/ci.yml`; `repository/compose.yml`.

**Expected behavior.** Analysis succeeds. `credentials` is empty.
`schema_version`, `policies`, `graph`, and every other required top-level
field per docs/report-schema-v2.json are still present and well-formed.

**Expected non-behavior.** No rule fires. No warning claims a credential
was found.

**Covered rule/evidence concepts.** None by design — this case's golden
output is the checked proof that an empty result is still a complete,
valid one.

**Why the fixture is safe.** No credential-shaped variable names, no
findings, and a loopback-only port.
