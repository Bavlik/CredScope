# compose-multiple-services-shared-credential

**Scenario.** Three services — `api`, `worker`, and `scheduler` — each
independently reference the same variable name, `SHARED_TOKEN`.

**Threat or safety property.** A credential reachable from multiple,
independently compromisable services has a larger blast radius than one
confined to a single service. CredScope must recognize and surface this as
a distinct condition.

**Relevant inputs.** `repository/compose.yml`.

**Expected behavior.** `CRD301` matches for each service reference.
`CRD306` ("Credential shared across multiple services") matches once for
`SHARED_TOKEN`, reflecting the three independent references.

**Expected non-behavior.** CredScope does not claim the three services
share a single running process or that the credential is literally the
same secret value at runtime — only that the same variable name is
statically referenced by more than one service definition.

**Covered rule/evidence concepts.** `CRD301`, `CRD306`.

**Why the fixture is safe.** `SHARED_TOKEN` is only ever a `${VAR}`
reference, never a literal value.
