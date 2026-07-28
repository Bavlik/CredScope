# compose-malformed

**Scenario.** `services.api.ports` is written as the scalar `invalid`
instead of a YAML sequence. The document is valid YAML; it is invalid
Compose structure.

**Threat or safety property.** The parser must distinguish "not valid YAML"
from "valid YAML but the wrong shape for this field" and report the latter
with a specific, actionable field reference.

**Relevant inputs.** `repository/compose.yml`.

**Expected behavior.** `ingest.Repository` returns a `ParseError` whose
message contains "ports must be a list".

**Expected non-behavior.** No Compose project, service, or credential is
produced from this file.

**Covered rule/evidence concepts.** Structural malformed-input handling in
the Compose parser; negative control, not a rule match.

**Why the fixture is safe.** Contains no credential-shaped variable names.
