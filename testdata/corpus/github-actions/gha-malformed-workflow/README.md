# gha-malformed-workflow

**Scenario.** `jobs.broken.steps` is written as the scalar `not-a-list`
instead of a YAML sequence. The document is valid YAML; it is invalid
GitHub Actions structure.

**Threat or safety property.** The parser must distinguish "not valid YAML"
from "valid YAML but the wrong shape for this field" and report the latter
with a specific, actionable field reference rather than a generic failure
or a silent partial parse.

**Relevant inputs.** `repository/.github/workflows/bad.yml`.

**Expected behavior.** `ingest.Repository` returns a `ParseError` whose
message contains "steps must be a list", identifying the exact offending
field.

**Expected non-behavior.** No workflow, job, or credential is produced from
this file. Analysis does not proceed past ingestion.

**Covered rule/evidence concepts.** Structural malformed-input handling in
the GitHub Actions parser; negative control, not a rule match.

**Why the fixture is safe.** Contains no secrets or executable content —
the `run:` field is entirely absent from the malformed job.
