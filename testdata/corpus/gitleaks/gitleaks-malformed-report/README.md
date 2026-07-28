# gitleaks-malformed-report

**Scenario.** The imported Gitleaks JSON report is truncated: a finding
object is opened but never closed, and the top-level array is closed with a
stray `]` in the wrong place.

**Threat or safety property.** Untrusted, possibly corrupted or
adversarially crafted report files must never crash the tool or leak
partially-parsed field contents; CredScope must fail closed with a
structural, descriptive error.

**Relevant inputs.** `input/gitleaks.json`, deliberately invalid JSON.

**Expected behavior.** `ingest.Repository` returns an error whose message
contains "invalid JSON syntax". No analysis result is produced.

**Expected non-behavior.** No credential, node, or finding is produced. The
error message contains no fragment of the file's field values (Go's JSON
syntax error only reports a byte offset, never surrounding content).

**Covered rule/evidence concepts.** Malformed-input handling in the
Gitleaks adapter's `decode`; this is a negative control, not a rule match.

**Why the fixture is safe.** JSON decoding fails before any field value is
ever read into a `Finding`, and the fixture's only secret-like value is a
fixed canary marker.
