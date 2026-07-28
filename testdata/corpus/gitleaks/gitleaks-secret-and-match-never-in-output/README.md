# gitleaks-secret-and-match-never-in-output

**Scenario.** A single finding sets distinct `Secret` and `Match` values and
also embeds both of them inside `Description`, `Author`, `Message`, and
`Tags` — every free-text field the Gitleaks adapter touches.

**Threat or safety property.** CredScope's core secret-safety contract:
`Secret` and `Match` are used only transiently to compute an irreversible
fingerprint and to redact themselves out of every other field, then
discarded. This case pressure-tests that redaction against every field the
adapter reads, not just the two fields themselves.

**Relevant inputs.** `input/gitleaks.json`, with both canary values repeated
across five different fields.

**Expected behavior.** Analysis succeeds. The credential's fingerprint is a
`sha256:`-prefixed digest. `Description`, commit `Author`, and `Tags` in the
rendered output contain `[REDACTED]` in place of the canary substrings. The
commit message is represented only via `message_fingerprint`, never as
literal text.

**Expected non-behavior.** Neither canary value appears anywhere in
`expected.json` or `expected.sarif`, in any raw, JSON-escaped, URL-encoded,
or base64 form — enforced by the corpus runner on every render of every
case, and exercised here deliberately across the widest field surface.

**Covered rule/evidence concepts.** `CRD101`; the Gitleaks adapter's
`redact` closure and `MessageFingerprint` handling.

**Why the fixture is safe.** Both "secrets" are fixed
`CREDSCOPE_TEST_CANARY_GITLEAKS_REDACT_*` markers, declared as forbidden
output strings.
