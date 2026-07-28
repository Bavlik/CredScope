# gitleaks-repository-root-confinement

**Scenario.** A Gitleaks finding reports a `File` value that attempts to
escape the repository root via `../` traversal, with no
`gitleaks.path_prefix` configured to authorize any absolute or
prefix-relative resolution.

**Threat or safety property.** Untrusted scanner-report paths must never be
used to read, write, or reference filesystem locations outside the analyzed
repository root. CredScope must fail closed with a controlled, descriptive
error rather than clamping the path to something plausible-looking.

**Relevant inputs.** `input/gitleaks.json` with `File: "../../../../etc/passwd"`.

**Expected behavior.** `ingest.Repository` returns an error whose message
contains "repository-relative". The corpus runner asserts this exact
controlled failure; there is no successful analysis result and therefore no
`expected.json`/`expected.sarif` for this case.

**Expected non-behavior.** No node, edge, or finding referencing a path
outside the repository is ever produced. The raw canary value is not
present in the error message.

**Covered rule/evidence concepts.** Repository-root confinement in the
Gitleaks adapter's `normalizeFindingPath`; this is a malformed/adversarial
input control, not a rule match.

**Why the fixture is safe.** The traversal target (`/etc/passwd`) is never
actually read — the rejection happens on the string form of the path before
any filesystem access — and the associated "secret" is a fixed canary
marker.
