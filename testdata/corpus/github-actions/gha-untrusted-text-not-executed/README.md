# gha-untrusted-text-not-executed

**Scenario.** The workflow name, a step name, and run text contain a
script-tag lookalike, a shell command chain (`rm -rf /`, `curl | sh`), a
Mermaid `graph TD` directive lookalike, and a plain-text marker standing in
for an ANSI escape sequence (real control bytes are exercised separately by
`internal/sanitizer`'s own fuzz test, not by this YAML fixture).

**Threat or safety property.** CredScope reads repository content only as
static text for evidence, scoring, and display. This case is an inert
adversarial-text control proving that no part of the pipeline executes
shell content, interprets HTML/script tags, or lets repository text inject
Mermaid diagram directives into generated reports.

**Relevant inputs.** `repository/.github/workflows/hostile-text.yml`.

**Expected behavior.** Analysis succeeds and treats every adversarial
string purely as text: HTML metacharacters are escaped by the JSON encoder,
and no Mermaid rendering is produced by this corpus (Mermaid output is out
of scope for the JSON/SARIF goldens this runner compares, and is covered by
`internal/reporters/mermaid`'s own fuzz test). Control-character and ANSI
escape stripping is covered by `internal/sanitizer`'s own fuzz test rather
than this fixture, since embedding real control bytes in a YAML source file
risks the file itself becoming invalid YAML.

**Expected non-behavior.** No shell command from any `run:` block is ever
invoked. No `<script>` tag survives unescaped into JSON. No workflow or step
name is interpreted as a diagram directive.

**Covered rule/evidence concepts.** Terminal/JSON sanitization
(`internal/sanitizer.TerminalText`); this is a safety control, not a rule
match.

**Why the fixture is safe.** The adversarial strings are static YAML string
values; nothing in the pipeline shells out to repository content, so no
command in this fixture is ever run.
