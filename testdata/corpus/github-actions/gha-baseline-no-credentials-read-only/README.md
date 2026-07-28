# gha-baseline-no-credentials-read-only

**Scenario.** A minimal CI workflow: explicit `permissions: contents:
read`, a single pinned first-party `actions/checkout` step, and a test
command that references no secret.

**Threat or safety property.** This is the negative control other GitHub
Actions cases are contrasted against. It proves CredScope does not invent
findings, rule matches, or risk where none of the static conditions those
rules check for are present.

**Relevant inputs.** `repository/.github/workflows/ci.yml`.

**Expected behavior.** Analysis succeeds with an empty credentials list. No
rule matches anything, because there is nothing for any rule to match.

**Expected non-behavior.** No `CRD201`/`CRD207` permission finding (explicit
least-privilege permissions are declared), no `CRD204`/`CRD205` third-party
action finding (the only action is first-party and pinned).

**Covered rule/evidence concepts.** None — this case's purpose is the
absence of matches, which `expected.json`'s empty `credentials` array
documents as a golden, checked fact rather than an assumption.

**Why the fixture is safe.** Contains no secrets, no third-party actions,
and no elevated permissions.
