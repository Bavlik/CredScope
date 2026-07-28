# Test corpus

## Purpose

The test corpus (`testdata/corpus/`) is a deterministic, offline set of
fixtures exercising CredScope's real analysis pipeline end to end —
discovery, parsing, classification, graph construction, rule evaluation,
scoring, and reporting — through the same production packages the CLI uses
(`internal/config`, `internal/ingest`, `internal/analysis`,
`internal/reporters/...`). It is foundational infrastructure this and
future CredScope work builds on: it does not itself implement local
reusable workflow resolution, composite-action resolution, baseline/diff,
Compose multi-file merging, Kubernetes support, or new scanner adapters —
see "Relationship to future work" below.

The corpus is run by a dedicated package, `internal/corpustest`, and is
independent from (does not duplicate or replace) `internal/analysis`'s own
existing end-to-end fixture test or `internal/repositoryquality`'s
release/packaging guards, though `internal/repositoryquality` does add a
small set of structural guard tests over the corpus itself (see below).

## Architecture

```
testdata/corpus/
├── README.md                   corpus-facing quick reference
├── COVERAGE.md                 rule/evidence/edge/format coverage matrix
├── coverage-exceptions.yaml    documented, justified coverage gaps
├── gitleaks/<case-id>/
├── github-actions/<case-id>/
├── compose/<case-id>/
└── integrated/<case-id>/

internal/corpustest/
├── manifest.go       case.yaml schema, LoadManifest, Manifest.Validate
├── discover.go        Discover, Filter, RequireGoldens
├── copydir.go          symlink-rejecting tree copy into an isolated workDir
├── canary.go           secret-safety scanning (raw/json/url/base64 forms)
├── pipeline.go         Execute: the real ingest -> analyze -> report pipeline
├── update.go            StageAll / PublishAll (all-or-nothing golden writes)
├── golden.go           byte comparison, atomic update, redacted diffs
└── corpustest_test.go   TestCorpus: the go test entry point
```

Each case directory is self-contained:

```
<case-id>/
├── README.md        scenario, threat/safety property, expected (non-)behavior
├── case.yaml         manifest (schema below)
├── repository/       the fixture repository root that gets scanned
├── input/             imported reports (e.g. gitleaks.json), if applicable
├── expected.json       golden JSON report (success cases only)
└── expected.sarif       golden SARIF report (success cases only)
```

`inputs.repository` is copied into an isolated temporary directory before
each run — the corpus never mutates its own fixtures. A case may also
declare `inputs.alternate_repository`, a second, semantically-identical
repository (used only by determinism-regression cases) and/or
`inputs.gitleaks`, an imported Gitleaks JSON report.

## Manifest schema (`case.yaml`, `schema_version: 1`)

```yaml
schema_version: 1
id: integrated-gitleaks-compose-published   # must equal the directory name
title: Public Compose service using an imported credential finding
description: >
  One or more sentences. Must not be empty.
category: integrated                          # gitleaks | github-actions | compose | integrated
inputs:
  repository: repository                       # required; case-relative, must exist, no symlinks
  gitleaks: input/gitleaks.json                 # optional; required if the case imports findings
  alternate_repository: repository-alt           # optional; determinism-regression cases only
config:
  profile: production                            # optional; auto|local|ci|staging|production
  config_file: config/.credscope.yml              # optional; mutually exclusive with profile
expect:
  result: success                                  # success | error
  error_contains: "steps must be a list"            # required when result is error
covers:
  rules: [CRD101, CRD301, CRD303]                    # must be real rule IDs (internal/rules.ByID)
  evidence: [confirmed_static_data_flow]              # must be real evidence kinds
  edges: [available_to_service, exposes_port]          # must be real edge types
tags: [integrated, gitleaks, compose, published-port]
forbidden_output_strings:
  - CREDSCOPE_TEST_CANARY_INTEGRATED_COMPOSE_001
notes: ""
```

Every field is validated strictly by `Manifest.Validate`
(`internal/corpustest/manifest.go`):

- `schema_version` must equal the current supported version.
- `id` must be lowercase kebab-case and equal the case's directory name.
- `category` must be one of the four known categories and match the
  directory it lives under.
- `title` and `description` must be non-empty.
- `inputs.repository`, `inputs.gitleaks`, `inputs.alternate_repository`, and
  `config.config_file` must be case-relative (no absolute paths — checked
  with an explicit, GOOS-independent backslash/drive-letter normalization,
  not `filepath.IsAbs`, since that check is otherwise platform-conditional),
  must not escape the case directory, and (where they must exist) must not
  be symbolic links.
- `expect.result: success` requires no `error_contains` and (once goldens
  exist — see below) `expected.json`/`expected.sarif`; `expect.result:
  error` requires a non-empty `error_contains` and forbids golden files
  entirely.
- `covers.rules`/`covers.evidence`/`covers.edges` must reference real,
  currently-defined values (`internal/rules.ByID`, `domain.EvidenceKind`,
  `domain.EdgeType`).
- `forbidden_output_strings` (canaries) must look like
  `CREDSCOPE_TEST_CANARY_*` markers, and are *required* whenever
  `inputs.gitleaks` points at a report containing a non-empty `Secret` or
  `Match` field (checked by parsing the referenced file the same way the
  production adapter does).

Cross-case checks run in `Discover` (`internal/corpustest/discover.go`):
duplicate case IDs (including across different category directories),
missing `case.yaml`/`README.md`, and any manifest validation failure — all
aggregated into one error listing every problem found, not just the first.

**Golden-file existence is intentionally not part of structural
validation.** `Discover` only checks global, filter-independent safety.
Golden existence is enforced separately, by `RequireGoldens`, only against
whatever survives the `-case` filter (if any) — see "Filtering order"
below. This means an unrelated case that has no golden files yet can never
block a different, explicitly selected case from being compared or updated.

## How cases run

`Execute` (`internal/corpustest/pipeline.go`) is the real pipeline, not a
reimplementation:

1. Copy `repository/` into an isolated temp directory (rejecting symlinks).
2. Load configuration: `config.Default()` plus `config.profile`, or a full
   `config.Load()` of `config.config_file` (reusing production validation).
3. Stage the Gitleaks report (if any) *inside* the copied repository root —
   `internal/input.ReadFile` root-confines it exactly like any other
   discovered input, so it cannot live outside the repository copy.
4. `ingest.Repository` → `analysis.Analyze`, run **twice** from the same
   parsed input on every invocation (not just when explicitly checking
   determinism); `Execute` fails if JSON or SARIF rendering is not
   byte-identical both times.
5. Render JSON and SARIF via the real reporters
   (`internal/reporters/jsonreport`, `internal/reporters/sarif`), with a
   fixed tool identity, fixed timestamp, and the case ID as the repository
   label — see "Normalization" below.
6. For `inputs.alternate_repository` cases, additionally analyze the
   alternate repository and compare a *semantic* projection (label,
   classification, score, severity, matched rule IDs) against the primary
   result — not raw bytes, since content-addressed IDs and evidence line
   numbers legitimately differ when the same content sits on a different
   source line. Exact byte equality is still required against the
   committed golden files for `repository/` itself.
7. For `expect.result: error` cases, capture the ingest/analyze error,
   scan it for declared canaries *before* it can appear in any test
   output, and assert it contains `error_contains` (case-insensitive).

No Gitleaks binary, GitHub API, Docker daemon, or network access is ever
used — Gitleaks reports are imported static JSON, and workflow/Compose
content is only ever parsed as data, never executed.

## Running the corpus

```
go test ./internal/corpustest -run TestCorpus                        # compare every case
go test ./internal/corpustest -run TestCorpus -case <case-id>          # compare one case
go test ./internal/corpustest -run TestCorpus -update                  # regenerate all goldens
go test ./internal/corpustest -run TestCorpus -case <case-id> -update    # regenerate one case only
```

### Filtering order

1. `Discover` — global structural validation only (never requires goldens).
2. `Filter(cases, -case)` — narrows to one case; an unknown ID fails
   clearly, listing every valid ID (case IDs are never secret).
3. Compare mode: `RequireGoldens` on the *filtered* set only.
   Update mode: `StageAll` (execute everything in the filtered set,
   in-memory, failing before writing anything if any case fails) then
   `PublishAll` (atomic write-then-rename per file). A `-case`-scoped update
   is exactly this same all-or-nothing logic applied to a one-case batch,
   and logs that it is a targeted update.

### Updating goldens intentionally

`-update` is opt-in and:

- refuses to run outside this repository (checks `go.mod`'s module path);
- never writes a partial result — every selected case must succeed before
  any file is written (`StageAll` returns before writing anything on the
  first failure; `PublishAll` only ever runs after `StageAll` succeeds);
- writes atomically (temp file + rename within the case directory);
- uses the same deterministic, pretty-printed JSON/SARIF encoding as
  comparison mode, so a regenerated golden immediately re-passes compare
  mode with no further changes;
- never embeds a real timestamp or absolute path (see Normalization);
- prints every case updated.

**Never manually author or hand-edit `expected.json`/`expected.sarif`.**
Regenerate them only through `-update`.

## Normalization and determinism

Exact full-output byte comparison is used — CredScope's report schemas are
already deterministic, so nothing needs approximating. The only
normalization applied is at render time, by construction, not after the
fact:

| Field | Real production behavior | Corpus behavior |
| --- | --- | --- |
| `scan.repository` | Sanitized basename of the scanned path | Fixed to the case ID |
| `scan.started_at` / `completed_at` | Wall-clock time | Fixed to `2026-01-01T00:00:00Z` (so `duration_ms` is always `0`) |
| `tool.name` / `tool.version` | Real build info | Fixed to `credscope` / `corpustest` |

Nothing else is normalized. Rule IDs, severities, scores, confidence,
finding IDs, fingerprints, evidence, graph relationships, remediation,
locations, ordering, and schema versions are compared exactly as rendered.

`Execute` enforces determinism unconditionally, on every run, for every
case — not only when explicitly asked to check it:

- two independent `analysis.Analyze` calls from the same parsed input must
  render byte-identical JSON and SARIF;
- an `inputs.alternate_repository` case's two repositories (identical
  content, different YAML key order) must produce identical per-credential
  classification, score, severity, and matched rule IDs.

## Secret safety

- Every "secret" anywhere in the corpus is an unmistakable
  `CREDSCOPE_TEST_CANARY_<CASE>_<NUMBER>`-style marker, never a realistic
  credential shape.
- A case whose imported Gitleaks report has a non-empty `Secret` or `Match`
  field *must* declare its canaries in `forbidden_output_strings` —
  enforced at manifest-validation time, not just at run time.
- On every run, `Execute`'s canary scan checks rendered JSON, rendered
  SARIF, and (for controlled-error cases) the pipeline error message, for
  the raw canary value and three encoded forms: JSON-escaped, URL-encoded,
  and base64. A hit fails the case; the failure message names the case ID,
  the representation that matched, and the output location — **never the
  canary value itself**.
- `internal/repositoryquality`'s corpus guards independently re-check
  committed golden files for canaries, and additionally scan the entire
  corpus tree for symlinks, oversized files, unexpected executable
  extensions, private-key markers, and machine-specific absolute path text.

## Repository-quality guards

`internal/repositoryquality/corpus_test.go` runs as an ordinary part of
`go test ./...`, so a broken corpus case is caught without anyone needing to
know to run `internal/corpustest` specifically:

- manifests discover and validate structurally (`TestCorpusManifestsAreStructurallyValid`);
- discovery order is deterministic and ID-sorted (`TestCorpusDiscoveryOrderIsDeterministic`);
- every success case has golden files (`TestCorpusSuccessCasesHaveGoldenFiles`)
  — **expected to fail until golden generation is complete**; see "Current
  status" below;
- no symlinks, no oversized fixtures, no unexpected executable extensions,
  no machine-specific absolute paths, no private-key markers anywhere in
  the corpus tree (`TestCorpusNoSymlinksAbsolutePathsOrOversizedFixtures`);
- every committed golden file is valid JSON/SARIF with the expected schema
  markers (`TestCorpusGoldenFilesAreValidJSONAndSARIF`);
- committed goldens carry no declared canary (`TestCorpusCanariesAbsentFromCommittedGoldens`);
- `COVERAGE.md` mentions every real case ID (`TestCorpusCoverageDocumentReferencesRealCaseIDs`);
- `coverage-exceptions.yaml` entries are well-formed and unique (`TestCorpusCoverageExceptionsAreWellFormed`).

## Current status: golden generation deferred to Linux

As of this writing, 21 of 22 success cases still need their
`expected.json`/`expected.sarif` generated (`gitleaks-normal-finding` is
done). Generation on the Windows development machine used for this work is
unreliable: Windows Defender intermittently blocks or hangs freshly-linked,
unsigned Go test binaries (`Operation did not complete successfully because
the file contains a virus or potentially unwanted software` — a known false
positive against fresh Go linker output, not specific to this package; even
a trivial hello-world program reproduced it). Everything not requiring
execution of the full corpus pipeline (all case content, all manifests, all
documentation, the runner itself, and every unit/regression test that uses
small synthetic fixtures instead of the real 26-case corpus) is complete
and compiles cleanly. The remaining step —
`go test ./internal/corpustest -run TestCorpus -update` followed by
`go test ./internal/corpustest -run TestCorpus` to confirm — should be run
on Linux (the project's authoritative CI environment; see
`.github/workflows/ci.yml`), where this constraint does not apply.

## How to add a new parser case

1. Pick the right category directory and a kebab-case ID.
2. Create `<category>/<id>/repository/` with the minimal fixture needed —
   prefer the smallest input that exercises the behavior under test.
3. Write `<id>/README.md` (scenario, safety property, expected/non-expected
   behavior, covered concepts, why it's safe) and `<id>/case.yaml`.
4. If importing Gitleaks findings, use `CREDSCOPE_TEST_CANARY_<ID>_<N>`
   markers and declare them in `forbidden_output_strings`.
5. Run `go test ./internal/corpustest -run TestCorpus -case <id> -update`
   to generate goldens for just that case, then
   `go test ./internal/corpustest -run TestCorpus -case <id>` to confirm.
6. Add the case to `COVERAGE.md`'s matrix and index.

## How to add a new rule case

Same as above, but choose (or construct) a fixture whose static shape
matches the rule's documented trigger condition (`docs/RULES.md`,
`internal/rules.Catalog()`). If you cannot safely reproduce a rule's
trigger without fabricating an unrealistic or unsafe fixture, add a
justified entry to `coverage-exceptions.yaml` instead of forcing a case
that doesn't actually exercise the rule.

## How to add a regression case

Regression cases exist to freeze a specific, previously-verified behavior
against silent change — e.g. `compose-topology-does-not-imply-flow-regression`
guards the exact "dependency does not imply data flow" boundary from
`docs/ARCHITECTURE.md`. Name the case `*-regression` (or similarly clear),
document the specific claim it guards in its `README.md`, and prefer
asserting the *absence* of an incorrect edge/rule match as explicitly as
the presence of the correct one.

## Review checklist

Before merging a new or changed case:

- [ ] `README.md` states scenario, safety property, expected behavior,
      expected *non*-behavior, covered rule/evidence concepts, and why the
      fixture is safe.
- [ ] Every secret-shaped value is a `CREDSCOPE_TEST_CANARY_*` marker.
- [ ] `forbidden_output_strings` declares every canary the fixture uses.
- [ ] `covers.rules`/`evidence`/`edges` name only what the case actually,
      verifiably exercises (checked against the real golden output, not
      assumed).
- [ ] Golden files were generated via `-update`, never hand-edited.
- [ ] `COVERAGE.md` and, if applicable, `coverage-exceptions.yaml` are
      updated to match.
- [ ] `go test ./internal/corpustest -run TestCorpus -case <id>` passes.
- [ ] `go test ./internal/repositoryquality/...` passes (or its one
      currently-expected failure — missing goldens pending Linux
      generation — is the only failure).

## Prohibited fixture content

- Real or realistic-looking credentials, private keys, or tokens.
- Network calls, external scanner invocations, or Docker daemon dependence.
- Shell commands that are actually executed by any part of the pipeline
  (workflow/Compose "run" content is only ever parsed as text).
- Absolute local filesystem paths or machine-specific paths.
- Symlinks, junctions, or device files.
- Hand-authored `expected.json`/`expected.sarif`.
- Fixtures whose only purpose is to inflate the case count rather than
  exercise a genuine, reviewable behavior.

## Relationship to future work

This corpus is foundational infrastructure. It deliberately does not
implement, and its cases do not assume, any of: local reusable workflow
resolution, composite-action resolution, Docker Compose multi-file merging,
Kubernetes support, baseline/diff, or additional scanner adapters. When
those land, they should get their own corpus cases following this same
manifest schema and runner, not a parallel framework.

## Relationship to v1.0 stability

Every rule ID, evidence kind, edge type, JSON field, and SARIF field this
corpus exercises is treated as part of CredScope's stable, documented
contract (`docs/CONFIGURATION.md`'s schema v2 migration notes,
`docs/RULES.md`, `docs/SCORING.md`). A golden-file diff on an existing case
after a production change is a signal to stop and evaluate: is this an
intentional, documented schema change, or a regression? See
`coverage-exceptions.yaml` for the specific rules/evidence/edges not yet
exercised — closing those gaps (or explicitly re-affirming them as
out-of-scope) is a reasonable v1.0-readiness task, though none currently
block it.
