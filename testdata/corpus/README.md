# CredScope test corpus

This directory is a deterministic, offline test corpus exercising
CredScope's real analysis pipeline (discovery, parsing, classification,
graph construction, rule evaluation, scoring, and reporting) against a
curated set of self-contained fixtures. It is run and validated by
`internal/corpustest`. See [docs/TEST_CORPUS.md](../../docs/TEST_CORPUS.md)
for the full architecture, manifest schema, and workflow.

## Layout

```
testdata/corpus/
├── README.md                   (this file)
├── COVERAGE.md                 rule/evidence/edge/format coverage matrix
├── coverage-exceptions.yaml    documented, justified coverage gaps
├── gitleaks/<case-id>/         Gitleaks-import-only cases
├── github-actions/<case-id>/   GitHub Actions parser cases
├── compose/<case-id>/          Docker Compose parser cases
└── integrated/<case-id>/       Cases combining multiple input types
```

Each `<case-id>/` directory is self-contained:

```
<case-id>/
├── README.md        scenario, threat/safety property, expected (non-)behavior
├── case.yaml         machine-readable manifest (see docs/TEST_CORPUS.md)
├── repository/       the fixture repository root that gets scanned
├── input/            imported reports (e.g. gitleaks.json), when applicable
├── expected.json      golden JSON report (success cases only)
└── expected.sarif      golden SARIF report (success cases only)
```

Cases whose manifest declares `expect.result: error` intentionally carry no
golden files — the corpus runner instead asserts the pipeline fails closed
with a specific, controlled error message.

## Running

```
go test ./internal/corpustest -run TestCorpus                       # compare all cases
go test ./internal/corpustest -run TestCorpus -case <case-id>        # compare one case
go test ./internal/corpustest -run TestCorpus -update                # regenerate all goldens (opt-in, all-or-nothing)
go test ./internal/corpustest -run TestCorpus -case <case-id> -update # regenerate one case's goldens only
```

## Reviewing a new or changed case

Before adding or modifying a case, read its own `README.md` and confirm:

- the scenario and safety property are stated plainly, without overstating
  what CredScope proves (see docs/THREAT_MODEL.md's language conventions);
- every "secret" value is an unmistakable `CREDSCOPE_TEST_CANARY_*` marker,
  declared in `case.yaml`'s `forbidden_output_strings`;
- `case.yaml`'s `covers` block names real rule IDs, evidence kinds, and edge
  types (validated automatically — an unknown value fails discovery);
- golden files were generated via `-update`, never hand-authored.

See docs/TEST_CORPUS.md for the complete manifest schema, secret-safety
requirements, determinism requirements, and review checklist.
