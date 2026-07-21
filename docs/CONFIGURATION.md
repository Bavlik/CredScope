# Configuration

CredScope reads `.credscope.yml` from the analyzed repository root unless `--config` specifies another file. YAML is size-bounded, single-document, strict about unknown fields, and rejected when the configuration file is a symbolic link.

Configuration versions 1 and 2 are accepted for compatibility. New files should use version 2.

```yaml
version: 2
profile: auto

scan:
  include:
    - .github/workflows/*.yml
    - compose.yml
  exclude:
    - vendor/**

gitleaks:
  path_prefix: /repo

ignore:
  paths:
    - value: docs/examples/**
      reason: Checked-in redacted report examples
  variables:
    - value: NEXT_PUBLIC_DEFAULT_LOCALE
      reason: Public frontend configuration
  findings:
    - value: generic-api-key
      reason: Reviewed scanner rule in a fake fixture
  rules:
    - value: CRD308
      reason: Runtime user is enforced by the deployment platform

classifications:
  NEXT_PUBLIC_API_BASE_URL: public_configuration

risk:
  fail_on: high
  minimum_score: 40

rules:
  CRD208:
    enabled: false

output:
  format: terminal
  path: ""
  no_color: false
  quiet: false
  verbose: false
```

## Ignore safety

Each ignore entry requires `value` and a human-readable `reason`. Path patterns must be repository-relative and cannot traverse parents. Variable entries must be variable names. Rule entries must be `CRD` identifiers. Values containing whitespace, control characters, or `=` are rejected. Common token prefixes, private-key markers, and secret assignments are rejected in both values and reasons so ignore metadata cannot be used to store credential material.

Ignored metadata and counts appear in JSON without secret values. Test paths are not implicitly suppressed; imported findings under `tests/` or `testdata/` receive only `test_fixture_candidate: true`.

## Gitleaks path prefix

`gitleaks.path_prefix` and `--gitleaks-path-prefix` accept an exact absolute container or Windows directory prefix below the filesystem root. An absolute finding path must match that prefix at a path boundary. CredScope strips the prefix, cleans the remainder, and rejects root prefixes, parent traversal, or any path outside the prefix. Finding paths are never followed as input files.

## Precedence

Built-in defaults are overlaid by `.credscope.yml`, then explicitly supplied CLI flags override the matching configuration fields.

## JSON schema v2 migration

Schema v2 changes graph relationship values to lowercase typed edges, adds `evidence_kind`, classification fields, profile selection and assumptions, ignored-item metadata, and explicit score-contribution semantics. Consumers should select behavior by top-level `schema_version`. Existing stable IDs and secret-safe fields are preserved where practical, but v1 edge-name comparisons require migration.
