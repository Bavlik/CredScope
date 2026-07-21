# GitHub Action

CredScope ships a composite Action in `action.yml`. During the pre-release period it builds the checked-in Go source on a GitHub-hosted Linux runner, so local `uses: ./` smoke tests do not depend on an artifact that has not been published.

The Action uses a Go entrypoint to convert inputs directly into process arguments. It never concatenates inputs into a shell command, evaluates them, or prints environment values. Paths containing spaces are supported; control characters, invalid formats, invalid booleans, and out-of-range scores are rejected with exit code 2.

## Inputs

| Input | Default | Meaning |
| --- | --- | --- |
| `path` | `.` | Checked-out repository path to scan |
| `gitleaks-report` | empty | Optional Gitleaks JSON path |
| `config` | empty | Optional CredScope configuration path |
| `format` | `sarif` | `terminal`, `json`, `sarif`, `html`, or `mermaid` |
| `output` | `credscope.sarif` | Output inside the selected scan root; empty means stdout |
| `fail-on` | `high` | `none`, `informational`, `low`, `medium`, `high`, or `critical` |
| `minimum-score` | `0` | Score from 0 to 100 used for threshold evaluation |
| `verbose` | `false` | Add secret-safe evidence |
| `no-color` | `true` | Disable terminal colors |

## Outputs

| Output | Meaning |
| --- | --- |
| `report-path` | Configured explicit output path |
| `highest-score` | Highest score, or `0` for no credential analyses |
| `highest-severity` | `informational` through `critical`, or `none` |
| `credentials-analyzed` | Number of credential analyses |
| `threshold-exceeded` | `true` only when the primary scan returns exit code 1 |

Summary outputs are obtained by a second non-failing JSON rendering of the same repository state. This never changes the primary scan exit code. If summary generation is unavailable, the Action emits a warning and preserves the primary result with conservative default output values.

## Exit handling

The Action returns CredScope's primary exit code unchanged: 0 for success, 1 for an exceeded threshold, 2 for invalid input/configuration, 3 for malformed analysis input, and 4 for internal/build/report failure. A threshold failure therefore fails the Action step after the report has been written. Use `if: always()` on a following SARIF upload step.

The Action does not upload artifacts, comment on pull requests, modify repository files other than the configured report, or request permissions. Callers should normally grant `contents: read`; an explicit later SARIF upload requires `security-events: write`.

## Local pre-release usage

```yaml
permissions:
  contents: read

steps:
  - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4.3.1
  - id: credscope
    uses: ./
    with:
      path: testdata/vulnerable
      gitleaks-report: gitleaks.json
      format: json
      output: action-smoke.json
      fail-on: none
```

Consumer syntax such as `OWNER/credscope@v1` is intentionally documented as a placeholder until the public owner and major-version ref exist. GitHub-hosted Linux is the only supported Action platform for the initial release; the CLI binaries themselves remain cross-platform.

See [the complete SARIF example](examples/github-action.yml).
