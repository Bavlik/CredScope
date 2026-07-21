# GitHub Action

The composite Action builds the checked-in Go source on a GitHub-hosted Linux runner. It converts validated inputs directly to process arguments and does not evaluate them as shell fragments.

## Inputs

| Input | Default | Meaning |
| --- | --- | --- |
| `path` | `.` | Checked-out repository path |
| `gitleaks-report` | empty | Optional Gitleaks JSON path |
| `gitleaks-path-prefix` | empty | Exact absolute scanner prefix to strip |
| `profile` | `auto` | `auto`, `local`, `ci`, `staging`, or `production` |
| `config` | empty | Optional configuration path |
| `format` | `sarif` | `terminal`, `json`, `sarif`, `html`, or `mermaid` |
| `output` | `credscope.sarif` | Repository-relative output path |
| `fail-on` | `high` | Failing severity threshold |
| `minimum-score` | `0` | Minimum risk score for threshold evaluation |
| `verbose` | `false` | Include additional secret-safe evidence |
| `no-color` | `true` | Disable terminal color |

The Action exposes report path, highest score, highest severity, analyzed-item count, and threshold status. It preserves CredScope exit codes and does not upload reports automatically.

```yaml
permissions:
  contents: read

steps:
  - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4.3.1
  - uses: Bavlik/CredScope@v0.2.0
    with:
      path: .
      profile: ci
      gitleaks-report: gitleaks.json
      format: sarif
      output: credscope.sarif
```

The v0.2.0 reference becomes usable only after the maintainer publishes that release. See [the complete example](examples/github-action.yml).
