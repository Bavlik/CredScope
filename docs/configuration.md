# Configuration

CredScope reads `.credscope.yml` from the selected repository root when the file exists. Use `--config PATH` to select another file. Configuration precedence is:

1. Explicit CLI flags.
2. Configuration file values.
3. Built-in defaults.

Only configuration schema version `1` is accepted. Unknown fields and multiple YAML documents are errors rather than silently ignored values.

```yaml
version: 1

scan:
  include:
    - ".github/workflows/*.yml"
    - "docker-compose.yml"
  exclude:
    - "testdata/**"

risk:
  fail_on: high
  minimum_score: 40

rules:
  CRD104:
    enabled: true

output:
  format: terminal
  path: ""
  no_color: false
  quiet: false
  verbose: false
```

Include and exclude patterns are repository-relative. `*`, `?`, and `**` are supported; character classes are intentionally not supported. Absolute paths and patterns that traverse parent directories are rejected.

The accepted `fail_on` values are `none`, `low`, `medium`, `high`, and `critical`. `minimum_score` must be between 0 and 100. The accepted output formats are reserved as `terminal`, `json`, `sarif`, `html`, and `mermaid`; only the Phase 1 terminal discovery inventory is currently implemented.
