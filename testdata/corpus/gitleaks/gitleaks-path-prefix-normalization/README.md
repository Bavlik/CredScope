# gitleaks-path-prefix-normalization

**Scenario.** The imported Gitleaks report describes a finding using the
absolute path a containerized scanner would report
(`/repo/config/settings.env`), and `.credscope.yml` configures
`gitleaks.path_prefix: /repo` to match that scanner's mount point.

**Threat or safety property.** CredScope must resolve scanner-container
absolute paths to clean, repository-relative locations rather than either
rejecting them outright or leaking the container's absolute filesystem
layout into reports.

**Relevant inputs.** `input/gitleaks.json` (absolute `File` path);
`config/.credscope.yml` (`gitleaks.path_prefix: /repo`).

**Expected behavior.** Analysis succeeds; the finding's rendered location is
the normalized relative path `config/settings.env`, not the original
absolute container path.

**Expected non-behavior.** No path outside the configured prefix is
accepted; the raw absolute path is not preserved verbatim in output.

**Covered rule/evidence concepts.** `CRD101`; `gitleaks.path_prefix` exact
absolute-prefix normalization.

**Why the fixture is safe.** The only "secret" is the fixed
`CREDSCOPE_TEST_CANARY_GITLEAKS_PREFIX_001` marker.
