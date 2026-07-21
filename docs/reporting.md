# Reporting

All reporters consume the same secret-safe analysis model and write only to the supplied writer.

- `terminal` provides a concise sanitized summary, classification, independent risk and confidence, typed evidence, and bounded detail.
- `json` emits deterministic schema v2 with profile assumptions, classifications, typed edges, ignored metadata, and no raw secrets.
- `sarif` emits SARIF 2.1.0 with stable rule IDs, repository-relative locations, and source properties distinguishing imported scanner findings from CredScope analysis.
- `html` is fully offline, auto-escaped, JavaScript-free, and protected by a restrictive CSP.
- `mermaid` deduplicates source/type/target edges, sanitizes labels, and draws topology differently from static data flow.

Severity thresholds are 0–19 Informational, 20–39 Low, 40–59 Medium, 60–79 High, and 80–100 Critical. Risk and evidence confidence are independent.

Reports written with `--output` remain repository-confined. Parent components and final targets are checked for traversal, symbolic links, Windows reparse points, unsafe type changes, and attempts to overwrite analyzed inputs. Publication uses a staged file in the destination directory.

An empty result is not proof that a repository is secure.

The machine-readable schema is [report-schema-v2.json](report-schema-v2.json). Schema v1 remains checked in only for existing consumers; migration is documented in [CONFIGURATION.md](CONFIGURATION.md#json-schema-v2-migration).
