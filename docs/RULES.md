# Rule catalog

CredScope rule catalog v2 uses stable `CRD` identifiers. Rules describe static conditions, not credential validity, exploitability, runtime propagation, or internet exposure.

| IDs | Area | Examples |
| --- | --- | --- |
| `CRD101`–`CRD104` | Imported findings and workflow scope | scanner finding, workflow reference, multiple jobs, `pull_request_target` |
| `CRD201`–`CRD208` | GitHub Actions context | write permissions, shell use, third-party actions, outputs, environments |
| `CRD301`–`CRD308` | Docker Compose context | service availability, privileged mode, ports, Docker socket, host network, sharing, bind mounts, user uncertainty |
| `CRD401`–`CRD404` | Cross-component context | CI/runtime sharing, production-like components, permissions, independent paths |
| `CRD501`–`CRD503` | Analysis limitations | unresolved workflows, runtime permissions, external exposure uncertainty |

Run `credscope rules list` for the compiled catalog. Run `credscope explain CRD304` for a specific rule title.

Zero-weight limitation rules remain visible without adding risk points. Repository configuration may disable a rule under `rules` or suppress a matched rule under `ignore.rules`; suppressions require reasons and are reported as ignored metadata.

Rotation remediation is emitted only when an imported scanner finding independently indicates secret-like material. Public configuration, operational settings, and credential identifiers do not receive rotation advice from name heuristics alone.
