# Rule catalog v1

Every rule has a stable ID, category, default severity, weight, default confidence, evidence requirements, remediation ID, enabled state, and scoring-policy version. Catalog entries are Go data, while structural matching is isolated from input parsers.

| ID | Title | Weight | Default confidence |
| --- | --- | ---: | --- |
| CRD101 | Credential finding imported | 15 | Confirmed |
| CRD102 | Credential referenced by workflow | 8 | Confirmed |
| CRD103 | Credential used by multiple jobs | 8 | High |
| CRD104 | Credential used by pull_request_target | 16 | High |
| CRD201 | Workflow grants write permission | 12 | Confirmed |
| CRD202 | Workflow grants write-all | 20 | Confirmed |
| CRD203 | Secret passed to shell | 12 | Confirmed |
| CRD204 | Secret passed to third-party action | 10 | Confirmed |
| CRD205 | Third-party action uses mutable reference | 7 | Confirmed |
| CRD206 | Secret propagated through job output | 12 | Confirmed |
| CRD207 | Missing explicit workflow permissions | 5 | High |
| CRD208 | Credential reaches production environment | 12 | Medium |
| CRD301 | Credential passed to Compose service | 8 | Confirmed |
| CRD302 | Credential reaches privileged service | 18 | Confirmed |
| CRD303 | Credential reaches a published host port | 8 | Medium |
| CRD304 | Credential reaches Docker socket mount | 20 | Confirmed |
| CRD305 | Credential reaches host-network service | 12 | Confirmed |
| CRD306 | Credential shared across multiple services | 8 | Confirmed |
| CRD307 | Credential reaches writable host bind mount | 10 | High |
| CRD308 | Container user cannot be confirmed as non-root | 3 | Low |
| CRD401 | Credential shared across CI and runtime | 15 | High |
| CRD402 | Credential reaches multiple production components | 10 | Medium |
| CRD403 | Credential reaches write permissions and a deployment environment | 14 | High |
| CRD404 | Credential has multiple independent reachability paths | 8 | High |
| CRD501 | Reusable workflow unresolved | 0 | Unknown |
| CRD502 | Runtime permissions cannot be confirmed | 0 | Unknown |
| CRD503 | Actual external network exposure cannot be confirmed | 0 | Unknown |

## Cross-component semantics

`CRD401` requires evidence that one credential reaches both GitHub Actions and a directly receiving Compose service. `CRD402` requires at least two production-like environment or service nodes. `CRD403` requires both an explicit write permission and a declared deployment environment. `CRD404` counts independent workflow, multi-job, and service branches without treating one workflow and its single child job as two independent components.

Production-like names are a Medium-confidence inference. A published host port means the service may be reachable depending on host and network configuration. An omitted Compose `user` is Low confidence and does not prove root execution. Unresolved reusable workflows and runtime conditions remain Unknown.

## Remediation

Matched rules map to stable `REM001`–`REM020` recommendations. Equivalent recommendations are deduplicated while retaining all triggering rule IDs, evidence-path IDs, and affected locations. They are ordered by priority then ID. AWS-named workflow credentials additionally receive a conditional OIDC recommendation. No remediation modifies repository content.
