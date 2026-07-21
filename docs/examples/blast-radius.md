# CredScope blast-radius graph

Repository: `write-all`

Scoring policy: `v1`

Rule catalog: `v1`

## Credential summary

| Credential | Score | Severity | Matched rules |
| --- | ---: | --- | --- |
| CRITICAL_DEMO_TOKEN | 100/100 | critical | CRD102, CRD103, CRD104, CRD201, CRD202, CRD203, CRD204, CRD205, CRD208, CRD301, CRD302, CRD303, CRD304, CRD305, CRD307, CRD308, CRD401, CRD402, CRD403, CRD404, CRD501, CRD502, CRD503 |

```mermaid
graph TD
    n_aab579635d96681b["CRITICAL_DEMO_TOKEN"]
    n_e55716109c33a6c4["production-api"]
    n_c67f312f0811ecfb["production"]
    n_613d080783560c8c["example-vendor/deploy-action@v1"]
    n_4acb388e661caccf[".github/workflows/critical.yml"]
    n_e8433fd79890fee4["compose.yml"]
    n_d8da89e9f5954e27["call-reusable"]
    n_31b159bf66ecad27["deploy"]
    n_9ea616ac3e0b5dfa["all:write-all"]
    n_f51c7948bac77987["published 9443 -&gt; 443"]
    n_cff4cc313e5121bf["repository"]
    n_e4e9f75f3e9fb39b["example-vendor/reusable/.github/workflows/deploy.yml@v1"]
    n_8afd0c9ae716ad5e["Inert credential demonstration"]
    n_36fb9c0b350c20a4["Mutable third-party demonstration"]
    n_23c9e84d4d6803a9["workflow_dispatch"]
    n_275cb672aee69d22["pull_request_target"]
    n_02be34489288c34f["./demo-config:/app/config"]
    n_cb4c759ca6aaeeb6["/var/run/docker.sock:/var/run/docker.sock"]
    n_b3b421dc7f878995["Synthetic critical scenario"]
    n_31b159bf66ecad27 -->|USES_ENVIRONMENT| n_c67f312f0811ecfb
    n_b3b421dc7f878995 -->|HAS_PERMISSION| n_9ea616ac3e0b5dfa
    n_b3b421dc7f878995 -->|TRIGGERED_BY| n_23c9e84d4d6803a9
    n_aab579635d96681b -->|REFERENCED_BY| n_b3b421dc7f878995
    n_e55716109c33a6c4 -->|MOUNTS| n_02be34489288c34f
    n_aab579635d96681b -->|PASSED_TO| n_e55716109c33a6c4
    n_aab579635d96681b -->|PASSED_TO| n_31b159bf66ecad27
    n_e55716109c33a6c4 -->|DETECTED_IN| n_e8433fd79890fee4
    n_36fb9c0b350c20a4 -->|RUNS_ACTION| n_613d080783560c8c
    n_b3b421dc7f878995 -->|DETECTED_IN| n_4acb388e661caccf
    n_e55716109c33a6c4 -->|PUBLISHES_PORT| n_f51c7948bac77987
    n_aab579635d96681b -->|PASSED_TO| n_d8da89e9f5954e27
    n_aab579635d96681b -->|REFERENCED_BY| n_b3b421dc7f878995
    n_aab579635d96681b -->|PASSED_TO| n_36fb9c0b350c20a4
    n_e8433fd79890fee4 -->|DETECTED_IN| n_cff4cc313e5121bf
    n_b3b421dc7f878995 -->|TRIGGERED_BY| n_275cb672aee69d22
    n_8afd0c9ae716ad5e -->|EXECUTED_BY| n_31b159bf66ecad27
    n_4acb388e661caccf -->|DETECTED_IN| n_cff4cc313e5121bf
    n_aab579635d96681b -->|PASSED_TO| n_31b159bf66ecad27
    n_d8da89e9f5954e27 -->|REFERENCED_BY| n_b3b421dc7f878995
    n_e55716109c33a6c4 -->|MOUNTS| n_cb4c759ca6aaeeb6
    n_36fb9c0b350c20a4 -->|EXECUTED_BY| n_31b159bf66ecad27
    n_d8da89e9f5954e27 -->|CALLS_WORKFLOW| n_e4e9f75f3e9fb39b
    n_aab579635d96681b -->|PASSED_TO| n_8afd0c9ae716ad5e
    n_aab579635d96681b -->|REFERENCED_BY| n_b3b421dc7f878995
    n_31b159bf66ecad27 -->|REFERENCED_BY| n_b3b421dc7f878995
```
