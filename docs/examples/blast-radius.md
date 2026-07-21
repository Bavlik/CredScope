# CredScope static exposure graph

Repository: `write-all`

Scoring policy: `v2`

Rule catalog: `v2`

Environment profile: `production` — A Docker Compose service or profile name contains a production marker.

Profile assumptions: Published services, broad credential sharing, and privileged runtime settings receive stricter risk weighting.; Internet exposure is not assumed without direct evidence.

## Credential summary

| Item | Classification | Risk score | Confidence | Severity | Matched rules |
| --- | --- | ---: | --- | --- | --- |
| CRITICAL_DEMO_TOKEN | secret | 100/100 | high | critical | CRD102, CRD103, CRD104, CRD201, CRD202, CRD203, CRD204, CRD205, CRD208, CRD301, CRD302, CRD304, CRD305, CRD307, CRD308, CRD401, CRD402, CRD403, CRD404, CRD501, CRD502, CRD503 |

```mermaid
graph TD
    n_aab579635d96681b["CRITICAL_DEMO_TOKEN"]
    n_e55716109c33a6c4["production-api"]
    n_c67f312f0811ecfb["production"]
    n_613d080783560c8c["example-vendor/deploy-operation@v1"]
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
    n_36fb9c0b350c20a4 -->|runs_action · inferred_exposure_context| n_613d080783560c8c
    n_aab579635d96681b -->|configured_in · inferred_exposure_context| n_b3b421dc7f878995
    n_aab579635d96681b -->|explicitly_forwarded_to · confirmed_static_data_flow| n_36fb9c0b350c20a4
    n_4acb388e661caccf -->|detected_in · inferred_exposure_context| n_cff4cc313e5121bf
    n_e8433fd79890fee4 -->|detected_in · inferred_exposure_context| n_cff4cc313e5121bf
    n_e55716109c33a6c4 -->|mounts_volume · inferred_exposure_context| n_cb4c759ca6aaeeb6
    n_b3b421dc7f878995 -->|triggered_by · inferred_exposure_context| n_23c9e84d4d6803a9
    n_31b159bf66ecad27 -->|uses_environment · inferred_exposure_context| n_c67f312f0811ecfb
    n_e55716109c33a6c4 -->|detected_in · inferred_exposure_context| n_e8433fd79890fee4
    n_aab579635d96681b -->|configured_in · inferred_exposure_context| n_d8da89e9f5954e27
    n_b3b421dc7f878995 -->|has_permission · inferred_exposure_context| n_9ea616ac3e0b5dfa
    n_31b159bf66ecad27 -->|belongs_to · inferred_exposure_context| n_b3b421dc7f878995
    n_aab579635d96681b -->|referenced_by_process · confirmed_static_data_flow| n_8afd0c9ae716ad5e
    n_e55716109c33a6c4 -->|exposes_port · inferred_exposure_context| n_f51c7948bac77987
    n_e55716109c33a6c4 -->|mounts_volume · inferred_exposure_context| n_02be34489288c34f
    n_b3b421dc7f878995 -->|triggered_by · inferred_exposure_context| n_275cb672aee69d22
    n_b3b421dc7f878995 -->|detected_in · inferred_exposure_context| n_4acb388e661caccf
    n_d8da89e9f5954e27 -->|calls_workflow · inferred_exposure_context| n_e4e9f75f3e9fb39b
    n_36fb9c0b350c20a4 -->|belongs_to · inferred_exposure_context| n_31b159bf66ecad27
    n_aab579635d96681b -->|configured_in · inferred_exposure_context| n_31b159bf66ecad27
    n_d8da89e9f5954e27 -->|belongs_to · inferred_exposure_context| n_b3b421dc7f878995
    n_aab579635d96681b -->|available_to_service · confirmed_static_data_flow| n_e55716109c33a6c4
    n_8afd0c9ae716ad5e -->|belongs_to · inferred_exposure_context| n_31b159bf66ecad27
```
