# Risk scoring and confidence

CredScope scoring policy v2 produces two independent results for every analyzed item:

- **Risk score** estimates the significance of confirmed or inferred static exposure conditions.
- **Evidence confidence** describes how strongly repository evidence supports those conditions.

Confidence never multiplies or reduces risk points. A low-confidence condition may still have a risk contribution, but the report labels it inferred and shows its confidence separately.

## Severity thresholds

| Score | Severity |
| ---: | --- |
| 0–19 | Informational |
| 20–39 | Low |
| 40–59 | Medium |
| 60–79 | High |
| 80–100 | Critical |

Scores are capped at 100. Each rule contributes at most once per analyzed item. An affected-component adjustment adds 10% for each additional independently affected node, up to 30%, using deterministic integer half-up rounding.

## Classification gate

Items classified as `public_configuration`, `operational_setting`, or `credential_identifier` receive no credential-exposure risk points. They remain in reports with classification reasoning and static context. An imported scanner finding overrides weak name heuristics, classifies the item as a secret, and makes rotation remediation applicable.

Name-based secret classification indicates expected secret material; it is not proof that a secret value exists or was exposed.

## Profile adjustments

Profile adjustments affect risk only. Published host-port context (`CRD303`) uses these adjustments:

| Selected profile | Risk adjustment |
| --- | ---: |
| `local` | −60% |
| `ci` | −50% |
| `auto` fallback | −25% |
| `staging` | 0% |
| `production` | +30% |

These adjustments do not claim internet exposure. Loopback bindings and local profiles reduce concern; repository evidence still cannot establish firewall policy or deployed reachability.

Loopback-only bindings (`localhost`, `127.0.0.0/8`, or `::1`) remain visible as exposure context but do not trigger `CRD303`. Under the `production` profile, broad sharing rules (`CRD103`, `CRD306`, `CRD401`, `CRD402`, and `CRD404`) receive a 15% increase. Privileged-runtime rules (`CRD302`, `CRD304`, `CRD305`, and `CRD307`) receive a 20% increase. Every changed contribution records the selected profile and adjustment.

## Contribution fields

Machine reports record the base weight, bounded adjustments, adjusted weight, final risk contribution, condition status (`confirmed` or `inferred`), evidence confidence, `risk_or_confidence`, and whether the profile changed the contribution.

Overall evidence confidence is summarized from matched conditions. `confirmed`, `high`, `medium`, `low`, and `unknown` remain descriptive evidence levels and do not alter the risk score.
