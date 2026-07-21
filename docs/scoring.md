# Scoring policy v1

CredScope scores each credential independently from matched rule evidence. Scores are deterministic integers from 0 to 100. A rule contributes at most once per credential, so duplicate scanner findings or equivalent evidence cannot multiply risk without bound.

## Calculation

For each matched rule:

1. Start with the catalog weight.
2. Add 10% for each additional distinct affected node, capped at 30%.
3. Round the adjusted weight to the nearest integer, with halves rounded up.
4. Apply the confidence multiplier.
5. Round the final contribution the same way.
6. Sum contributions and cap the result at 100.

Warning-only `CRD5xx` rules have weight zero. They remain in the match and contribution breakdown but do not increase the score.

## Confidence multipliers

| Confidence | Multiplier | Meaning |
| --- | ---: | --- |
| Confirmed | 100% | Directly represented by parsed repository structure |
| High | 90% | Strong structural inference with limited uncertainty |
| Medium | 70% | Naming or exposure inference that depends on deployment context |
| Low | 40% | Weak static indicator, such as an omitted container user |
| Unknown | 0% | Runtime state cannot be established offline |

The overall confidence is a contribution-weighted average: at least 95 is Confirmed, at least 80 is High, at least 55 is Medium, and lower non-zero values are Low. An analysis with no positive contribution is Unknown. Confidence counts include zero-point warning matches so consumers can display uncertainty separately.

## Severity boundaries

| Score | Severity |
| ---: | --- |
| 0–19 | Informational |
| 20–39 | Low |
| 40–59 | Medium |
| 60–79 | High |
| 80–100 | Critical |

## Duplicate suppression

- Equivalent Gitleaks findings are deduplicated by the Phase 2 adapter.
- Equivalent graph nodes and evidence-bearing edges share stable IDs.
- Evidence paths with identical ordered node and edge IDs are deduplicated.
- The scoring engine retains one match per rule and credential.
- Multiple components affect only the bounded adjustment, not an unlimited repeated base weight.

Scores describe static structural blast radius. They do not prove credential validity, exploitability, effective cloud IAM permissions, or internet reachability.
