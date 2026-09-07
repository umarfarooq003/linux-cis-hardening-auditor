# Scoring methodology

## Overall score (0–100)

Each evaluated control contributes a **weight** derived from its severity:

| Severity | Weight |
|---|---|
| CRITICAL | 10 |
| HIGH | 6 |
| MEDIUM | 3 |
| LOW | 1 |
| INFO | 0 |

Only `PASS`, `FAIL` and `WARN` participate. `NOT_APPLICABLE` and `ERROR` are excluded from **both** the numerator and the denominator, so an inapplicable or errored control never moves the score.

```
earned      = Σ weight(PASS) + (1 − warn_factor) · Σ weight(WARN)
achievable  = Σ weight(PASS) + Σ weight(FAIL) + Σ weight(WARN)
score       = round(100 × earned / achievable)      # 100 if achievable == 0
```

`warn_factor` defaults to **0.5** (configurable via `warn_weight_factor`), so a `WARN` is a *partial failure* worth half its weight.

## Why weighting?

A flat pass/fail ratio would let a swarm of `LOW` checks mask a failing `CRITICAL` control. Weighting keeps the score aligned with real risk: fixing one `HIGH` finding moves the needle more than fixing six `LOW` ones.

## Worked examples

| Findings | earned / achievable | Score |
|---|---|---|
| HIGH pass, LOW pass | 7 / 7 | **100** |
| CRITICAL fail | 0 / 10 | **0** |
| LOW pass + CRITICAL fail | 1 / 11 | **9** |
| HIGH pass + HIGH warn | (6 + 3) / 12 | **75** |
| HIGH pass, HIGH N/A, HIGH error | 6 / 6 | **100** |

## Category scores

The identical formula is applied per category. A category's `total` counts only its scored (`PASS`/`FAIL`/`WARN`) controls. This makes it obvious *where* a low overall score comes from (e.g. `SSH 25%` vs `Filesystem 91%`).

## Risk prioritization

Failing findings are ordered by **severity rank (desc)**, then `FAIL` before `WARN`, then category/rule ID, and numbered `Priority 1..N`. Each item carries severity, affected configuration, reason, and recommended action — this is the actionable remediation plan shown in the HTML report and the `audit` table output.
