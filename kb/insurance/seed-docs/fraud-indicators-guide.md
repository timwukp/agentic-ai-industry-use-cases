# Fraud Indicators Guide (Demo Carrier SIU)

Document ID: GUI-FRAUD-001 | Effective: 2026-01-01 | Owner: Special Investigation Unit

## Screening policy

- Every new claim is screened automatically at intake and again at assessment.
- Composite fraud risk score thresholds:
  - Score > 0.7: refer to SIU (REFER_TO_SIU). Do not issue settlement until cleared.
  - Score 0.4-0.7: enhanced review (ENHANCED_REVIEW) by a senior adjuster.
  - Score <= 0.4: standard processing.

## Indicator catalog (weights used by the screening model)

| Indicator | Severity | Weight |
|-----------|----------|--------|
| Prior fraud history in database | CRITICAL | 0.20 |
| Claim filed within 30 days of policy inception | HIGH | 0.15 |
| Staged accident indicators | HIGH | 0.15 |
| Multiple claims in short period | HIGH | 0.12 |
| Provider on watch list | HIGH | 0.12 |
| Inconsistent damage description vs photos | MEDIUM | 0.10 |
| Inconsistent witness statements | MEDIUM | 0.09 |
| Claim amount near policy limit | MEDIUM | 0.08 |
| Unusual geographic pattern | MEDIUM | 0.07 |
| Late reporting of incident | LOW | 0.05 |

## SIU referral procedure

1. Freeze settlement processing; document the triggering indicators.
2. Complete the fraud investigation report (executive summary, evidence, financial
   impact, recommendation) within 15 business days.
3. Recommendations: DENY_CLAIM, REDUCE_SETTLEMENT, REFER_TO_LAW_ENFORCEMENT, or
   CLOSE_NO_FRAUD.
4. State fraud bureau notification is mandatory where required by law; consult
   compliance before external referral.

## Anti-retaliation and fairness

- A fraud flag is an investigation trigger, not a determination. Communicate neutrally
  with claimants during investigation.
- False positive review: any claim cleared after SIU referral is fed back to model
  tuning monthly.
