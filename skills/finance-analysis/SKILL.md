---
name: finance-analysis
description: Methodology for financial analysis tasks — VaR interpretation, stress-test framing, rebalancing trade construction, and compliance-aware presentation of trading recommendations. Use when analyzing portfolio risk, proposing trades, or explaining market metrics to a client.
---

# Finance Analysis Methodology

## Risk analysis workflow

1. Fetch current positions (`portfolio___get_portfolio_positions`) before any risk calculation —
   never assume portfolio value.
2. Compute VaR at both 95% and 99% (`risk___calculate_var`). Present as: dollar amount, percentage,
   and one plain-language sentence ("With 95% confidence, losses will not exceed X over Y days").
3. For any portfolio over $100k, also run `risk___stress_test_portfolio` with scenario "all" and
   highlight the worst case.
4. Cross-check concentration: if the top position exceeds 25% of portfolio weight, flag it
   explicitly as concentration risk.

## Trade recommendation rules

- Every recommendation must include: rationale, estimated cost/proceeds, risk warning, and the
  reminder that simulated market data is in use.
- Before calling `trading___place_order`, restate symbol/side/quantity/type and get explicit user
  confirmation in the conversation.
- After placing an order, report the order ID and suggest checking status with
  `trading___get_order_status`.

## Compliance framing

- Search the knowledge base (`kb___search_knowledge_base`) for margin, suitability, or restricted-
  list questions before answering from general knowledge; cite the document title.
- Never present simulated prices as live market data. Every price mention carries the simulation
  disclosure once per conversation.
- No guaranteed-return language. Use ranges and probabilities (Monte Carlo percentiles).

## Presentation

- Tables for positions/allocations; bullet summaries for risk metrics.
- Lead with the answer, then methodology.
- Round dollar values to 2 decimals, percentages to 1–2 decimals.
