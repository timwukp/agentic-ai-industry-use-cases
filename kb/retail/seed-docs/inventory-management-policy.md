# Inventory Management Policy (Demo Retailer)

Document ID: POL-INV-001 | Effective: 2026-01-01 | Owner: VP Supply Chain

## ABC classification and service targets

| Class | Definition | Target fill rate | Cycle count |
|-------|------------|------------------|-------------|
| A | Top ~20% of SKUs, ~80% of revenue | 98% | Weekly |
| B | Next ~30% of SKUs, ~15% of revenue | 95% | Monthly |
| C | Bottom ~50% of SKUs, ~5% of revenue | 90% | Quarterly |

- A-class items always take priority in reorder, allocation, and expedite decisions.
- C-class items with turnover below 2x/year are reviewed quarterly for discontinuation.

## Reorder policy

- Standard reorder point: average daily sales x lead time + safety stock.
- Safety stock: 7 days of average daily sales (14 days for single-source items and
  during holiday peak, Nov 1 - Jan 15).
- Order quantity: Economic Order Quantity (EOQ) unless supplier minimums or truckload
  economics dictate otherwise. Document any override.
- Purchase orders above $50,000 require category manager approval; above $250,000
  require VP approval.

## Stockout response

- A-class stockout: expedite review within 4 business hours; consider inter-location
  transfer before emergency PO.
- Record estimated lost revenue for every stockout day; feed into the weekly S&OP
  review.

## Overstock and markdown

- Overstock threshold: > 60 days of supply for A/B items, > 120 days for C items.
- Markdown ladder: 25% → 40% → 60% at 3-week intervals; clearance objective pricing
  requires margin sign-off below cost.

## Pricing guardrails

- No automated price change may exceed ±15% in a single move without human approval.
- Price matching applies only to the tracked competitor set and identical SKUs.
