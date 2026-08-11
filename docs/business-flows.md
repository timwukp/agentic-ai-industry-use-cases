# Business Logic Flows — Six Industry Use Cases

[繁體中文](business-flows.zh-TW.md)

How each industry agent actually runs its business process — written for practitioners, not
engineers. Every diagram uses the same grammar: the **spine** (top to bottom) is the business
process; the **left rail** holds the systems and policy documents the process reads; the
**right rail** holds the humans it escalates to. Blue `AI` steps are agent-executed, amber
diamonds are decision gates, rose `COMPLIANCE` boxes are regulatory checkpoints, green
`WRITE` boxes are the only steps that change state — and every one of them sits behind a
confirmation or an approval. Thresholds shown are the ones actually enforced in the agents'
prompts, tools, and knowledge-base policies.

The animated SVGs are generated from declarative specs in
[`business-flows/generate_business_flows.py`](business-flows/generate_business_flows.py)
(with a geometric no-crossing check); the collapsed Mermaid block under each diagram is the
same logic emitted by `--mermaid` — **edit the spec, regenerate both, never hand-edit**.

---

## Finance Trading — Signal to Executed Order

A trading desk lives and dies by knowing *what kind* of number it is looking at. This agent
labels every figure with its data world — **LIVE** (Finnhub/FRED market data), **DERIVED**
(news-scored factor signals, hypothesis-grade), **MODEL** (PRISM regime and tail-risk
output), or **SIMULATED** (demo book) — and never mixes them silently. The PRISM regime read
is deliberately positioned as a historical lens (AUROC 0.85–0.91 against NBER recessions,
but lagging real time by more than 10 trading days): it explains where you have been, and
the agent will refuse to turn it into a crash date.

The path from signal to order runs through two hard gates. Any margin call over $250k
escalates to the Risk Desk the same day, per the margin policy (Reg T 50/30, concentration
surcharges above 40% of account). And no solicited recommendation leaves the suitability
check without matching the client's profile matrix — a Conservative client cannot be shown a
leveraged-ETF idea, full stop; anything out of profile needs a supervisor's documented
sign-off. Only then does the confirm-then-execute rule apply: symbol, side, quantity, and
order type are read back to the client before `place_order` touches the book.

![Finance trading business flow](business-flows/finance-trading.svg)

<details>
<summary>Flow logic (Mermaid — editable source)</summary>

```mermaid
flowchart TD
    classDef ai fill:#1e293b,stroke:#3b82f6,color:#e2e8f0
    classDef write fill:#1e293b,stroke:#22c55e,color:#e2e8f0
    classDef compliance fill:#1e293b,stroke:#f43f5e,color:#e2e8f0
    classDef human fill:#1e293b,stroke:#f59e0b,color:#e2e8f0
    classDef escalation fill:#3f1d2b,stroke:#f43f5e,color:#fecdd3
    classDef data fill:#164e63,stroke:#06b6d4,color:#e2e8f0
    classDef gate fill:#1e293b,stroke:#f59e0b,color:#fcd34d
    intel["Market intelligence — quotes · macro · news factors"]:::ai
    prism["Regime & signal read (PRISM) — regime = lens, never a timing signal"]:::ai
    port["Portfolio review — positions · P&L · concentration"]:::ai
    risk["Risk assessment — VaR · stress tests · Monte Carlo"]:::ai
    g_margin{"margin call?"}:::gate
    suit["Suitability & compliance check — profile matrix · restricted list"]:::compliance
    g_profile{"in profile?"}:::gate
    confirm["Client confirmation — symbol · side · quantity · type"]:::human
    order["Order placement & management — market fills now · limit stays open"]:::write
    worlds[("Data worlds (labeled)")]:::data
    kb[("KB: margin & suitability policy")]:::data
    riskdesk["Risk Desk — margin calls > $250k"]:::escalation
    super["Supervisor approval — documented rationale required"]:::human
    intel --> prism
    prism --> port
    port --> risk
    risk --> g_margin
    g_margin -->|"none / cured"| suit
    suit --> g_profile
    g_profile -->|"within client risk profile"| confirm
    confirm --> order
    g_margin -->|"> $250k same day"| riskdesk
    g_profile -->|"out-of-profile rec"| super
    worlds -.-> intel
    kb -.-> suit
```

</details>

### Decision gates & guardrails

| Gate | Threshold / trigger | Source policy | Human in the loop |
|---|---|---|---|
| Margin call escalation | call > $250k | `kb/finance/seed-docs/margin-policy.md` | Risk Desk, same day |
| Suitability | recommendation outside profile matrix | `kb/finance/seed-docs/suitability-and-restricted-list.md` | supervisor approval, documented rationale |
| Restricted list | MNPI names · first 10 days post-IPO · SEC suspensions | same | trade blocked |
| Order execution | every order | agent prompt (confirm-then-execute) | client confirms symbol/side/qty/type |

**KPIs:** calibrated 99% VaR (~1.0% violations, Basel green) · regime AUROC 0.85–0.91 ·
zero unsuitable solicited recommendations

---

## Healthcare — Chart Review to Care Plan

Everything in this flow is decision *support*: the agent assembles the chart, scores the
risks, and drafts the plan, but a licensed clinician reviews before anything touches a
patient. The flow cannot even start without HIPAA discipline — two identifiers to verify the
patient, minimum-necessary access, and every record touch audit-logged (who, when, why; six
years' retention).

Two gates protect the clinical middle of the process. Triage follows the RED/ORANGE ladder —
chest pain, stroke signs, or anaphylaxis hand off to the ED immediately, and patients aged
65+ or 5 and under are auto-escalated one level. Then medication safety: a major interaction
(warfarin + aspirin, sertraline + tramadol, and the rest of the curated table) stops the
line until the prescriber acknowledges it. Downstream, care planning turns a LACE+ readmission
score of 30% or more into a transitional-care visit within 7 days, and the only write
actions in the whole flow are appointment scheduling and reminders — which may state date,
time, and provider, but never a diagnosis.

![Healthcare business flow](business-flows/healthcare-medical.svg)

<details>
<summary>Flow logic (Mermaid — editable source)</summary>

```mermaid
flowchart TD
    classDef ai fill:#1e293b,stroke:#3b82f6,color:#e2e8f0
    classDef write fill:#1e293b,stroke:#22c55e,color:#e2e8f0
    classDef compliance fill:#1e293b,stroke:#f43f5e,color:#e2e8f0
    classDef human fill:#1e293b,stroke:#f59e0b,color:#e2e8f0
    classDef escalation fill:#3f1d2b,stroke:#f43f5e,color:#fecdd3
    classDef data fill:#164e63,stroke:#06b6d4,color:#e2e8f0
    classDef gate fill:#1e293b,stroke:#f59e0b,color:#fcd34d
    verify["Patient identity verification — two identifiers · minimum necessary"]:::compliance
    chart["Chart review — summary · meds · labs · notes"]:::ai
    triage["Clinical assessment & triage — red flags · ICD-10 differentials"]:::ai
    g_triage{"triage level?"}:::gate
    ix["Interactions & risk scores — drug pairs · ASCVD · Morse · LACE+"]:::ai
    g_ix{"major interaction?"}:::gate
    care["Care planning — care gaps · LACE+ ≥30% → transitional"]:::ai
    sched["Scheduling & reminders — no diagnosis in any reminder"]:::write
    pop["Population health roll-up — HEDIS gaps · prevalence · utilization"]:::ai
    ehr[("EHR (HIPAA audit-logged)")]:::data
    kb[("KB: clinical protocols")]:::data
    ed["ED / 911 handoff — chest pain · stroke · anaphylaxis"]:::escalation
    rx["Prescriber acknowledgment — required before dispensing"]:::human
    verify --> chart
    chart --> triage
    triage --> g_triage
    g_triage -->|"URGENT / ROUTINE · age auto-escalation"| ix
    ix --> g_ix
    g_ix -->|"none found (list non-exhaustive)"| care
    care --> sched
    sched --> pop
    g_triage -->|"EMERGENCY (RED)"| ed
    g_ix -->|"major pair flagged"| rx
    ehr -.-> chart
    kb -.-> ix
```

</details>

### Decision gates & guardrails

| Gate | Threshold / trigger | Source policy | Human in the loop |
|---|---|---|---|
| Identity verification | two identifiers before any disclosure | `kb/healthcare/seed-docs/hipaa-phi-handling-policy.md` | disclosure blocked otherwise |
| Triage | EMERGENCY (RED) symptoms · age ≥65 / ≤5 auto-escalates | `kb/healthcare/seed-docs/clinical-protocols.md` | ED / 911 handoff |
| Drug interaction | major-severity pair | `kb/healthcare/seed-docs/medication-safety-protocol.md` | prescriber acknowledgment before dispensing |
| Readmission risk | LACE+ ≥ 30% | clinical protocols | transitional-care visit ≤ 7 days |

**KPIs:** HbA1c < 7.0% (individualized < 8.0%) · BP < 130/80 high-risk · 100% audit-logged
access · critical labs flagged immediately

---

## Insurance Claims — FNOL to Settlement

The manual's first rule is speed with discipline: acknowledge within 24 hours, assign an
adjuster within 48, and set the initial reserve within 5 business days (Chain-Ladder and
Bornhuetter-Ferguson, P10/P50/P90). But nothing moves toward payment until the mandatory
fraud screen has scored the claim: at 0.4 or below it runs the standard track; between 0.4
and 0.7 a senior adjuster runs enhanced review; above 0.7 it goes to SIU **and the
settlement freezes** until the investigation clears — with all claimant communication kept
neutral, because a fraud flag is an investigation trigger, not a determination.

Money then moves only inside the authority ladder: an adjuster signs to $10k, a supervisor
to $25k (and reviews everything above $25k regardless), a director to $100k, and beyond that
a committee. Every determination cites policy language; every denial is written. The
fair-claims clock runs the whole time — respond in 10 business days, decide within 40 days
of proof of loss or send a written delay notice every 30.

![Insurance claims business flow](business-flows/insurance-claims.svg)

<details>
<summary>Flow logic (Mermaid — editable source)</summary>

```mermaid
flowchart TD
    classDef ai fill:#1e293b,stroke:#3b82f6,color:#e2e8f0
    classDef write fill:#1e293b,stroke:#22c55e,color:#e2e8f0
    classDef compliance fill:#1e293b,stroke:#f43f5e,color:#e2e8f0
    classDef human fill:#1e293b,stroke:#f59e0b,color:#e2e8f0
    classDef escalation fill:#3f1d2b,stroke:#f43f5e,color:#fecdd3
    classDef data fill:#164e63,stroke:#06b6d4,color:#e2e8f0
    classDef gate fill:#1e293b,stroke:#f59e0b,color:#fcd34d
    fnol["FNOL intake — acknowledge 24h · assign adjuster 48h"]:::write
    verify["Policy & coverage verification — active? premium paid? exclusions?"]:::ai
    fraud["Mandatory fraud screen — weighted indicators → score 0-1"]:::compliance
    g_fraud{"fraud score?"}:::gate
    damage["Damage assessment — fast-track / standard / investigation"]:::ai
    reserve["Reserve estimation — Chain-Ladder + BF · initial ≤ 5 days"]:::ai
    settle["Settlement calculation — deductible · depreciation · limits"]:::ai
    g_auth{"within authority?"}:::gate
    pay["Payment — itemized · written basis · cite policy"]:::write
    kb[("KB: claims-handling manual")]:::data
    ladder[("Authority ladder")]:::data
    enh["Enhanced review — senior adjuster"]:::human
    siu["SIU investigation — report ≤ 15 days · neutral comms"]:::escalation
    signoff["Supervisor / Director sign-off — > $100k adds committee review"]:::human
    fnol --> verify
    verify --> fraud
    fraud --> g_fraud
    g_fraud -->|"≤ 0.4 standard track"| damage
    damage --> reserve
    reserve --> settle
    settle --> g_auth
    g_auth -->|"adjuster ≤ $10k"| pay
    g_fraud -->|"0.4 - 0.7"| enh
    g_fraud -->|"> 0.7 · freeze settlement"| siu
    g_auth -->|"$25k / $100k / above"| signoff
    kb -.-> fraud
    ladder -.-> g_auth
    siu -->|"cleared → resume"| settle
```

</details>

### Decision gates & guardrails

| Gate | Threshold / trigger | Source policy | Human in the loop |
|---|---|---|---|
| Fraud screen | score 0.4–0.7 / > 0.7 | `kb/insurance/seed-docs/fraud-indicators-guide.md` | enhanced review / SIU + settlement freeze |
| Settlement authority | > $10k / $25k / $100k | `kb/insurance/seed-docs/claims-handling-manual.md` | adjuster / supervisor / director + committee |
| Severe or total loss | before any offer | claims-handling manual | independent adjuster verification |
| Claim submission & approval | every write | agent prompt | user confirms policy no., type, amount, rationale |

**KPIs:** acknowledge ≤ 24h · assign ≤ 48h · initial reserve ≤ 5 days · decide ≤ 40 days ·
SIU report ≤ 15 days

---

## Retail Inventory — Stockout to Reorder to Price

The policy is unambiguous about priorities: A-class items (top 20% of SKUs, ~80% of revenue)
carry a 98% fill-rate target and any A-class stockout gets an expedite review within 4
business hours — and the network is checked first, because an inter-store transfer beats an
emergency purchase order on both speed and cost. Reorders come out of the EOQ model with
safety stock at 7 days (14 for single-source suppliers and the Nov–Jan holiday peak);
overrides for supplier minimums or truckload economics are documented, not silent.

Buying runs through the supplier scorecard (35% on-time, 30% quality, 20% cost, 15%
responsiveness): PREFERRED at 90+, PROBATIONARY below 75 — which means a 90-day improvement
plan and no new SKUs. Purchase orders above $50k need the category manager; above $250k, the
VP. On the sell side the same discipline applies in reverse: no automated price move beyond
±15% in one step, markdowns walk the 25/40/60 ladder at 3-week intervals, and below-cost
pricing needs margin sign-off. Sell-through feeds the next forecast cycle.

![Retail inventory business flow](business-flows/retail-inventory.svg)

<details>
<summary>Flow logic (Mermaid — editable source)</summary>

```mermaid
flowchart TD
    classDef ai fill:#1e293b,stroke:#3b82f6,color:#e2e8f0
    classDef write fill:#1e293b,stroke:#22c55e,color:#e2e8f0
    classDef compliance fill:#1e293b,stroke:#f43f5e,color:#e2e8f0
    classDef human fill:#1e293b,stroke:#f59e0b,color:#e2e8f0
    classDef escalation fill:#3f1d2b,stroke:#f43f5e,color:#fecdd3
    classDef data fill:#164e63,stroke:#06b6d4,color:#e2e8f0
    classDef gate fill:#1e293b,stroke:#f59e0b,color:#fcd34d
    stock["Stock position check — ABC classes · fill targets 98/95/90%"]:::ai
    forecast["Demand forecast — seasonality · confidence intervals"]:::ai
    reorder["Reorder computation — EOQ + safety stock 7d (14d peak)"]:::ai
    g_net{"network stock?"}:::gate
    supplier["Supplier evaluation — tiers: PREFERRED ≥90 · APPROVED ≥75"]:::ai
    po["Purchase order — terms · delivery · line items"]:::write
    g_po{"PO value?"}:::gate
    price["Pricing & markdown — auto moves capped ±15% · 25/40/60 ladder"]:::ai
    kb[("KB: inventory policy")]:::data
    transfer["Inter-store transfer — A-class stockout: expedite ≤ 4h"]:::write
    approvals["Category manager / VP — > $50k cat-mgr · > $250k VP"]:::human
    stock --> forecast
    forecast --> reorder
    reorder --> g_net
    g_net -->|"none free → buy"| supplier
    supplier --> po
    po --> g_po
    g_po -->|"within buyer authority"| price
    g_net -->|"another store has it"| transfer
    g_po -->|"> $50k / > $250k"| approvals
    kb -.-> supplier
    price -->|"sell-through feeds next cycle"| forecast
```

</details>

### Decision gates & guardrails

| Gate | Threshold / trigger | Source policy | Human in the loop |
|---|---|---|---|
| Network stock check | transfer available | `kb/retail/seed-docs/inventory-management-policy.md` | user confirms SKU/qty/locations |
| PO authority | > $50k / > $250k | inventory management policy | category manager / VP |
| Price move | > ±15% in one step, or below cost | inventory management policy | human approval / margin sign-off |
| Single-source risk | no qualified alternate | `kb/retail/seed-docs/supplier-sla-standards.md` | signed risk acceptance |

**KPIs:** fill rates 98/95/90% by class · A-class stockout response ≤ 4h · supplier on-time
≥ 95% · quality ≥ 98.5% · defects ≤ 1,500 PPM

---

## Manufacturing — Sensor to Work Order

Vibration severity is read straight off ISO 10816 Class III: zone C (4.5–11.2 mm/s RMS)
means plan maintenance within two weeks; zone D above 11.2 means the machine stops — on
high-criticality equipment that is an immediate stop, shift-supervisor notification, and a
critical work order in the same shift. Between the sensors and the schedule sits the
diagnostic layer: FFT against the bearing defect frequencies (BPFO/BPFI/BSF/FTF — a defect
tone above 25% of the 1X peak, trending up across two measurements, raises a predictive work
order), anomaly detection, and remaining-useful-life estimation. Predictive triggers override
calendar PMs; the plant target is OEE 75% with reactive work below 30%.

No work order is approved without its permits listed — lockout/tagout for any
energy-isolating work (one lock per authorized worker, only the applier removes it), plus
confined-space and hot-work permits where they apply. Spare parts below $1k auto-issue;
anything at or above needs procurement sign-off. Closing the loop, reliability KPIs
(OEE, MTBF, MTTR) feed back into monitoring thresholds — deferred maintenance is possible,
but only with the reliability manager's documented risk acceptance.

![Manufacturing maintenance business flow](business-flows/manufacturing-maintenance.svg)

<details>
<summary>Flow logic (Mermaid — editable source)</summary>

```mermaid
flowchart TD
    classDef ai fill:#1e293b,stroke:#3b82f6,color:#e2e8f0
    classDef write fill:#1e293b,stroke:#22c55e,color:#e2e8f0
    classDef compliance fill:#1e293b,stroke:#f43f5e,color:#e2e8f0
    classDef human fill:#1e293b,stroke:#f59e0b,color:#e2e8f0
    classDef escalation fill:#3f1d2b,stroke:#f43f5e,color:#fecdd3
    classDef data fill:#164e63,stroke:#06b6d4,color:#e2e8f0
    classDef gate fill:#1e293b,stroke:#f59e0b,color:#fcd34d
    monitor["Condition monitoring — health score · ISO 10816 zones A-D"]:::ai
    diagnose["Diagnosis — FFT bearing tones · anomalies · RUL"]:::ai
    g_zone{"Zone D + high-crit?"}:::gate
    urgency["Urgency validation — criticality x production impact"]:::ai
    parts["Parts availability — stock · lead time · alternatives"]:::ai
    g_parts{"parts cost?"}:::gate
    sched["Scheduling (permit-gated) — LOTO · confined space · hot work"]:::compliance
    wo["Work order execution — tasks · parts · labor · safety steps"]:::write
    kpi["Reliability KPIs — OEE target 75% · reactive < 30%"]:::ai
    kb[("KB: lockout-tagout policy")]:::data
    stop["Stop machine — notify shift supervisor · same-shift WO"]:::escalation
    proc["Procurement approval — order placed on sign-off"]:::human
    monitor --> diagnose
    diagnose --> g_zone
    g_zone -->|"zones A-C: plan within window"| urgency
    urgency --> parts
    parts --> g_parts
    g_parts -->|"< $1k auto-issue"| sched
    sched --> wo
    wo --> kpi
    g_zone -->|"danger zone"| stop
    g_parts -->|"≥ $1k"| proc
    kb -.-> sched
    kpi -->|"continuous improvement"| monitor
```

</details>

### Decision gates & guardrails

| Gate | Threshold / trigger | Source policy | Human in the loop |
|---|---|---|---|
| Vibration severity | zone D (> 11.2 mm/s) on high-criticality | `kb/manufacturing/seed-docs/maintenance-standards-summary.md` | stop machine · shift supervisor · same-shift WO |
| Parts cost | ≥ $1,000 | tool policy (`order_spare_parts`) | procurement approval |
| Permit gate | LOTO / confined space / hot work required | `kb/manufacturing/seed-docs/lockout-tagout-safety-policy.md` | work may not start until permits issued |
| Deferred maintenance | any deferral | maintenance standards | reliability manager risk acceptance |

**KPIs:** OEE ≥ 75% (world class 85%) · reactive share < 30% · zone C response ≤ 2 weeks ·
fire watch 60 min after hot work

---

## Real Estate — Subject Property to Value Range

This is the one flow with **zero transactional writes** — it renders opinions, and it is
disciplined about what kind. Comparables follow the appraisal methodology: sales within 6
months preferred (12 with time adjustment at ~0.3%/month), within a mile urban/suburban,
gross living area within ±25%, and the *comparable* is adjusted toward the subject — with
net adjustments over 15% or gross over 25% flagged as weakening the comp. At least two of
the three approaches (sales comparison, income, cost) are reconciled with documented
weighting, and the output is always a **range with a confidence statement, never a bare
point** — stated alongside the USPAP disclosure that an AVM/CMA is not a formal appraisal
and lending or legal use requires a licensed appraiser.

Fair Housing is a hard gate, not a preference: neighborhood demographics are never a value
factor, school quality comes only from published ratings, crime statistics are reported
neutrally, and steering is refused **even when the client requests it** — the agent provides
objective data for all areas matching the client's non-protected criteria instead. If a
completed valuation's impartiality is challenged, a second independent valuation runs and
compliance reviews within 10 business days.

![Real estate valuation business flow](business-flows/real-estate-valuation.svg)

<details>
<summary>Flow logic (Mermaid — editable source)</summary>

```mermaid
flowchart TD
    classDef ai fill:#1e293b,stroke:#3b82f6,color:#e2e8f0
    classDef write fill:#1e293b,stroke:#22c55e,color:#e2e8f0
    classDef compliance fill:#1e293b,stroke:#f43f5e,color:#e2e8f0
    classDef human fill:#1e293b,stroke:#f59e0b,color:#e2e8f0
    classDef escalation fill:#3f1d2b,stroke:#f43f5e,color:#fecdd3
    classDef data fill:#164e63,stroke:#06b6d4,color:#e2e8f0
    classDef gate fill:#1e293b,stroke:#f59e0b,color:#fcd34d
    subject["Subject property profile — characteristics · zoning · tax history"]:::ai
    comps["Comparable selection — 6-12 mo · 1 mile · ±25% GLA · adjust comp"]:::ai
    g_fh{"steering request?"}:::gate
    approaches["Three approaches to value — sales · income · cost — reconcile ≥ 2"]:::ai
    cma["CMA report (USPAP) — RANGE + confidence · never a point"]:::compliance
    g_bias{"bias challenge?"}:::gate
    market["Market context — DOM · months of supply · forecast"]:::ai
    invest["Investment analysis — cap rate · NOI · cash-on-cash · ROI"]:::ai
    mls[("MLS · assessor · market data")]:::data
    kb[("KB: fair-housing policy")]:::data
    refused["Refused — Fair Housing — even when the client requests it"]:::escalation
    second["Second independent valuation — compliance review ≤ 10 days"]:::human
    subject --> comps
    comps --> g_fh
    g_fh -->|"objective criteria only"| approaches
    approaches --> cma
    cma --> g_bias
    g_bias -->|"none raised"| market
    market --> invest
    g_fh -->|"demographics as value factor"| refused
    g_bias -->|"value challenged"| second
    mls -.-> subject
    kb -.-> g_fh
    second -->|"re-run, independent"| approaches
```

</details>

### Decision gates & guardrails

| Gate | Threshold / trigger | Source policy | Human in the loop |
|---|---|---|---|
| Fair Housing | steering request · demographics as value factor | `kb/realestate/seed-docs/fair-housing-compliance-policy.md` | refused; violations reported ≤ 24h |
| Comp quality | net adj > 15% · gross > 25% | `kb/realestate/seed-docs/appraisal-methodology-guide.md` | flagged in reconciliation |
| Formal valuation | lending / legal use | USPAP (methodology guide) | licensed appraiser required |
| Bias challenge | any challenge to impartiality | fair-housing policy | second independent valuation · review ≤ 10 days |

**KPIs:** value ranges with confidence on 100% of reports · 10% of reports spot-checked
quarterly · workfiles retained 5 years

---

*Regenerate diagrams and mermaid after any spec change:*

```bash
python3 docs/business-flows/generate_business_flows.py            # six SVGs (fails on any edge crossing)
python3 docs/business-flows/generate_business_flows.py --mermaid  # blocks pasted above
```
