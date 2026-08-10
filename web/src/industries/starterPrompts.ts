/** Starter questions shown in an empty AI Assistant pane, per industry.
 *
 * These are the first thing a visitor sees, so every prompt names an entity that
 * actually exists in the simulated data and an argument the tool actually
 * accepts. A prompt like "optimize pricing for SKU-APRL-2001 to improve margin"
 * reads fine but makes the agent call optimize_pricing(objective="margin"), which
 * the handler rejects — the valid enum is "maximize_margin". Every id and enum
 * below was checked by calling the tool.
 *
 * Ids come from the shared bases, not invention: catalog SKUs are
 * `SKU-<CAT>-<n>` (toolkit.retail_basis.CATALOG), assets are in
 * asset_basis.CRITICALITY, providers in healthcare/SchedulingSection, markets in
 * realestate/types MARKETS. Deliberately avoided: claim ids, which are redrawn
 * daily (`CLM-<year>-<hex>` seeded on today's date), so a hardcoded one goes
 * stale overnight — those prompts ask the agent to list claims and pick one.
 *
 * Each entry is one question a real practitioner in that seat would ask on
 * opening the app, ordered read-only first so the opening click never mutates
 * state.
 */

export interface StarterPrompt {
  /** Short button label — what the user scans. English canonical; tests and
   *  the census click by this. */
  label: string
  /** Catalog key for the label (i18n/messages). The PROMPT is deliberately not
   *  keyed: it is agent input carrying ids and enums the tools require, and the
   *  reply-language directive localizes the answer instead. */
  labelKey?: string
  /** The full prompt sent to the agent. */
  prompt: string
}

export const STARTER_PROMPTS: Record<string, StarterPrompt[]> = {
  finance: [
    {
      label: 'Live market brief',
      labelKey: 'starters.finance.liveBrief',
      prompt:
        'Give me a live market brief: Nasdaq and S&P levels, the Treasury yield curve with the 10Y-2Y spread, and how my tracked stocks are moving. Cite your data sources and as-of times.',
    },
    {
      label: 'Global hotspots',
      labelKey: 'starters.finance.hotspots',
      prompt:
        "What are today's global news hotspots — wars, oil, US-China, Fed — and how might they transmit to my tech-heavy portfolio? Be clear about signal quality.",
    },
    {
      label: 'What regime are we in',
      labelKey: 'starters.finance.regime',
      prompt:
        'What market regime does PRISM say we are in right now, how confident is it, and what has that regime historically meant for stocks and bonds?',
    },
    {
      label: 'Crash risk today',
      labelKey: 'starters.finance.crashRisk',
      prompt:
        'How fragile is the market right now? Show me the tail risk on the Nasdaq, jump activity, and yield-curve signals — and explain why crash timing itself cannot be predicted.',
    },
    {
      label: 'What is proven',
      labelKey: 'starters.finance.proven',
      prompt:
        'Which market regularities has PRISM actually CONFIRMED with out-of-sample validation, and what remains hypothesis? Explain the confirmed one and how I should read it.',
    },
  ],

  'healthcare-medical': [
    {
      label: 'Care gaps for PT-1001',
      labelKey: 'starters.healthcare.careGaps',
      prompt:
        'What care gaps are open for patient PT-1001, and which should I close first?',
    },
    {
      label: 'Readmission risk',
      labelKey: 'starters.healthcare.readmission',
      prompt:
        'Summarize the 30-day readmission risk for PT-1001 and draft an intervention plan.',
    },
    {
      label: 'Check interactions',
      labelKey: 'starters.healthcare.interactions',
      prompt:
        'Check for interactions between metformin, lisinopril and atorvastatin.',
    },
    {
      label: 'Panel health',
      labelKey: 'starters.healthcare.panelHealth',
      prompt:
        'How is my patient panel doing overall — where are the biggest quality gaps?',
    },
    {
      label: "Dr. Chen's openings",
      labelKey: 'starters.healthcare.chenOpenings',
      prompt: 'When is DR-CHEN next available for a follow-up visit?',
    },
  ],

  'insurance-claims': [
    {
      label: 'Whats in my queue',
      labelKey: 'starters.insurance.myQueue',
      prompt:
        'List the open claims and tell me which ones need my attention first and why.',
    },
    {
      label: 'Fraud signals',
      labelKey: 'starters.insurance.fraudSignals',
      prompt:
        'Show the fraud dashboard, then pick the highest-risk open claim and explain what is driving its score.',
    },
    {
      label: 'Verify coverage',
      labelKey: 'starters.insurance.verifyCoverage',
      prompt:
        'Verify policy POL-2024-118273 and check whether a $25,000 home claim is covered.',
    },
    {
      label: 'Settlement view',
      labelKey: 'starters.insurance.settlementView',
      prompt:
        'What do our settlement analytics look like this month, and where are we leaking money?',
    },
  ],

  'retail-inventory': [
    {
      label: 'What is out of stock',
      labelKey: 'starters.retail.outOfStock',
      prompt:
        'Which SKUs are out of stock right now, and how much revenue are we losing per day?',
    },
    {
      label: 'Forecast earbuds',
      labelKey: 'starters.retail.forecastEarbuds',
      prompt:
        'Forecast demand for SKU-ELEC-1001 over the next 30 days and tell me whether I should reorder.',
    },
    {
      label: 'Where is the excess',
      labelKey: 'starters.retail.excess',
      prompt:
        'Run an ABC analysis and tell me where we are carrying too much inventory.',
    },
    {
      label: 'Price the jacket',
      labelKey: 'starters.retail.priceJacket',
      prompt:
        'Optimize pricing for SKU-APRL-2001 with the objective maximize_margin, and explain the tradeoff.',
    },
    {
      label: 'Supplier health',
      labelKey: 'starters.retail.supplierHealth',
      prompt:
        'How is supplier SUP-100 performing, and is that a risk to my Electronics category?',
    },
  ],

  'manufacturing-maintenance': [
    {
      label: 'What needs attention',
      labelKey: 'starters.manufacturing.needsAttention',
      prompt:
        'Show me the current equipment alerts and tell me which asset to deal with first.',
    },
    {
      label: 'Will the turbine fail',
      labelKey: 'starters.manufacturing.turbineFail',
      prompt:
        'Predict failure risk for EQ-TURB-001 and tell me how much runway I have.',
    },
    {
      label: 'Vibration on CNC-001',
      labelKey: 'starters.manufacturing.vibration',
      prompt:
        'Analyze the vibration spectrum for EQ-CNC-001 and tell me what the peaks suggest.',
    },
    {
      label: 'Plan the week',
      labelKey: 'starters.manufacturing.planWeek',
      prompt:
        'What does the maintenance calendar look like, and does it match where the risk actually is?',
    },
  ],

  'real-estate-valuation': [
    {
      label: 'Market conditions',
      labelKey: 'starters.realestate.marketConditions',
      prompt:
        'What are market conditions in 78701 — is this a buyer or seller market right now?',
    },
    {
      label: 'Value a property',
      labelKey: 'starters.realestate.valueProperty',
      prompt:
        'Pull a CMA report for 1200 Oak Dr, 78701 and walk me through how the comps support the value.',
    },
    {
      label: '12-month outlook',
      labelKey: 'starters.realestate.outlook',
      prompt:
        'Give me the 12-month price forecast for 78701 and tell me what would break that forecast.',
    },
    {
      label: 'Find 3-bed homes',
      labelKey: 'starters.realestate.findHomes',
      prompt:
        'Search for 3-bedroom single-family homes in 78701 and highlight anything priced below the market median.',
    },
  ],
}

/** Starters for an industry, or an empty list if it has none. */
export function starterPrompts(industryId: string): StarterPrompt[] {
  return STARTER_PROMPTS[industryId] ?? []
}
