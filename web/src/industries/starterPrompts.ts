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
  /** Short button label — what the user scans. */
  label: string
  /** The full prompt sent to the agent. */
  prompt: string
}

export const STARTER_PROMPTS: Record<string, StarterPrompt[]> = {
  finance: [
    {
      label: 'Market snapshot',
      prompt:
        'Give me a market overview and tell me which sectors are leading and lagging today.',
    },
    {
      label: 'Review my portfolio',
      prompt:
        'Show my portfolio positions and allocation, then tell me whether it looks concentrated.',
    },
    {
      label: 'Downside risk',
      prompt:
        'Calculate 1-day 95% VaR on a $250,000 portfolio and stress test it against the 2008 financial crisis.',
    },
    {
      label: 'Quote NVDA',
      prompt: 'What is NVDA trading at, and how does that compare to its 30-day history?',
    },
  ],

  'healthcare-medical': [
    {
      label: 'Care gaps for PT-1001',
      prompt:
        'What care gaps are open for patient PT-1001, and which should I close first?',
    },
    {
      label: 'Readmission risk',
      prompt:
        'Summarize the 30-day readmission risk for PT-1001 and draft an intervention plan.',
    },
    {
      label: 'Check interactions',
      prompt:
        'Check for interactions between metformin, lisinopril and atorvastatin.',
    },
    {
      label: 'Panel health',
      prompt:
        'How is my patient panel doing overall — where are the biggest quality gaps?',
    },
    {
      label: "Dr. Chen's openings",
      prompt: 'When is DR-CHEN next available for a follow-up visit?',
    },
  ],

  'insurance-claims': [
    {
      label: 'Whats in my queue',
      prompt:
        'List the open claims and tell me which ones need my attention first and why.',
    },
    {
      label: 'Fraud signals',
      prompt:
        'Show the fraud dashboard, then pick the highest-risk open claim and explain what is driving its score.',
    },
    {
      label: 'Verify coverage',
      prompt:
        'Verify policy POL-2024-118273 and check whether a $25,000 home claim is covered.',
    },
    {
      label: 'Settlement view',
      prompt:
        'What do our settlement analytics look like this month, and where are we leaking money?',
    },
  ],

  'retail-inventory': [
    {
      label: 'What is out of stock',
      prompt:
        'Which SKUs are out of stock right now, and how much revenue are we losing per day?',
    },
    {
      label: 'Forecast earbuds',
      prompt:
        'Forecast demand for SKU-ELEC-1001 over the next 30 days and tell me whether I should reorder.',
    },
    {
      label: 'Where is the excess',
      prompt:
        'Run an ABC analysis and tell me where we are carrying too much inventory.',
    },
    {
      label: 'Price the jacket',
      prompt:
        'Optimize pricing for SKU-APRL-2001 with the objective maximize_margin, and explain the tradeoff.',
    },
    {
      label: 'Supplier health',
      prompt:
        'How is supplier SUP-100 performing, and is that a risk to my Electronics category?',
    },
  ],

  'manufacturing-maintenance': [
    {
      label: 'What needs attention',
      prompt:
        'Show me the current equipment alerts and tell me which asset to deal with first.',
    },
    {
      label: 'Will the turbine fail',
      prompt:
        'Predict failure risk for EQ-TURB-001 and tell me how much runway I have.',
    },
    {
      label: 'Vibration on CNC-001',
      prompt:
        'Analyze the vibration spectrum for EQ-CNC-001 and tell me what the peaks suggest.',
    },
    {
      label: 'Plan the week',
      prompt:
        'What does the maintenance calendar look like, and does it match where the risk actually is?',
    },
  ],

  'real-estate-valuation': [
    {
      label: 'Market conditions',
      prompt:
        'What are market conditions in 78701 — is this a buyer or seller market right now?',
    },
    {
      label: 'Value a property',
      prompt:
        'Pull a CMA report for 1200 Oak Dr, 78701 and walk me through how the comps support the value.',
    },
    {
      label: '12-month outlook',
      prompt:
        'Give me the 12-month price forecast for 78701 and tell me what would break that forecast.',
    },
    {
      label: 'Find 3-bed homes',
      prompt:
        'Search for 3-bedroom single-family homes in 78701 and highlight anything priced below the market median.',
    },
  ],
}

/** Starters for an industry, or an empty list if it has none. */
export function starterPrompts(industryId: string): StarterPrompt[] {
  return STARTER_PROMPTS[industryId] ?? []
}
