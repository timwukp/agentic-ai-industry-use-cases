/**
 * Audit: does every starter question produce a chart panel above the dashboard?
 *
 * This is a coverage census, not a pass/fail gate on individual prompts. It
 * clicks all 26 starter questions in all six industries from the dashboard
 * route, waits for the answer to finish, and records whether the overlay
 * appeared, which charts it drew, and — decisively — which tools the answer
 * actually called.
 *
 * The tool list is what makes a "no panel" result diagnosable. A missing panel
 * has two very different causes and they need different fixes:
 *
 *   1. The answer called a tool that has a recognizer, but the panel did not
 *      appear — a real bug in extraction or correlation.
 *   2. The answer called only tools with no recognizer (or no tool at all, e.g.
 *      a knowledge-base lookup or a pure explanation) — a coverage gap, where
 *      the fix is a new recognizer, not a bug fix.
 *
 * Without the tool names the two are indistinguishable, and the second would be
 * misreported as the first. Tools are read from the browser by patching
 * window.fetch to tee the invoke stream, because the app deliberately keeps tool
 * payloads out of the DOM (they must never land in a chat bubble).
 */
import { test, expect, type Page } from '@playwright/test';
import { writeFileSync, mkdirSync, readdirSync, readFileSync } from 'node:fs';

const EMAIL = process.env.E2E_EMAIL!;
const PASSWORD = process.env.E2E_PASSWORD!;

/** Mirrors web/src/industries/starterPrompts.ts. Labels only: the click target
 *  is the button, and duplicating prompt text here would drift. */
const INDUSTRIES: Array<{ id: string; labels: string[] }> = [
  {
    id: 'finance',
    labels: ['Market snapshot', 'Review my portfolio', 'Downside risk', 'Quote NVDA'],
  },
  {
    id: 'healthcare-medical',
    labels: [
      'Care gaps for PT-1001',
      'Readmission risk',
      'Check interactions',
      'Panel health',
      "Dr. Chen's openings",
    ],
  },
  {
    id: 'insurance-claims',
    labels: ['Whats in my queue', 'Fraud signals', 'Verify coverage', 'Settlement view'],
  },
  {
    id: 'retail-inventory',
    labels: [
      'What is out of stock',
      'Forecast earbuds',
      'Where is the excess',
      'Price the jacket',
      'Supplier health',
    ],
  },
  {
    id: 'manufacturing-maintenance',
    labels: [
      'What needs attention',
      'Will the turbine fail',
      'Vibration on CNC-001',
      'Plan the week',
    ],
  },
  {
    id: 'real-estate-valuation',
    labels: ['Market conditions', 'Value a property', '12-month outlook', 'Find 3-bed homes'],
  },
];

interface Row {
  industry: string;
  label: string;
  panel: boolean;
  charts: string[];
  tools: string[];
  note: string;
  run: number;
}

/** Identifies the run a row belongs to.
 *
 * Now that the rows outlive the run (see OUT_DIR), a row from yesterday would be
 * read as a result of today's census: a question that failed to run today would
 * still be reported "panel: yes" from its stale file. Workers are forked from one
 * runner process, so the parent pid is shared across every worker of a single run
 * and differs between runs. If a pid were ever recycled the mismatch direction is
 * the safe one — the row is treated as absent and the report says so loudly.
 */
const RUN = process.ppid;

/** Where the census writes its evidence.
 *
 *  NOT under screenshots/: that is playwright.config.ts's `outputDir`, which
 *  Playwright empties at the start of every run. A later, unrelated run of
 *  answer-charts.spec.ts deleted a completed 26/26 census — report, per-question
 *  JSON and all 26 panel screenshots — leaving a directory that looked as if the
 *  audit had never happened. The report is the artifact that substantiates the
 *  coverage claim, so it has to outlive the next test run.
 */
const OUT_DIR = 'chart-audit';
/** One JSON file per question, so a row survives whatever happens to the rest of
 *  the run. A single transient network error used to abort the remaining tests
 *  and the report was assembled from an in-memory array, so 8 of 26 questions
 *  silently vanished from a report that still called itself complete. */
const RESULT_DIR = `${OUT_DIR}/results`;
const REPORT = `${OUT_DIR}/chart-coverage.md`;

function recordRow(row: Omit<Row, 'run'>) {
  mkdirSync(RESULT_DIR, { recursive: true });
  const slug = `${row.industry}__${row.label.replace(/[^a-z0-9]+/gi, '-')}`;
  writeFileSync(
    `${RESULT_DIR}/${slug}.json`,
    JSON.stringify({ ...row, run: RUN }, null, 2),
  );
}

async function login(page: Page) {
  // The live app is reached over the internet; one dropped connection should
  // cost a retry, not the remaining questions in the census.
  let lastErr: unknown;
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      await page.goto('/');
      lastErr = undefined;
      break;
    } catch (err) {
      lastErr = err;
      await page.waitForTimeout(5_000);
    }
  }
  if (lastErr) throw lastErr;
  await page.getByRole('textbox', { name: /email/i }).fill(EMAIL);
  await page.getByRole('textbox', { name: /password/i }).fill(PASSWORD);
  await page.getByRole('button', { name: /sign in/i }).click();
  await expect(page).not.toHaveURL(/login/, { timeout: 30_000 });
}

/** Tees the invoke response body so tool names are observable from the test.
 *
 * The app strips tool payloads before anything reaches the DOM, so there is
 * nothing to scrape. Patching fetch and cloning the stream is the only way to
 * see which tools an answer actually used, and it must be installed via
 * addInitScript so it is in place before the app's first request.
 */
async function installToolSniffer(page: Page) {
  await page.addInitScript(() => {
    (window as unknown as { __tools: string[] }).__tools = [];
    const orig = window.fetch;
    window.fetch = async (...args: Parameters<typeof fetch>) => {
      const res = await orig(...args);
      const url = typeof args[0] === 'string' ? args[0] : (args[0] as Request)?.url ?? '';
      if (!/invoke|harness/i.test(url) || !res.body) return res;
      // tee: one branch back to the app untouched, one scanned here.
      const [a, b] = res.body.tee();
      (async () => {
        const reader = b.getReader();
        const dec = new TextDecoder();
        let buf = '';
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          buf += dec.decode(value, { stream: true });
          // Tool names appear as "name":"<target>___<tool>" in toolUse events.
          // The target segment contains hyphens (market-data, fraud-detection,
          // demand-forecast), so the character class must allow them — a
          // [A-Za-z0-9_]+ target silently records "no tools called" for the
          // industries whose targets are hyphenated.
          for (const m of buf.matchAll(/"name"\s*:\s*"([A-Za-z0-9_-]+___[A-Za-z0-9_]+|skills)"/g)) {
            const list = (window as unknown as { __tools: string[] }).__tools;
            const bare = m[1].includes('___') ? m[1].split('___').pop()! : m[1];
            if (!list.includes(bare)) list.push(bare);
          }
          if (buf.length > 200_000) buf = buf.slice(-50_000);
        }
      })().catch(() => {});
      return new Response(a, {
        status: res.status,
        statusText: res.statusText,
        headers: res.headers,
      });
    };
  });
}

// Not serial: each question is independent, and in serial mode the first
// failure skips every question after it — which is exactly how the first run
// lost manufacturing and real-estate entirely.
// Explicitly parallel: the questions are independent, and Playwright serializes
// tests within one file by default. In serial mode the first failure also skips
// every question after it — which is how the first run lost manufacturing and
// real-estate entirely to one dropped connection.
test.describe.configure({ mode: 'parallel', timeout: 240_000, retries: 1 });

for (const industry of INDUSTRIES) {
  for (const label of industry.labels) {
    test(`${industry.id} · ${label}`, async ({ page }, testInfo) => {
      test.skip(
        testInfo.project.name !== 'desktop',
        'the overlay is a desktop surface; below lg charts render inline',
      );
      await installToolSniffer(page);
      await login(page);
      // The dashboard route, because that is where the user clicks and where the
      // overlay has to appear — the whole point of the feature.
      await page.goto(`/${industry.id}/dashboard`);

      const button = page.getByRole('button', { name: label, exact: false }).first();
      await expect(button).toBeVisible({ timeout: 30_000 });
      await button.click();

      const input = page
        .locator('textarea[placeholder="Ask the agent…"]')
        .locator('visible=true')
        .first();
      // Streaming end: the composer re-enables only after the stream closes.
      await expect(input).toBeEnabled({ timeout: 200_000 });
      const assistant = page.locator('[data-role="assistant"]').last();
      await expect(assistant).not.toHaveText('', { timeout: 20_000 });

      const panel = page.locator('[data-testid="answer-chart-panel"]');
      let seen = false;
      try {
        await expect(panel).toBeVisible({ timeout: 15_000 });
        seen = true;
      } catch {
        seen = false;
      }

      const charts = seen
        ? await panel
            .locator('[data-testid="answer-chart"]')
            .evaluateAll((els) => els.map((e) => e.getAttribute('data-chart-title') ?? '?'))
        : [];
      const tools = await page.evaluate(
        () => (window as unknown as { __tools: string[] }).__tools ?? [],
      );
      const prose = await assistant.innerText();

      recordRow({
        industry: industry.id,
        label,
        panel: seen,
        charts,
        tools,
        note: seen ? '' : prose.slice(0, 160).replace(/\s+/g, ' '),
      });

      await page.screenshot({
        path: `${OUT_DIR}/audit-${industry.id}-${label.replace(/[^a-z0-9]+/gi, '-')}.png`,
        fullPage: true,
      });
    });
  }
}

const TOTAL = INDUSTRIES.reduce((n, i) => n + i.labels.length, 0);

test.afterAll(() => {
  mkdirSync(RESULT_DIR, { recursive: true });
  // Read from disk, not from memory: with parallel workers each worker has its
  // own module instance, so an in-memory array only ever holds that worker's
  // share and the last afterAll to run would overwrite the others' report.
  const byKey = new Map<string, Row>();
  for (const f of readdirSync(RESULT_DIR)) {
    if (!f.endsWith('.json')) continue;
    const row = JSON.parse(readFileSync(`${RESULT_DIR}/${f}`, 'utf8')) as Row;
    // A row left by an earlier census is not a result of this one.
    if (row.run !== RUN) continue;
    byKey.set(`${row.industry}__${row.label}`, row);
  }
  // Emit in declaration order so the table is stable regardless of finish order.
  const rows: Row[] = [];
  const missing: string[] = [];
  for (const ind of INDUSTRIES) {
    for (const label of ind.labels) {
      const row = byKey.get(`${ind.id}__${label}`);
      if (row) rows.push(row);
      else missing.push(`${ind.id} · ${label}`);
    }
  }
  if (!rows.length) {
    // Do not leave the previous run's report in place — it would be read as the
    // result of this run.
    writeFileSync(
      REPORT,
      `# Starter-question chart coverage\n\n**No questions ran.** 0/${TOTAL}.\n`,
    );
    return;
  }
  const withPanel = rows.filter((r) => r.panel).length;
  const lines = [
    `# Starter-question chart coverage`,
    ``,
    `${withPanel}/${rows.length} starter questions produced a chart panel.`,
    ``,
    // A partial census must announce itself. The first run reported "9/18" for a
    // 26-question suite with nothing saying 8 questions were never asked.
    ...(missing.length
      ? [
          `> **Incomplete: ${missing.length} of ${TOTAL} questions did not run** — ` +
            missing.join('; '),
          ``,
        ]
      : [`All ${TOTAL} starter questions ran.`, ``]),
    `| Industry | Starter | Panel | Charts | Tools called |`,
    `|---|---|---|---|---|`,
    ...rows.map(
      (r) =>
        `| ${r.industry} | ${r.label} | ${r.panel ? 'yes' : '**no**'} | ${
          r.charts.join(', ') || '—'
        } | ${r.tools.join(', ') || '—'} |`,
    ),
    ``,
    `## Answers with no panel`,
    ``,
    // Spelled out rather than left as a bare heading: an empty section reads as
    // "this was not filled in", which is the opposite of what it means here.
    ...(rows.some((r) => !r.panel)
      ? rows
          .filter((r) => !r.panel)
          .map(
            (r) => `- **${r.industry} · ${r.label}** — tools: ${r.tools.join(', ') || 'none'}`,
          )
      : ['None.']),
  ];
  writeFileSync(REPORT, lines.join('\n'));
  // eslint-disable-next-line no-console
  console.log(`\n${withPanel}/${rows.length} produced a panel — ${REPORT}\n`);
});
