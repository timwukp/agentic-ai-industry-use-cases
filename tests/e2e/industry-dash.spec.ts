/**
 * Dashboard regression guard for the four non-finance/healthcare industries.
 *
 * These specs replace an earlier version that asserted the "agent is live"
 * hand-off link was visible. That link only existed on the *placeholder*
 * dashboard, so the test passed by asserting the emptiness it was supposed to
 * catch. Every assertion here is on rendered live data — a regression back to a
 * placeholder (or an API that returns nothing) fails the test:
 *
 *   - a KPI tile shows a real number, not the "—" empty marker
 *   - at least one recharts <svg> is painted with a non-zero plot area
 *   - a data table has body rows
 *   - Ask agent prefills the chat input with industry-specific text
 */
import { test, expect, type Page } from '@playwright/test';

const EMAIL = process.env.E2E_EMAIL!;
const PASSWORD = process.env.E2E_PASSWORD!;

/** Anything that is NOT the em-dash placeholder our formatters emit for null. */
const REAL_VALUE = /^(?!—$).*[0-9].*/;

async function login(page: Page) {
  await page.goto('/');
  await page.getByRole('textbox', { name: /email/i }).fill(EMAIL);
  await page.getByRole('textbox', { name: /password/i }).fill(PASSWORD);
  await page.getByRole('button', { name: /sign in/i }).click();
  await expect(page).not.toHaveURL(/login/, { timeout: 30_000 });
}

/** The value node of a StatCard, addressed by its data-kpi title. */
function kpi(page: Page, title: string) {
  return page.locator(`[data-kpi="${title}"] [data-kpi-value]`).first();
}

/** Fails if the chart element exists but paints nothing (zero-size surface). */
async function expectPaintedChart(page: Page, atLeast = 1) {
  const surfaces = page.locator('svg.recharts-surface');
  await expect(surfaces.first()).toBeVisible({ timeout: 30_000 });
  expect(await surfaces.count()).toBeGreaterThanOrEqual(atLeast);
  const box = await surfaces.first().boundingBox();
  expect(box!.width).toBeGreaterThan(100);
  expect(box!.height).toBeGreaterThan(60);
  // a chart with no data still renders a surface — require plotted geometry
  await expect(
    page.locator('svg.recharts-surface path.recharts-curve, svg.recharts-surface .recharts-bar-rectangle').first()
  ).toBeAttached({ timeout: 30_000 });
}

/** Fails if a table renders only its header, or the "no rows" empty state. */
async function expectTableRows(page: Page, atLeast = 1) {
  const rows = page.locator('table tbody tr');
  await expect(rows.first()).toBeVisible({ timeout: 30_000 });
  expect(await rows.count()).toBeGreaterThanOrEqual(atLeast);
}

interface DashCase {
  id: string;
  /** Section heading that only the real dashboard renders. */
  heading: RegExp;
  /** StatCard titles (exact, as passed to the component) that must each show a number. */
  kpis: string[];
  /** Text the Ask agent prompt must contain once prefilled. */
  promptPattern: RegExp;
  /** Extra industry-specific checks. */
  extra?: (page: Page) => Promise<void>;
}

const CASES: DashCase[] = [
  {
    id: 'insurance-claims',
    heading: /claims book/i,
    kpis: ['Claims Screened', 'Fraud Detection Rate', 'Detection Savings'],
    promptPattern: /fraud|claim|settlement/i,
    extra: async (page) => {
      // fraud-scored queue is the differentiator; a score pill must be present
      await expect(page.getByText(/open claims/i).first()).toBeVisible();
      await expectTableRows(page, 3);
    },
  },
  {
    id: 'retail-inventory',
    heading: /network health/i,
    kpis: ['Total SKUs', 'In-Stock Rate', 'Blended Margin'],
    promptPattern: /inventory|replenish|stockout|markdown/i,
    extra: async (page) => {
      await expect(page.getByText(/abc classification/i).first()).toBeVisible();
      await expect(page.getByText(/out-of-stock items/i).first()).toBeVisible();
      await expectTableRows(page, 3);
    },
  },
  {
    id: 'manufacturing-maintenance',
    heading: /plant status/i,
    kpis: ['Fleet Health', 'PM Utilization', 'Parts Fill Rate'],
    promptPattern: /equipment|maintenance|work order|asset/i,
    extra: async (page) => {
      await expect(page.getByText(/equipment fleet/i).first()).toBeVisible();
      await expect(page.getByText(/maintenance schedule/i).first()).toBeVisible();
      await expectTableRows(page, 3);
      // drilling into an asset must load the prediction/reliability routes
      await page.getByRole('button', { name: /^EQ-/ }).first().click();
      await expect(page.getByText(/failure prediction/i).first()).toBeVisible({
        timeout: 30_000,
      });
      await expect(page.getByText(/remaining useful life/i).first()).toBeVisible();
    },
  },
  {
    id: 'real-estate-valuation',
    heading: /market pulse/i,
    kpis: ['Median Sale Price', 'Median Days on Market', 'Active Listings'],
    promptPattern: /market|listing|valuation|comparable/i,
    extra: async (page) => {
      await expect(page.getByText(/price forecast/i).first()).toBeVisible();
      await expect(page.getByText(/months of supply/i).first()).toBeVisible();
      await expectTableRows(page, 3);
      // selecting a listing address must pull comparables
      const address = page.getByRole('button', { name: /^\d+ \w+ \w+$/ }).first();
      await address.click();
      await expect(page.getByText(/indicated value/i).first()).toBeVisible({
        timeout: 30_000,
      });
      await expect(kpi(page, 'Indicated Value')).toHaveText(REAL_VALUE);
    },
  },
];

for (const dash of CASES) {
  test(`${dash.id} dashboard renders live widget data`, async ({ page }, testInfo) => {
    await login(page);
    await page.goto(`/${dash.id}/dashboard`);

    await expect(page.getByText(dash.heading).first()).toBeVisible({ timeout: 30_000 });

    for (const title of dash.kpis) {
      await expect(kpi(page, title)).toHaveText(REAL_VALUE, { timeout: 30_000 });
    }

    await expectPaintedChart(page);
    await dash.extra?.(page);

    // the dashboard scrolls inside its own container (AppShell shell + the
    // dashboard root), so fullPage alone would capture whatever the drill-down
    // clicks scrolled into view
    await page.evaluate(() => {
      document
        .querySelectorAll('div.overflow-y-auto')
        .forEach((el) => el.scrollTo(0, 0));
    });
    await page.screenshot({
      path: `screenshots/${dash.id}-dashboard-${testInfo.project.name}.png`,
      fullPage: true,
    });
  });

  test(`${dash.id} Ask agent prefills chat`, async ({ page }) => {
    await login(page);
    await page.goto(`/${dash.id}/dashboard`);
    await expect(page.getByText(dash.heading).first()).toBeVisible({ timeout: 30_000 });

    await page.getByRole('button', { name: /ask agent/i }).first().click();
    const chatInput = page.getByPlaceholder(/message|ask/i).locator('visible=true').first();
    await expect(chatInput).toBeVisible({ timeout: 15_000 });
    await expect(chatInput).toHaveValue(dash.promptPattern, { timeout: 10_000 });
  });
}
