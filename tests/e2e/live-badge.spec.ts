/**
 * Real-browser verification of the live-market provenance surfaces.
 *
 * Asserts what the API tests cannot: that MarketLiveSection actually renders,
 * the green LiveBadge shows provider + as-of + delay, live data is fresh (not
 * stale), and the simulated sections still carry the amber SimulatedBadge —
 * both worlds visible on one page, badge-separated. Screenshots land in
 * screenshots/ for eyeballing.
 */
import { test, expect, type Page } from '@playwright/test';

const EMAIL = process.env.E2E_EMAIL!;
const PASSWORD = process.env.E2E_PASSWORD!;

async function login(page: Page) {
  await page.goto('/');
  await page.getByRole('textbox', { name: /email/i }).fill(EMAIL);
  await page.getByRole('textbox', { name: /password/i }).fill(PASSWORD);
  await page.getByRole('button', { name: /sign in/i }).click();
  await expect(page).not.toHaveURL(/login/, { timeout: 30_000 });
}

test('finance dashboard shows LIVE badges with provenance and keeps simulated badge', async ({
  page,
}) => {
  await login(page);

  // Live section rendered with real data (not loading/error panes)
  const liveSection = page.locator('[data-section="market-live"]');
  await expect(liveSection).toBeVisible({ timeout: 30_000 });

  // Index proxy tiles show numeric levels
  const qqq = liveSection.locator('[data-kpi="live-index-QQQ"] [data-kpi-value]');
  await expect(qqq).toBeVisible();
  const qqqText = await qqq.textContent();
  expect(parseFloat(qqqText!.replace(/,/g, ''))).toBeGreaterThan(100);

  // LIVE badges present, fresh (green), and carrying provenance text
  const badges = liveSection.locator('[data-live-badge]');
  expect(await badges.count()).toBeGreaterThanOrEqual(3);
  const first = badges.first();
  await expect(first).toHaveAttribute('data-live-badge', 'fresh');
  const badgeText = (await first.textContent()) ?? '';
  expect(badgeText).toMatch(/finnhub|fred/i); // provider
  expect(badgeText).toMatch(/20\d\d/); // as-of timestamp year

  // Tracked quotes grid has the 20-symbol watchlist rendering prices
  const quotes = liveSection.locator('[data-kpi^="live-quote-"]');
  expect(await quotes.count()).toBeGreaterThanOrEqual(15);

  // The simulated world is still badge-separated on the same page
  await expect(page.getByText(/source: simulated/i).first()).toBeVisible();

  await page.screenshot({
    path: 'screenshots/live-badge-top.png',
    fullPage: false,
  });

  // Scroll the dashboard container to capture the yield curve + quotes grid.
  // Recharts animates the line left-to-right (~1.5s); wait it out so the
  // screenshot shows the full curve, not a mid-animation truncation.
  await liveSection.scrollIntoViewIfNeeded();
  await page.waitForTimeout(2000);
  await page.screenshot({
    path: 'screenshots/live-badge-section.png',
    fullPage: false,
  });
});
