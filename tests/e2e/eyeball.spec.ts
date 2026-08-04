/**
 * Not a regression test — a manual layout inspection aid.
 *
 * The dashboards scroll inside their own container, so Playwright's fullPage
 * screenshot only ever captures one viewport. This walks each dashboard down in
 * viewport-sized steps so chart axes, pill wrapping and table overflow can be
 * eyeballed. Run explicitly:
 *
 *   npx playwright test eyeball.spec.ts --project=desktop
 */
import { test, expect, type Page } from '@playwright/test';

const EMAIL = process.env.E2E_EMAIL!;
const PASSWORD = process.env.E2E_PASSWORD!;

const DASHBOARDS = [
  { id: 'insurance-claims', heading: /claims book/i },
  { id: 'retail-inventory', heading: /network health/i },
  { id: 'manufacturing-maintenance', heading: /plant status/i },
  { id: 'real-estate-valuation', heading: /market pulse/i },
];

async function login(page: Page) {
  await page.goto('/');
  await page.getByRole('textbox', { name: /email/i }).fill(EMAIL);
  await page.getByRole('textbox', { name: /password/i }).fill(PASSWORD);
  await page.getByRole('button', { name: /sign in/i }).click();
  await expect(page).not.toHaveURL(/login/, { timeout: 30_000 });
}

for (const dash of DASHBOARDS) {
  test(`eyeball ${dash.id}`, async ({ page }, testInfo) => {
    await page.setViewportSize({ width: 1600, height: 1000 });
    await login(page);
    await page.goto(`/${dash.id}/dashboard`);
    await expect(page.getByText(dash.heading).first()).toBeVisible({ timeout: 30_000 });
    // collapse the chat panel so the dashboard gets the full width
    const toggle = page.getByRole('button', { name: /^chat$/i }).first();
    if (await toggle.isVisible().catch(() => false)) await toggle.click();
    // collapsing the panel remounts the dashboard — wait out the refetch
    await expect(page.getByText(/^Loading /).first()).toBeHidden({ timeout: 30_000 });

    // reveal every drill-down section before measuring the scroll height
    const drill = page
      .getByRole('button', { name: /^EQ-/ })
      .or(page.getByRole('button', { name: /^\d+ \w+ \w+$/ }))
      .first();
    if (await drill.isVisible().catch(() => false)) {
      await drill.click();
      await page.waitForTimeout(3000);
    }

    const scroller = page.locator('div.h-full.overflow-y-auto').first();
    const total = await scroller.evaluate((el) => el.scrollHeight);
    const step = 900;
    for (let i = 0, y = 0; y < total; i += 1, y += step) {
      await scroller.evaluate((el, top) => el.scrollTo(0, top), y);
      await page.waitForTimeout(400);
      await page.screenshot({
        path: `screenshots/eyeball-${dash.id}-${testInfo.project.name}-${i}.png`,
      });
    }
  });
}
