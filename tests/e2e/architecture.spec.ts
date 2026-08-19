import { test, expect } from '@playwright/test';

const EMAIL = process.env.E2E_EMAIL!;
const PASSWORD = process.env.E2E_PASSWORD!;

async function login(page) {
  await page.goto('/');
  await page.getByRole('textbox', { name: /email/i }).fill(EMAIL);
  await page.getByRole('textbox', { name: /password/i }).fill(PASSWORD);
  await page.getByRole('button', { name: /sign in/i }).click();
  await expect(page).not.toHaveURL(/login/, { timeout: 30_000 });
}

test('architecture page renders both animated diagrams', async ({ page, isMobile }) => {
  await login(page);
  await page.goto('/finance/architecture');

  for (const name of ['System architecture', 'Request flow']) {
    const img = page.getByRole('img', { name });
    await expect(img).toBeVisible({ timeout: 15_000 });
    // the asset must actually load, not just the <img> exist
    await expect
      .poll(() => img.evaluate((el: HTMLImageElement) => el.naturalWidth))
      .toBeGreaterThan(0);
  }

  if (isMobile) {
    // 4th bottom tab is the mobile entry point
    await expect(page.getByRole('button', { name: 'Architecture' })).toBeVisible();
  } else {
    // at lg+ the page replaces both panes — no dashboard content bleeding in
    await expect(page.getByText(/total return/i)).toHaveCount(0);
  }

  await page.screenshot({ path: 'screenshots/architecture.png', fullPage: true });
});

test('switching industry from the architecture page lands on its dashboard', async ({
  page,
  isMobile,
}) => {
  test.skip(isMobile, 'sidebar industry list is desktop/tablet only');
  await login(page);
  await page.goto('/finance/architecture');
  await expect(page.getByRole('img', { name: 'System architecture' })).toBeVisible({
    timeout: 15_000,
  });
  // industry links must NOT preserve the architecture view (industry-agnostic
  // page — preserving it makes every industry click look dead)
  await page.getByRole('link', { name: /healthcare/i }).first().click();
  await expect(page).toHaveURL(/\/healthcare-medical\/dashboard/);
});
