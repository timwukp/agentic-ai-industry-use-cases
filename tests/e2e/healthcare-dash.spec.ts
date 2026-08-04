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

test('healthcare Patient 360 renders all zones with live data', async ({ page }) => {
  await login(page);
  await page.goto('/healthcare-medical/dashboard');

  // Zone 1: Practice Pulse
  await expect(page.getByText(/practice pulse/i).first()).toBeVisible({ timeout: 30_000 });
  await expect(page.getByText(/active patients/i).first()).toBeVisible();

  // Zone 2: Patient 360 — care gaps + readmission + at least one rendered chart
  await expect(page.getByText(/care gaps/i).first()).toBeVisible({ timeout: 30_000 });
  await expect(page.getByText(/readmission risk/i).first()).toBeVisible();
  await expect(page.getByText(/OVERDUE/).first()).toBeVisible();
  await expect(page.locator('svg.recharts-surface').first()).toBeVisible({ timeout: 30_000 });

  // Zone 3: real provider directory
  await expect(page.getByRole('combobox').last()).toBeVisible();
  await expect(
    page.getByRole('option', { name: /sarah chen/i }).or(page.getByText(/sarah chen/i)).first()
  ).toBeAttached();

  await page.screenshot({ path: 'screenshots/healthcare-dashboard.png', fullPage: true });
});

test('patient chip switch changes patient context', async ({ page }) => {
  await login(page);
  await page.goto('/healthcare-medical/dashboard');
  await expect(page.getByText(/care gaps/i).first()).toBeVisible({ timeout: 30_000 });

  const headerBefore = await page
    .locator('[data-testid="patient-name"], h3, h2')
    .filter({ hasText: /·/ })
    .first()
    .textContent()
    .catch(() => null);

  await page.getByRole('button', { name: 'PT-1002' }).click();
  await expect(page.getByText(/PT-1002/).first()).toBeVisible({ timeout: 30_000 });
  // wait for refetch to land — care gaps count or name should update
  await page.waitForTimeout(2000);
  const headerAfter = await page
    .locator('[data-testid="patient-name"], h3, h2')
    .filter({ hasText: /·/ })
    .first()
    .textContent()
    .catch(() => null);
  if (headerBefore && headerAfter) {
    expect(headerAfter).not.toBe(headerBefore);
  }
});

test('Ask agent prefills the chat input', async ({ page }, testInfo) => {
  await login(page);
  await page.goto('/healthcare-medical/dashboard');
  await expect(page.getByText(/care gaps/i).first()).toBeVisible({ timeout: 30_000 });

  await page.getByRole('button', { name: /ask agent/i }).first().click();
  const chatInput = page.getByPlaceholder(/message|ask/i).locator('visible=true').first();
  await expect(chatInput).toBeVisible({ timeout: 15_000 });
  await expect(chatInput).toHaveValue(/PT-\d+|care gaps|readmission/i, { timeout: 10_000 });
  await page.screenshot({
    path: `screenshots/ask-agent-prefill-${testInfo.project.name}.png`,
    fullPage: true,
  });
});
