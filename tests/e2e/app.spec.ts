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

test('login and see finance dashboard with live data', async ({ page }) => {
  await login(page);
  // dashboard cards render from live API (not empty/skeleton)
  await expect(page.getByText(/total return/i).first()).toBeVisible({ timeout: 30_000 });
  await expect(page.getByText('AAPL').first()).toBeVisible({ timeout: 30_000 });
  await page.screenshot({ path: 'screenshots/dashboard.png', fullPage: true });
});

test('chat streams a reply from the harness', async ({ page }) => {
  await login(page);
  // navigate directly — the "Chat" control differs per viewport (link vs
  // bottom-tab button vs header panel toggle)
  await page.goto('/finance/chat');
  const input = page.getByPlaceholder(/message|ask/i).locator('visible=true').first();
  await input.fill('In one short sentence, what can you help me with?');
  await page.getByRole('button', { name: /send/i }).locator('visible=true').first().click();
  // assistant bubble appears and grows (streaming)
  const assistant = page.locator('[data-role="assistant"]').last();
  await expect(assistant).toBeVisible({ timeout: 60_000 });
  await expect(assistant).not.toHaveText('', { timeout: 60_000 });
  await page.screenshot({ path: 'screenshots/chat.png', fullPage: true });
});

// All six harnesses are deployed; these four have chat but no widgets yet, so
// their dashboard route shows the "agent is live" hand-off into chat.
const CHAT_ONLY = [
  'insurance-claims',
  'retail-inventory',
  'manufacturing-maintenance',
  'real-estate-valuation',
];

for (const industryId of CHAT_ONLY) {
  test(`${industryId} dashboard offers the live agent`, async ({ page }) => {
    await login(page);
    await page.goto(`/${industryId}/dashboard`);
    await expect(page.getByRole('link', { name: /agent is live/i })).toBeVisible({
      timeout: 30_000,
    });
  });

  test(`${industryId} chat streams from its own harness`, async ({ page }) => {
    await login(page);
    await page.goto(`/${industryId}/chat`);
    const input = page.getByPlaceholder(/message|ask/i).locator('visible=true').first();
    await input.fill('In one sentence: what tools do you have?');
    await page.getByRole('button', { name: /send/i }).locator('visible=true').first().click();
    const assistant = page.locator('[data-role="assistant"]').last();
    await expect(assistant).toBeVisible({ timeout: 60_000 });
    await expect(assistant).not.toHaveText('', { timeout: 60_000 });
    await page.screenshot({ path: `screenshots/${industryId}-chat.png`, fullPage: true });
  });
}

test('healthcare chat streams from its own harness', async ({ page }) => {
  await login(page);
  await page.goto('/healthcare-medical/chat');
  const input = page.getByPlaceholder(/message|ask/i).locator('visible=true').first();
  await input.fill('In one sentence: what clinical tools do you have?');
  await page.getByRole('button', { name: /send/i }).locator('visible=true').first().click();
  const assistant = page.locator('[data-role="assistant"]').last();
  await expect(assistant).toBeVisible({ timeout: 60_000 });
  await expect(assistant).not.toHaveText('', { timeout: 60_000 });
  await page.screenshot({ path: 'screenshots/healthcare-chat.png', fullPage: true });
});
