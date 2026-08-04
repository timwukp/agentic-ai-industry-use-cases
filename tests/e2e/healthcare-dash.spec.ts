import { test, expect } from '@playwright/test';

const EMAIL = process.env.E2E_EMAIL!;
const PASSWORD = process.env.E2E_PASSWORD!;

test('healthcare dashboard renders live population data', async ({ page }) => {
  await page.goto('/');
  await page.getByRole('textbox', { name: /email/i }).fill(EMAIL);
  await page.getByRole('textbox', { name: /password/i }).fill(PASSWORD);
  await page.getByRole('button', { name: /sign in/i }).click();
  await expect(page).not.toHaveURL(/login/, { timeout: 30_000 });

  await page.goto('/healthcare-medical/dashboard');
  // live API data, not the placeholder
  await expect(page.getByText(/coming soon/i)).not.toBeVisible();
  await expect(page.getByText('2,555').or(page.getByText('2555')).first())
    .toBeVisible({ timeout: 30_000 });
  await expect(page.getByText(/population/i).first()).toBeVisible();
  await expect(page.getByText(/availability/i).first()).toBeVisible({ timeout: 30_000 });
  await page.screenshot({ path: 'screenshots/healthcare-dashboard.png', fullPage: true });
});
