/**
 * The language picker, end to end: switching, persistence, and the reply
 * directive following the UI language.
 *
 * Everything else in the E2E suite runs in English on purpose — a fresh
 * Playwright profile has no localStorage, so `initialLocale()` returns 'en'
 * and every English selector in the other spec files keeps working. This file
 * is the one place a non-default locale is exercised, and it cleans up by
 * switching back before the page context dies (belt and braces; profiles are
 * per-test anyway).
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

test('the picker switches the UI language and the choice survives a reload', async ({
  page,
}, testInfo) => {
  test.skip(testInfo.project.name !== 'desktop', 'one platform is enough for locale plumbing');
  await login(page);
  await page.goto('/finance/dashboard');

  // English baseline: the sidebar nav renders the default locale.
  await expect(page.getByRole('link', { name: 'Dashboard' }).first()).toBeVisible({
    timeout: 30_000,
  });

  // Switch to Traditional Chinese via the header picker (a native <select>).
  await page.getByTestId('locale-picker').first().selectOption('zh-TW');

  // Chrome translates: nav links, chat header, and a dashboard StatCard title.
  await expect(page.getByRole('link', { name: '儀表板' }).first()).toBeVisible({
    timeout: 15_000,
  });
  await expect(page.getByText('投資組合價值').first()).toBeVisible({ timeout: 15_000 });

  // The stable E2E hook must NOT have translated: data-kpi is the English key.
  await expect(page.locator('[data-kpi="Portfolio Value"]')).toBeVisible();

  // Persistence: the choice is localStorage, not component state.
  await expect
    .poll(async () => page.evaluate(() => localStorage.getItem('ui-locale')))
    .toBe('zh-TW');
  await page.reload();
  await expect(page.getByRole('link', { name: '儀表板' }).first()).toBeVisible({
    timeout: 30_000,
  });

  // And back: the round trip proves the switch is not one-way.
  await page.getByTestId('locale-picker').first().selectOption('en');
  await expect(page.getByRole('link', { name: 'Dashboard' }).first()).toBeVisible({
    timeout: 15_000,
  });
});

test('a starter question answers in the UI language', async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== 'desktop', 'one platform is enough');
  await login(page);
  await page.goto('/finance/dashboard');

  await page.getByTestId('locale-picker').first().selectOption('zh-TW');

  // The starter button label is translated; the PROMPT it sends stays English
  // (ids and enums the tools need), and the reply-language directive carries
  // the UI locale — so the answer must come back in Chinese.
  const starter = page.getByTestId('starter-prompt').first();
  await expect(starter).toBeVisible({ timeout: 15_000 });
  await starter.click();

  const input = page
    .locator('textarea')
    .locator('visible=true')
    .first();
  await expect(input).toBeEnabled({ timeout: 200_000 });

  const answer = page.locator('[data-role="assistant"]').last();
  const prose = await answer.innerText();
  expect(
    /[一-鿿]/u.test(prose),
    `UI locale zh-TW but the answer has no CJK:\n${prose.slice(0, 400)}`,
  ).toBe(true);

  await page.screenshot({
    path: 'screenshots/locale-zh-starter-desktop.png',
    fullPage: true,
  });
});
