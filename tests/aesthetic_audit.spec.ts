import { test, expect } from '@playwright/test';

test('Aesthetic Audit - Multi-screen Verification', async ({ page }, testInfo) => {
  await page.addInitScript(() => {
    localStorage.setItem('tracetree_setup_complete', 'true');
  });
  await page.goto('http://localhost:3001');

  // 1. Logo & Top Bar Header
  const logo = page.locator('span:has-text("Trace")').first();
  await expect(logo).toBeVisible();
  await page.screenshot({ path: testInfo.outputPath('audit_dashboard.png') });

  // 2. Navigation Tabs
  const screens = ['Live', 'History', 'Evidence', 'Signatures', 'Settings'];
  for (const screenName of screens) {
    const tab = page.locator(`button:has-text("${screenName}")`).first();
    if (await tab.isVisible()) {
      await tab.click();
      await page.waitForTimeout(300);
      await page.screenshot({ path: testInfo.outputPath(`audit_${screenName.toLowerCase()}.png`) });
    }
  }
});
