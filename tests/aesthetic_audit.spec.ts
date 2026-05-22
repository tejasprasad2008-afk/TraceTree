import { test, expect } from '@playwright/test';

test('Aesthetic Audit - Multi-section Verification', async ({ page }, testInfo) => {
  await page.goto('http://localhost:3001');

  // 1. Hero Section
  const heroHeading = page.locator('h1:has-text("TRACETREE")');
  await expect(heroHeading).toBeVisible();
  await page.screenshot({ path: testInfo.outputPath('audit_hero.png') });

  // 2. Scroll to Architecture
  await page.mouse.wheel(0, 1000);
  const archHeading = page.locator('h2:has-text("Intelligence")');
  await expect(archHeading).toBeVisible();
  await page.screenshot({ path: testInfo.outputPath('audit_architecture.png') });

  // 3. Scroll to Nervous System
  await page.mouse.wheel(0, 1000);
  const nervousHeading = page.locator('h2:has-text("THE NERVOUS")');
  await expect(nervousHeading).toBeVisible();
  await page.screenshot({ path: testInfo.outputPath('audit_nervous_system.png') });

  // 4. Scroll to Secure Agent
  await page.mouse.wheel(0, 1000);
  const secureHeading = page.locator('h2:has-text("SECURE THE")');
  await expect(secureHeading).toBeVisible();
  await page.screenshot({ path: testInfo.outputPath('audit_secure_agent.png') });

  // 5. Scroll to Manual
  await page.mouse.wheel(0, 1000);
  const manualHeading = page.locator('h2:has-text("Establish Order")');
  await expect(manualHeading).toBeVisible();
  await page.screenshot({ path: testInfo.outputPath('audit_manual.png') });
});
