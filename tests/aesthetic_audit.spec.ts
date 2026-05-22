import { test, expect } from '@playwright/test';

test('Aesthetic Audit - Multi-section Verification', async ({ page }) => {
  await page.goto('http://localhost:3001');

  // Wait for animations
  await page.waitForTimeout(2000);

  // 1. Hero Section
  await page.screenshot({ path: 'audit_hero.png' });

  // 2. Scroll to Architecture
  await page.mouse.wheel(0, 1000);
  await page.waitForTimeout(1000);
  await page.screenshot({ path: 'audit_architecture.png' });

  // 3. Scroll to Nervous System
  await page.mouse.wheel(0, 1000);
  await page.waitForTimeout(1000);
  await page.screenshot({ path: 'audit_nervous_system.png' });

  // 4. Scroll to Secure Agent
  await page.mouse.wheel(0, 1000);
  await page.waitForTimeout(1000);
  await page.screenshot({ path: 'audit_secure_agent.png' });

  // 5. Scroll to Manual
  await page.mouse.wheel(0, 1000);
  await page.waitForTimeout(1000);
  await page.screenshot({ path: 'audit_manual.png' });
});
