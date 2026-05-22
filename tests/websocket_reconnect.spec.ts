import { test, expect } from '@playwright/test';

test('WebSocket should reconnect after server restart', async ({ page }) => {
  // Increase timeout for reconnection
  test.setTimeout(30000);

  // 1. Go to the dashboard
  await page.goto('http://localhost:3001');

  // 2. Wait for initial connection
  const onlineIndicator = page.locator('text=SYSTEM ONLINE');
  await expect(onlineIndicator).toBeVisible({ timeout: 10000 });
  console.log('Confirmed: System is ONLINE');

  // We will trigger the restart from the bash script running this test
  // So the test should just wait for OFFLINE then ONLINE

  const offlineIndicator = page.locator('text=SYSTEM OFFLINE');
  await expect(offlineIndicator).toBeVisible({ timeout: 15000 });
  console.log('Confirmed: System went OFFLINE');

  await expect(onlineIndicator).toBeVisible({ timeout: 15000 });
  console.log('Confirmed: System reconnected and is ONLINE');
});
