
import { test, expect } from '@playwright/test';

const ORCHESTRATOR_URL = 'http://localhost:3000';
const TELEMETRY_URL = `${ORCHESTRATOR_URL}/api/telemetry`;

const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

test('Verify Telemetry and Secure the Agent Overlay', async ({ page }) => {
  // Go to the dashboard
  await page.goto('http://localhost:3001'); // Assuming frontend is on 3001

  // Wait for initial load
  await expect(page.locator('h1')).toContainText('TRACETREE');

  // Trigger Mock Telemetry: Investigation Started
  await page.request.post(TELEMETRY_URL, {
    data: {
      event: 'investigation_started',
      payload: {
        prompt: "Analyze 'requests-async-v2' for exfiltration.",
        userId: "security_auditor_01",
        sessionId: "sess_test_123"
      }
    }
  });

  // Verify "Secure the Agent" card updates
  const activePayloadCard = page.locator('div.z-30:has-text("Active Payload")');
  await expect(activePayloadCard).toBeVisible();
  await expect(activePayloadCard).toContainText("Analyze 'requests-async-v2' for exfiltration.");

  // Test with a LONG payload string to check layout stability
  const longPrompt = "Analyze the 'extremely-long-package-name-v99.9.9' for potential data exfiltration via hidden post-install scripts that might try to reach out to multiple command and control servers and exfiltrate sensitive environment variables like AWS_SECRET_ACCESS_KEY and GOOGLE_APPLICATION_CREDENTIALS while also checking for local ssh keys and browser history files in a very stealthy manner using obfuscated python code and dynamic imports.";

  await page.request.post(TELEMETRY_URL, {
    data: {
      event: 'investigation_started',
      payload: {
        prompt: longPrompt,
        userId: "auditor_with_very_long_name_that_should_be_handled",
        sessionId: "sess_long_test_456"
      }
    }
  });

  await expect(page.locator('div.z-30:has-text("Active Payload")')).toContainText(longPrompt);

  // Capture screenshot of the card with long payload
  // Scroll by index if multiple sections match or use id if available
  await page.locator('h2:has-text("SECURE THE")').scrollIntoViewIfNeeded();
  await page.screenshot({ path: 'secure_the_agent_long_payload.png' });

  // Trigger Findings
  const mockFindings = {
    pid: "9999",
    target_type: "pip",
    is_malicious: true,
    confidence_score: 0.99,
    total_severity: 9.0,
    events: [
      { timestamp: "12:00:00", type: "EXECVE", target: "/bin/sh" }
    ]
  };

  await page.request.post(TELEMETRY_URL, {
    data: {
      event: 'step_completed',
      payload: {
        findings: JSON.stringify(mockFindings)
      }
    }
  });

  // Verify Nervous System updates (it should switch to Live mode or show telemetry)
  await page.locator('h2:has-text("THE NERVOUS")').scrollIntoViewIfNeeded();
  await expect(page.locator('h3:has-text("Telemetry Visualizer")')).toBeVisible();
  await expect(page.locator('span:has-text("PID: 9999")')).toBeVisible();

  await page.screenshot({ path: 'nervous_system_live_telemetry.png' });
});
