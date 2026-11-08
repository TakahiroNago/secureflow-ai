import { defineConfig, devices } from '@playwright/test'

// The stack is reached as localhost:<port>, which is what Sanctum's stateful domains list: scripts/test-e2e.sh
// forwards that port to nginx inside the compose network (global-setup.ts).
const port = Number(process.env['E2E_PORT'] ?? '8080')

export default defineConfig({
  testDir: './tests',
  globalSetup: './global-setup.ts',
  // The flows share one organization, so two workers are enough to overlap the slow browsers without crowding the
  // login limit per address (30 a minute).
  workers: 2,
  fullyParallel: false,
  retries: 0,
  timeout: 120_000,
  expect: { timeout: 10_000 },
  reporter: [['list'], ['html', { open: 'never', outputFolder: 'output/report' }]],
  outputDir: 'output/test-results',
  use: {
    baseURL: `http://localhost:${String(port)}`,
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    viewport: { width: 1280, height: 900 },
    locale: 'ja-JP',
  },
  projects: [
    // The scenario of §10 in every browser.
    { name: 'chromium', use: { ...devices['Desktop Chrome'] }, testMatch: /main-flow\.spec\.ts/ },
    { name: 'firefox', use: { ...devices['Desktop Firefox'] }, testMatch: /main-flow\.spec\.ts/ },
    { name: 'webkit', use: { ...devices['Desktop Safari'] }, testMatch: /main-flow\.spec\.ts/ },
    // The additions, once: the self-test is limited to three starts an hour per organization.
    { name: 'chromium-more', use: { ...devices['Desktop Chrome'] }, testIgnore: /main-flow\.spec\.ts/ },
  ],
})
