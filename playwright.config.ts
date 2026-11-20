import { defineConfig, devices } from '@playwright/test';

const PORT = 3210;
const VULNERABLE = process.env.VULNERABLE === '1';

export default defineConfig({
  testDir: './tests',
  // Tests share one in-memory app instance; serial workers keep account-level state (lockouts, roles) predictable.
  workers: 1,
  forbidOnly: !!process.env.CI,
  reporter: [['html', { open: 'never' }], ['list']],
  use: {
    baseURL: `http://localhost:${PORT}`,
    trace: 'retain-on-failure',
  },
  webServer: {
    command: 'node app/server.js',
    url: `http://localhost:${PORT}/login`,
    reuseExistingServer: false,
    env: { PORT: String(PORT), VULNERABLE: VULNERABLE ? '1' : '0' },
    stdout: 'pipe',
  },
  projects: [
    { name: 'api', testDir: './tests/api' },
    { name: 'ui', testDir: './tests/ui', use: { ...devices['Desktop Chrome'] } },
  ],
});
