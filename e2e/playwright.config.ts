import { defineConfig, devices } from "@playwright/test";
import { BASE_URL } from "./support/env";

// One server for the whole run (see support/server.ts), so tests run one after another.
export default defineConfig({
  testDir: "tests",
  fullyParallel: false,
  workers: 1,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  timeout: 60_000,
  expect: { timeout: 10_000 },
  reporter: process.env.CI ? [["github"], ["html", { open: "never" }]] : [["list"], ["html", { open: "never" }]],
  use: {
    baseURL: BASE_URL,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  webServer: {
    command: "node --experimental-strip-types support/server.ts",
    url: `${BASE_URL}/healthz`,
    reuseExistingServer: false,
    timeout: 30_000,
    stdout: "pipe",
  },
  projects: [
    { name: "setup", testMatch: /login\.setup\.ts/ },
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"], storageState: ".run/admin.json" },
      dependencies: ["setup"],
      testIgnore: /screenshots\.spec\.ts/,
    },
    {
      name: "screenshots",
      use: { ...devices["Desktop Chrome"], storageState: ".run/admin.json", viewport: { width: 1440, height: 900 } },
      dependencies: ["setup"],
      testMatch: /screenshots\.spec\.ts/,
    },
  ],
});
