import { defineConfig, devices } from "@playwright/test";
import { BASE_URL } from "./website/env";

// The website's screenshots (`npm run website`), from a demo installation in the release's
// Docker image. Separate from the tests: its own server (website/demo.ts) and output (site/img/).
export default defineConfig({
  testDir: "website",
  workers: 1,
  timeout: 120_000,
  expect: { timeout: 15_000 },
  reporter: [["list"]],
  use: {
    ...devices["Desktop Chrome"],
    baseURL: BASE_URL,
    // 1280×809 CSS px at 1.25 = 1600×1011, the size site/index.html declares.
    viewport: { width: 1280, height: 809 },
    deviceScaleFactor: 1.25,
    locale: "en-US",
  },
  webServer: {
    command: "node --experimental-strip-types website/demo.ts",
    url: `${BASE_URL}/healthz`,
    reuseExistingServer: false,
    timeout: 300_000,
    stdout: "pipe",
    // Lets demo.ts remove the container; the default, SIGKILL, would leave it running.
    gracefulShutdown: { signal: "SIGTERM", timeout: 15_000 },
  },
});
