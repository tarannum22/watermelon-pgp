import { test } from "@playwright/test";

// Not a test: `npm run screenshots` saves every page in both themes to screenshots/, for
// reviewing design changes. Run it after the other tests so there is data to show.
const PAGES = { dashboard: "/", customers: "/customers", keys: "/keys", jobs: "/jobs", "new-job": "/jobs/new", audit: "/audit", settings: "/settings", design: "/design" };

for (const scheme of ["light", "dark"] as const) {
  test(`screenshots (${scheme})`, async ({ page }) => {
    await page.emulateMedia({ colorScheme: scheme });
    for (const [name, path] of Object.entries(PAGES)) {
      await page.goto(path);
      await page.screenshot({ path: `screenshots/${name}-${scheme}.png`, fullPage: true });
    }
  });
}
