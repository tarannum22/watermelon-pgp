import path from "node:path";
import { fileURLToPath } from "node:url";
import { expect, test, type Page } from "@playwright/test";
import { PASSWORD, VERSION } from "./env";

// Not a test: takes the screenshots in site/img/ from the demo installation (demo.ts).
// See docs/releasing.md, "Website".
const here = path.dirname(fileURLToPath(import.meta.url));
const IMG = path.resolve(here, "..", "..", "site", "img");

async function shoot(page: Page, name: string) {
  await page.mouse.move(0, 0);
  await page.evaluate(() => document.fonts.ready);
  await page.screenshot({ path: path.join(IMG, `${name}.png`) });
}

test("website screenshots", async ({ page }) => {
  await page.goto("/login");
  await shoot(page, "login");
  await page.getByLabel("Admin password").fill(PASSWORD);
  await page.getByRole("button", { name: "Log in" }).click();
  await expect(page.getByRole("heading", { level: 1, name: "Dashboard" })).toBeVisible();
  // The version in the sidebar is how a reviewer tells the screenshots are current.
  await expect(page.locator(".brand-name small")).toHaveText(`v${VERSION}`);

  await page.goto("/jobs");
  await page.getByRole("link", { name: "inbound-invoices" }).first().click();
  await expect(page.getByRole("heading", { level: 1, name: "inbound-invoices" })).toBeVisible();
  const job = new URL(page.url()).pathname;

  const pages: Record<string, string> = {
    dashboard: "/",
    jobs: "/jobs",
    job,
    keys: "/keys",
    "audit-search": "/audit?q=invoice",
  };
  for (const scheme of ["light", "dark"] as const) {
    await page.emulateMedia({ colorScheme: scheme });
    for (const [name, url] of Object.entries(pages)) {
      await page.goto(url);
      await shoot(page, scheme === "light" ? name : `${name}-dark`);
    }
  }

  // The link preview: the dark dashboard on a card, 1200×630.
  await page.setViewportSize({ width: 1200, height: 630 });
  await page.goto(`file://${path.join(here, "social-card.html")}`);
  await page.evaluate(() => Promise.all([document.fonts.ready, ...Array.from(document.images, (i) => i.decode())]));
  await page.screenshot({ path: path.join(IMG, "social-card.png"), scale: "css" });
});
